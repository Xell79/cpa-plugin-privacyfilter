package walker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

const (
	rootTreePathRef = int32(-1)

	// Logical charges conservatively cover the retained 64-bit Go structures and
	// slice backing arrays. Growth is reserved before allocation.
	retainedTreeNodeBytes        = 128
	retainedTreePathBytes        = 64
	retainedTreeMemberBytes      = 64
	retainedTreeArrayBytes       = 16
	retainedTreeStringBytes      = 64
	retainedTreeTargetBytes      = 384
	retainedTreeUnsupportedBytes = 256
	retainedTreeIndexEntryBytes  = 128
	retainedFieldContextBytes    = (payload.MaxContextAncestors + 1) * payload.MaxContextKeyBytes
	retainedPathSegmentBytes     = 48
)

type member struct {
	key   string
	value *node
}

type treeString struct {
	Value   string
	Span    payload.Span
	ordinal int
}

type node struct {
	kind    payload.Kind
	path    treePath
	token   *treeString
	boolean bool
	object  []member
	array   []*node
}

type treePathNode struct {
	parent  int32
	segment payload.PathSegment
	depth   int
}

type treePathArena struct {
	nodes  []treePathNode
	budget *treeStructuralBudget
}

type treePath struct {
	arena *treePathArena
	ref   int32
}

func (p treePath) Clone() payload.Path {
	if p.arena == nil || p.ref < 0 {
		return nil
	}
	depth := p.arena.nodes[p.ref].depth
	path := make(payload.Path, depth)
	for current, index := p.ref, depth-1; current >= 0; current, index = p.arena.nodes[current].parent, index-1 {
		path[index] = p.arena.nodes[current].segment
	}
	return path
}

func (p treePath) String() string { return p.Clone().String() }

func (p treePath) reserveMaterialized() error {
	if p.arena == nil || p.ref < 0 {
		return nil
	}
	return p.arena.budget.retain(p.arena.nodes[p.ref].depth * retainedPathSegmentBytes)
}

func (p treePath) reserveTargetCapacity(targets []Target) ([]Target, error) {
	if p.arena == nil || p.arena.budget == nil {
		return nil, errorsInternal("target path arena is unavailable")
	}
	if len(targets) < cap(targets) {
		return targets, nil
	}
	newCap := nextTreeCapacity(cap(targets), len(targets)+1)
	if err := p.arena.budget.retain((newCap - cap(targets)) * retainedTreeTargetBytes); err != nil {
		return nil, err
	}
	grown := make([]Target, len(targets), newCap)
	copy(grown, targets)
	return grown, nil
}

type treeStructuralBudget struct {
	used  int
	limit int
}

func (b *treeStructuralBudget) retain(bytes int) error {
	if bytes < 0 || bytes > b.limit-b.used {
		return fmt.Errorf("%w: retained %d bytes, requested %d, max %d", payload.ErrStructuralLimit, b.used, bytes, b.limit)
	}
	b.used += bytes
	return nil
}

type treeParser struct {
	ctx       context.Context
	decoder   *json.Decoder
	document  *payload.Document
	stringPos int
	arena     treePathArena
	budget    *treeStructuralBudget
}

func parseTree(ctx context.Context, body []byte, document *payload.Document) (*node, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	limits := document.EffectiveLimits()
	budget := &treeStructuralBudget{used: document.StructuralBytes(), limit: limits.MaxStructuralBytes}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	p := treeParser{ctx: ctx, decoder: decoder, document: document, budget: budget}
	p.arena.budget = budget
	root, err := p.value(treePath{arena: &p.arena, ref: rootTreePathRef}, payload.KindInvalid)
	if err != nil {
		return nil, fmt.Errorf("walker: build validated JSON tree: %w", err)
	}
	if p.stringPos != document.StringCount() {
		return nil, fmt.Errorf("walker: payload/tree string index mismatch: consumed %d of %d", p.stringPos, document.StringCount())
	}
	if _, err = decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errorsInternal("decoder found a second root")
		}
		return nil, fmt.Errorf("walker: finish validated JSON tree: %w", err)
	}
	return root, nil
}

func (p *treeParser) value(path treePath, parentKind payload.Kind) (*node, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	token, err := p.decoder.Token()
	if err != nil {
		return nil, err
	}
	if err = p.budget.retain(retainedTreeNodeBytes); err != nil {
		return nil, err
	}
	n := &node{path: path}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			n.kind = payload.KindObject
			for p.decoder.More() {
				if err = p.ctx.Err(); err != nil {
					return nil, err
				}
				keyToken, keyErr := p.decoder.Token()
				if keyErr != nil {
					return nil, keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errorsInternal("object key is not a string")
				}
				childPath, pathErr := p.appendPath(path, payload.Key(key), len(key))
				if pathErr != nil {
					return nil, pathErr
				}
				child, childErr := p.value(childPath, payload.KindObject)
				if childErr != nil {
					return nil, childErr
				}
				if err = p.appendMember(n, member{key: key, value: child}); err != nil {
					return nil, err
				}
			}
			end, endErr := p.decoder.Token()
			if endErr != nil {
				return nil, endErr
			}
			if end != json.Delim('}') {
				return nil, errorsInternal("object has wrong closing delimiter")
			}
		case '[':
			n.kind = payload.KindArray
			for index := 0; p.decoder.More(); index++ {
				childPath, pathErr := p.appendPath(path, payload.Index(index), 0)
				if pathErr != nil {
					return nil, pathErr
				}
				child, childErr := p.value(childPath, payload.KindArray)
				if childErr != nil {
					return nil, childErr
				}
				if err = p.appendArray(n, child); err != nil {
					return nil, err
				}
			}
			end, endErr := p.decoder.Token()
			if endErr != nil {
				return nil, endErr
			}
			if end != json.Delim(']') {
				return nil, errorsInternal("array has wrong closing delimiter")
			}
		default:
			return nil, errorsInternal("unexpected closing delimiter")
		}
	case string:
		n.kind = payload.KindString
		indexed, ok := p.document.StringMetadataAt(p.stringPos)
		if !ok {
			return nil, errorsInternal("decoded string missing from payload index")
		}
		ordinal := p.stringPos
		p.stringPos++
		depth := 1
		if path.ref >= 0 {
			depth = p.arena.nodes[path.ref].depth + 1
		}
		if indexed.Value != value || indexed.Depth != depth || indexed.ParentKind != parentKind {
			return nil, fmt.Errorf("walker: payload/tree string mismatch at %s", path)
		}
		if err = p.budget.retain(retainedTreeStringBytes + len(value)); err != nil {
			return nil, err
		}
		n.token = &treeString{Value: value, Span: indexed.Span, ordinal: ordinal}
	case json.Number:
		n.kind = payload.KindNumber
	case bool:
		n.kind = payload.KindBoolean
		n.boolean = value
	case nil:
		n.kind = payload.KindNull
	default:
		return nil, errorsInternal("decoder returned an unknown token type")
	}
	return n, nil
}

func (p *treeParser) appendPath(parent treePath, segment payload.PathSegment, retainedStringBytes int) (treePath, error) {
	charge := retainedStringBytes
	if len(p.arena.nodes) == cap(p.arena.nodes) {
		newCap := nextTreeCapacity(cap(p.arena.nodes), len(p.arena.nodes)+1)
		charge += (newCap - cap(p.arena.nodes)) * retainedTreePathBytes
		if err := p.budget.retain(charge); err != nil {
			return treePath{}, err
		}
		grown := make([]treePathNode, len(p.arena.nodes), newCap)
		copy(grown, p.arena.nodes)
		p.arena.nodes = grown
	} else if err := p.budget.retain(charge); err != nil {
		return treePath{}, err
	}
	depth := 1
	if parent.ref >= 0 {
		depth = p.arena.nodes[parent.ref].depth + 1
	}
	ref := int32(len(p.arena.nodes))
	p.arena.nodes = append(p.arena.nodes, treePathNode{parent: parent.ref, segment: segment, depth: depth})
	return treePath{arena: &p.arena, ref: ref}, nil
}

func (p *treeParser) appendMember(object *node, item member) error {
	if len(object.object) == cap(object.object) {
		newCap := nextTreeCapacity(cap(object.object), len(object.object)+1)
		if err := p.budget.retain((newCap - cap(object.object)) * retainedTreeMemberBytes); err != nil {
			return err
		}
		grown := make([]member, len(object.object), newCap)
		copy(grown, object.object)
		object.object = grown
	}
	object.object = append(object.object, item)
	return nil
}

func (p *treeParser) appendArray(array *node, item *node) error {
	if len(array.array) == cap(array.array) {
		newCap := nextTreeCapacity(cap(array.array), len(array.array)+1)
		if err := p.budget.retain((newCap - cap(array.array)) * retainedTreeArrayBytes); err != nil {
			return err
		}
		grown := make([]*node, len(array.array), newCap)
		copy(grown, array.array)
		array.array = grown
	}
	array.array = append(array.array, item)
	return nil
}

func nextTreeCapacity(current, required int) int {
	if current == 0 {
		current = 16
	}
	for current < required {
		current *= 2
	}
	return current
}

func errorsInternal(detail string) error {
	return fmt.Errorf("walker: internal validated JSON mismatch: %s", detail)
}
