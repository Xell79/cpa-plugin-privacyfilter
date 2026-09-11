package walker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

type member struct {
	key   string
	value *node
}

type node struct {
	kind    payload.Kind
	path    payload.Path
	token   *payload.StringToken
	boolean bool
	object  []member
	array   []*node
}

type treeParser struct {
	ctx       context.Context
	decoder   *json.Decoder
	strings   []payload.StringToken
	stringPos int
}

func parseTree(ctx context.Context, body []byte, document *payload.Document) (*node, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	p := treeParser{ctx: ctx, decoder: decoder, strings: document.Strings()}
	root, err := p.value(nil)
	if err != nil {
		return nil, fmt.Errorf("walker: build validated JSON tree: %w", err)
	}
	if p.stringPos != len(p.strings) {
		return nil, fmt.Errorf("walker: payload/tree string index mismatch: consumed %d of %d", p.stringPos, len(p.strings))
	}
	if _, err = decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errorsInternal("decoder found a second root")
		}
		return nil, fmt.Errorf("walker: finish validated JSON tree: %w", err)
	}
	return root, nil
}

func (p *treeParser) value(path payload.Path) (*node, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	token, err := p.decoder.Token()
	if err != nil {
		return nil, err
	}
	n := &node{path: path.Clone()}
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
				childPath := append(path.Clone(), payload.Key(key))
				child, childErr := p.value(childPath)
				if childErr != nil {
					return nil, childErr
				}
				n.object = append(n.object, member{key: key, value: child})
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
				childPath := append(path.Clone(), payload.Index(index))
				child, childErr := p.value(childPath)
				if childErr != nil {
					return nil, childErr
				}
				n.array = append(n.array, child)
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
		if p.stringPos >= len(p.strings) {
			return nil, errorsInternal("decoded string missing from payload index")
		}
		indexed := p.strings[p.stringPos]
		p.stringPos++
		if indexed.Value != value || !indexed.Path.Equal(path) {
			return nil, fmt.Errorf("walker: payload/tree string mismatch at %s", path)
		}
		n.token = &indexed
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

func errorsInternal(detail string) error {
	return fmt.Errorf("walker: internal validated JSON mismatch: %s", detail)
}
