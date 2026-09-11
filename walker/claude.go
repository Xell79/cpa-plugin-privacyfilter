package walker

import (
	"fmt"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

func walkClaude(c *collector, root *node) error {
	if err := c.unique(root, "system", "messages"); err != nil {
		return err
	}
	system, hasSystem, err := c.field(root, "system")
	if err != nil {
		return err
	}
	if hasSystem {
		if err = walkClaudeSystem(c, system); err != nil {
			return err
		}
	}
	messages, _, err := c.arrayField(root, "messages", true)
	if err != nil {
		return err
	}
	for _, message := range messages.array {
		if err = walkClaudeMessage(c, message); err != nil {
			return err
		}
	}
	return nil
}

func walkClaudeSystem(c *collector, system *node) error {
	switch system.kind {
	case payload.KindString:
		return c.add(system, ScopeSystem, TargetKindNaturalText, MutabilityDirect)
	case payload.KindArray:
		for _, block := range system.array {
			if block.kind != payload.KindObject {
				c.unsupported(block, "system array element is not an object")
				continue
			}
			if err := c.unique(block, "type", "text", "id", "name", "signature"); err != nil {
				return err
			}
			typeNode, ok, err := c.stringField(block, "type", false)
			if err != nil {
				return err
			}
			if !ok {
				c.unsupported(block, "system block has no type")
				continue
			}
			if err = c.markOpaque(typeNode); err != nil {
				return err
			}
			if typeNode.token.Value != "text" {
				c.unsupported(block, fmt.Sprintf("unknown system block type %q", typeNode.token.Value))
				continue
			}
			text, _, err := c.stringField(block, "text", true)
			if err != nil {
				return err
			}
			if err = c.add(text, ScopeSystem, TargetKindNaturalText, MutabilityDirect); err != nil {
				return err
			}
		}
		return nil
	default:
		return c.shape(system, "string or array", "system")
	}
}

func walkClaudeMessage(c *collector, message *node) error {
	if message.kind != payload.KindObject {
		return c.shape(message, "object", "messages element")
	}
	if err := c.unique(message, "role", "content", "id", "name", "signature"); err != nil {
		return err
	}
	if err := c.markFields(message, "id", "name", "signature"); err != nil {
		return err
	}
	roleNode, _, err := c.stringField(message, "role", true)
	if err != nil {
		return err
	}
	scope, roleOK := scopeForRole(roleNode.token.Value)
	if err = c.markOpaque(roleNode); err != nil {
		return err
	}
	if !roleOK {
		c.unsupported(roleNode, fmt.Sprintf("unknown message role %q", roleNode.token.Value))
		return nil
	}
	content, present, err := c.field(message, "content")
	if err != nil {
		return err
	}
	if !present {
		return c.missing(message, "content", "string or array")
	}
	switch content.kind {
	case payload.KindString:
		return c.add(content, scope, TargetKindNaturalText, MutabilityDirect)
	case payload.KindArray:
		for _, block := range content.array {
			if err = walkClaudeContentBlock(c, block, scope); err != nil {
				return err
			}
		}
		return nil
	default:
		return c.shape(content, "string or array", "message content")
	}
}

func walkClaudeContentBlock(c *collector, block *node, messageScope Scope) error {
	if block.kind != payload.KindObject {
		c.unsupported(block, "content array element is not an object")
		return nil
	}
	if err := c.unique(block, "type", "text", "input", "content", "source", "thinking", "redacted_thinking", "signature", "id", "name", "tool_use_id"); err != nil {
		return err
	}
	if err := c.markFields(block, "thinking", "redacted_thinking", "signature", "id", "name", "tool_use_id"); err != nil {
		return err
	}
	typeNode, ok, err := c.stringField(block, "type", false)
	if err != nil {
		return err
	}
	if !ok {
		c.unsupported(block, "content block has no type")
		return nil
	}
	blockType := typeNode.token.Value
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch blockType {
	case "text":
		text, _, fieldErr := c.stringField(block, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(text, messageScope, TargetKindNaturalText, MutabilityDirect)
	case "tool_use":
		input, present, fieldErr := c.field(block, "input")
		if fieldErr != nil {
			return fieldErr
		}
		if !present {
			return nil
		}
		return c.walkStringValues(input, ScopeToolInput, TargetKindJSONValue)
	case "tool_result":
		content, present, fieldErr := c.field(block, "content")
		if fieldErr != nil {
			return fieldErr
		}
		if !present {
			return nil
		}
		return walkClaudeToolResult(c, content)
	case "thinking", "redacted_thinking":
		return c.markOpaque(block)
	case "image", "document":
		return c.markOpaque(block)
	default:
		c.unsupported(block, fmt.Sprintf("unknown content block type %q", blockType))
		return nil
	}
}

func walkClaudeToolResult(c *collector, value *node) error {
	switch value.kind {
	case payload.KindString:
		return c.add(value, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
	case payload.KindArray:
		for _, item := range value.array {
			if item.kind == payload.KindObject {
				typeNode, hasType, err := c.stringField(item, "type", false)
				if err != nil {
					return err
				}
				if hasType {
					if err = c.markOpaque(typeNode); err != nil {
						return err
					}
					switch typeNode.token.Value {
					case "text":
						if err = c.unique(item, "text", "signature", "id", "name", "tool_use_id"); err != nil {
							return err
						}
						if err = c.markFields(item, "signature", "id", "name", "tool_use_id"); err != nil {
							return err
						}
						text, _, textErr := c.stringField(item, "text", true)
						if textErr != nil {
							return textErr
						}
						if err = c.add(text, ScopeToolOutput, TargetKindToolOutput, MutabilityDirect); err != nil {
							return err
						}
						continue
					case "image", "document", "thinking", "redacted_thinking":
						if err = c.markOpaque(item); err != nil {
							return err
						}
						continue
					default:
						c.unsupported(item, fmt.Sprintf("unknown tool-result content block type %q", typeNode.token.Value))
						continue
					}
				}
			}
			if err := walkClaudeOutputValue(c, item, false); err != nil {
				return err
			}
		}
		return nil
	default:
		return walkClaudeOutputValue(c, value, false)
	}
}

var claudeProtectedOutputKeys = map[string]struct{}{
	"thinking":          {},
	"redacted_thinking": {},
	"signature":         {},
	"id":                {},
	"name":              {},
	"tool_use_id":       {},
}

func walkClaudeOutputValue(c *collector, value *node, underSource bool) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	switch value.kind {
	case payload.KindString:
		return c.add(value, ScopeToolOutput, TargetKindJSONValue, MutabilityDirect)
	case payload.KindArray:
		for _, item := range value.array {
			if err := walkClaudeOutputValue(c, item, underSource); err != nil {
				return err
			}
		}
	case payload.KindObject:
		for _, item := range value.object {
			if _, protected := claudeProtectedOutputKeys[item.key]; protected || underSource && item.key == "data" {
				if err := c.markOpaque(item.value); err != nil {
					return err
				}
				continue
			}
			if err := walkClaudeOutputValue(c, item.value, item.key == "source"); err != nil {
				return err
			}
		}
	}
	return nil
}
