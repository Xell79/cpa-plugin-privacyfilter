package walker

import "github.com/ahoo/cpa-plugin-privacyfilter/payload"

var claudeRootControlFields = []string{
	"model", "max_tokens", "inference_geo", "temperature", "top_k", "top_p", "container",
	"cache_control", "metadata", "output_config", "service_tier", "stop_sequences", "stream",
	"thinking", "tool_choice", "context_management", "mcp_servers",
}

func walkClaude(c *collector, root *node) error {
	if err := c.unique(root, "system", "messages", "tools"); err != nil {
		return err
	}
	if err := c.markFields(root, claudeRootControlFields...); err != nil {
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
	return walkClaudeToolDefinitions(c, root)
}

func walkClaudeToolDefinitions(c *collector, root *node) error {
	tools, present, err := c.field(root, "tools")
	if err != nil || !present {
		return err
	}
	if tools.kind != payload.KindArray {
		return c.shape(tools, "array", "tools")
	}
	for _, tool := range tools.array {
		if tool.kind != payload.KindObject {
			c.unsupported(tool, "tool definition is not an object")
			continue
		}
		if err = c.unique(tool, "type", "name", "description", "input_schema", "cache_control", "strict", "defer_loading"); err != nil {
			return err
		}
		typeNode, hasType, fieldErr := c.stringField(tool, "type", false)
		if fieldErr != nil {
			return fieldErr
		}
		if hasType {
			if err = c.markOpaque(typeNode); err != nil {
				return err
			}
		}
		if err = c.markOpaqueStringField(tool, "name", true, false); err != nil {
			return err
		}
		if err = c.addStringField(tool, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
			return err
		}
		if err = c.walkStringObjectField(tool, "input_schema", !hasType, false, ScopeSystem); err != nil {
			return err
		}
		if err = walkClaudeCacheControl(c, tool); err != nil {
			return err
		}
	}
	return nil
}

func walkClaudeCacheControl(c *collector, object *node) error {
	cacheControl, present, err := c.field(object, "cache_control")
	if err != nil || !present || cacheControl.kind == payload.KindNull {
		return err
	}
	if cacheControl.kind != payload.KindObject {
		return c.shape(cacheControl, "object or null", "cache_control")
	}
	if err = c.unique(cacheControl, "type", "ttl"); err != nil {
		return err
	}
	if err = c.markOpaqueStringField(cacheControl, "type", true, false); err != nil {
		return err
	}
	return c.markOpaqueStringField(cacheControl, "ttl", false, true)
}

func walkClaudeCitations(c *collector, object *node) error {
	citations, present, err := c.field(object, "citations")
	if err != nil || !present || citations.kind == payload.KindNull {
		return err
	}
	switch citations.kind {
	case payload.KindObject:
		if err = c.unique(citations, "enabled"); err != nil {
			return err
		}
		enabled, hasEnabled, fieldErr := c.field(citations, "enabled")
		if fieldErr != nil {
			return fieldErr
		}
		if !hasEnabled {
			return c.missing(citations, "enabled", "boolean")
		}
		if enabled.kind != payload.KindBoolean {
			return c.shape(enabled, "boolean", "citations enabled")
		}
		return nil
	case payload.KindArray:
		if len(citations.array) != 0 {
			c.unsupported(citations, "citation replay metadata is integrity-coupled")
		}
		return nil
	default:
		return c.shape(citations, "object, array, or null", "citations")
	}
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
			if err := c.unique(block, "type", "text", "id", "name", "signature", "cache_control", "citations"); err != nil {
				return err
			}
			for _, key := range []string{"id", "name", "signature"} {
				if err := c.markOpaqueStringField(block, key, false, true); err != nil {
					return err
				}
			}
			if err := walkClaudeCacheControl(c, block); err != nil {
				return err
			}
			if err := walkClaudeCitations(c, block); err != nil {
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
				c.unsupportedValue(block, "unknown system block type ", typeNode.token.Value)
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
	for _, key := range []string{"id", "name", "signature"} {
		if err := c.markOpaqueStringField(message, key, false, true); err != nil {
			return err
		}
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
		c.unsupportedValue(roleNode, "unknown message role ", roleNode.token.Value)
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
	if err := c.unique(
		block,
		"type", "text", "input", "content", "source", "context", "title", "thinking", "data",
		"signature", "id", "name", "tool_use_id", "toolset_name", "cache_control", "citations",
		"caller", "is_error",
	); err != nil {
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
		for _, key := range []string{"id", "name", "signature"} {
			if err = c.markOpaqueStringField(block, key, false, true); err != nil {
				return err
			}
		}
		if err = walkClaudeCacheControl(c, block); err != nil {
			return err
		}
		if err = walkClaudeCitations(c, block); err != nil {
			return err
		}
		text, _, fieldErr := c.stringField(block, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(text, messageScope, TargetKindNaturalText, MutabilityDirect)
	case "tool_use":
		for _, key := range []string{"id", "name", "toolset_name"} {
			if err = c.markOpaqueStringField(block, key, false, true); err != nil {
				return err
			}
		}
		if err = walkClaudeCacheControl(c, block); err != nil {
			return err
		}
		if caller, present, fieldErr := c.field(block, "caller"); fieldErr != nil {
			return fieldErr
		} else if present && caller.kind != payload.KindNull {
			c.unsupported(caller, "tool-use caller metadata is not admitted")
		}
		input, present, fieldErr := c.field(block, "input")
		if fieldErr != nil {
			return fieldErr
		}
		if !present {
			return c.missing(block, "input", "JSON value")
		}
		return c.walkStringValues(input, ScopeToolInput, TargetKindJSONValue)
	case "tool_result":
		for _, key := range []string{"tool_use_id", "toolset_name"} {
			if err = c.markOpaqueStringField(block, key, false, true); err != nil {
				return err
			}
		}
		if err = walkClaudeCacheControl(c, block); err != nil {
			return err
		}
		content, present, fieldErr := c.field(block, "content")
		if fieldErr != nil {
			return fieldErr
		}
		if !present {
			return c.missing(block, "content", "string or array")
		}
		return walkClaudeToolResult(c, content)
	case "thinking":
		if err = c.markOpaqueStringField(block, "thinking", true, false); err != nil {
			return err
		}
		return c.markOpaqueStringField(block, "signature", true, false)
	case "redacted_thinking":
		return c.markOpaqueStringField(block, "data", true, false)
	case "image":
		if err = walkClaudeCacheControl(c, block); err != nil {
			return err
		}
		return walkClaudeOpaqueSource(c, block)
	case "document":
		return walkClaudeDocument(c, block, messageScope)
	default:
		c.unsupportedValue(block, "unknown content block type ", blockType)
		return nil
	}
}

func walkClaudeToolResult(c *collector, value *node) error {
	switch value.kind {
	case payload.KindString:
		return c.add(value, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
	case payload.KindArray:
		for _, item := range value.array {
			if item.kind != payload.KindObject {
				if err := c.walkStringValues(item, ScopeToolOutput, TargetKindJSONValue); err != nil {
					return err
				}
				continue
			}
			typeNode, hasType, err := c.stringField(item, "type", false)
			if err != nil {
				return err
			}
			if !hasType {
				if err = c.walkStringValues(item, ScopeToolOutput, TargetKindJSONValue); err != nil {
					return err
				}
				continue
			}
			if err = c.markOpaque(typeNode); err != nil {
				return err
			}
			switch typeNode.token.Value {
			case "text":
				if err = c.unique(item, "type", "text", "cache_control", "citations"); err != nil {
					return err
				}
				if err = walkClaudeCacheControl(c, item); err != nil {
					return err
				}
				if err = walkClaudeCitations(c, item); err != nil {
					return err
				}
				text, _, textErr := c.stringField(item, "text", true)
				if textErr != nil {
					return textErr
				}
				if err = c.add(text, ScopeToolOutput, TargetKindToolOutput, MutabilityDirect); err != nil {
					return err
				}
			case "image":
				if err = walkClaudeOpaqueSource(c, item); err != nil {
					return err
				}
			case "document":
				if err = walkClaudeDocument(c, item, ScopeToolOutput); err != nil {
					return err
				}
			case "thinking":
				if err = c.markOpaqueStringField(item, "thinking", true, false); err != nil {
					return err
				}
				if err = c.markOpaqueStringField(item, "signature", true, false); err != nil {
					return err
				}
			case "redacted_thinking":
				if err = c.markOpaqueStringField(item, "data", true, false); err != nil {
					return err
				}
			default:
				c.unsupportedValue(item, "unknown tool-result content block type ", typeNode.token.Value)
			}
		}
		return nil
	default:
		return c.walkStringValues(value, ScopeToolOutput, TargetKindJSONValue)
	}
}

func walkClaudeOpaqueSource(c *collector, block *node) error {
	source, _, err := c.objectField(block, "source", true)
	if err != nil {
		return err
	}
	if err = c.unique(source, "type", "media_type", "data", "url", "file_id"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(source, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "base64":
		if err = c.markOpaqueStringField(source, "media_type", true, false); err != nil {
			return err
		}
		return c.markOpaqueStringField(source, "data", true, false)
	case "url":
		return c.markOpaqueStringField(source, "url", true, false)
	case "file":
		return c.markOpaqueStringField(source, "file_id", true, false)
	default:
		c.unsupportedValue(source, "unknown media source type ", typeNode.token.Value)
		return nil
	}
}

func walkClaudeDocument(c *collector, block *node, scope Scope) error {
	if err := walkClaudeCacheControl(c, block); err != nil {
		return err
	}
	if err := walkClaudeCitations(c, block); err != nil {
		return err
	}
	kind := TargetKindNaturalText
	if scope == ScopeToolOutput {
		kind = TargetKindToolOutput
	}
	for _, key := range []string{"context", "title"} {
		value, present, err := c.field(block, key)
		if err != nil {
			return err
		}
		if !present || value.kind == payload.KindNull {
			continue
		}
		if value.kind != payload.KindString {
			return c.shape(value, "string or null", key)
		}
		if err = c.add(value, scope, kind, MutabilityDirect); err != nil {
			return err
		}
	}
	source, _, err := c.objectField(block, "source", true)
	if err != nil {
		return err
	}
	if err = c.unique(source, "type", "media_type", "data", "url", "file_id", "content"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(source, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "text":
		data, _, fieldErr := c.stringField(source, "data", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(data, scope, kind, MutabilityDirect)
	case "content":
		content, _, fieldErr := c.arrayField(source, "content", true)
		if fieldErr != nil {
			return fieldErr
		}
		for _, item := range content.array {
			if err = c.walkTypedTextBlock(item, scope); err != nil {
				return err
			}
		}
		return nil
	case "base64":
		if err = c.markOpaqueStringField(source, "media_type", true, false); err != nil {
			return err
		}
		return c.markOpaqueStringField(source, "data", true, false)
	case "url":
		return c.markOpaqueStringField(source, "url", true, false)
	case "file":
		return c.markOpaqueStringField(source, "file_id", true, false)
	default:
		c.unsupportedValue(source, "unknown document source type ", typeNode.token.Value)
		return nil
	}
}
