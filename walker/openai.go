package walker

import (
	"fmt"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

func walkOpenAI(c *collector, root *node) error {
	messages, _, err := c.arrayField(root, "messages", true)
	if err != nil {
		return err
	}
	for _, message := range messages.array {
		if err = walkOpenAIMessage(c, message); err != nil {
			return err
		}
	}
	return nil
}

func walkOpenAIMessage(c *collector, message *node) error {
	if message.kind != payload.KindObject {
		return c.shape(message, "object", "messages element")
	}
	if err := c.unique(message, "role", "content", "tool_calls", "function_call", "name", "id", "call_id"); err != nil {
		return err
	}
	if err := c.markFields(message, "name", "id", "call_id"); err != nil {
		return err
	}
	roleNode, _, err := c.stringField(message, "role", true)
	if err != nil {
		return err
	}
	scope, roleOK := scopeForRole(roleNode.token.Value)
	if !roleOK {
		c.unsupported(roleNode, fmt.Sprintf("unknown message role %q", roleNode.token.Value))
		if err = c.markOpaque(roleNode); err != nil {
			return err
		}
	} else if err = c.markOpaque(roleNode); err != nil {
		return err
	}

	content, hasContent, err := c.field(message, "content")
	if err != nil {
		return err
	}
	if hasContent && roleOK {
		if err = c.walkTypedTextContent(content, scope); err != nil {
			return err
		}
	}

	toolCalls, hasToolCalls, err := c.field(message, "tool_calls")
	if err != nil {
		return err
	}
	if hasToolCalls {
		if toolCalls.kind != payload.KindArray {
			return c.shape(toolCalls, "array", "tool_calls")
		}
		for _, call := range toolCalls.array {
			if err = walkOpenAIToolCall(c, call); err != nil {
				return err
			}
		}
	}

	legacy, hasLegacy, err := c.field(message, "function_call")
	if err != nil {
		return err
	}
	if hasLegacy {
		if legacy.kind != payload.KindObject {
			return c.shape(legacy, "object", "function_call")
		}
		if err = walkOpenAIFunction(c, legacy); err != nil {
			return err
		}
	}
	return nil
}

func walkOpenAIToolCall(c *collector, call *node) error {
	if call.kind != payload.KindObject {
		return c.shape(call, "object", "tool_calls element")
	}
	if err := c.unique(call, "type", "function", "id", "name", "call_id"); err != nil {
		return err
	}
	if err := c.markFields(call, "id", "name", "call_id"); err != nil {
		return err
	}
	callType, hasType, err := c.stringField(call, "type", false)
	if err != nil {
		return err
	}
	if hasType {
		if err = c.markOpaque(callType); err != nil {
			return err
		}
		if callType.token.Value != "function" {
			c.unsupported(call, fmt.Sprintf("unknown tool call type %q", callType.token.Value))
			return nil
		}
	}
	function, _, err := c.objectField(call, "function", true)
	if err != nil {
		return err
	}
	return walkOpenAIFunction(c, function)
}

func walkOpenAIFunction(c *collector, function *node) error {
	if err := c.unique(function, "arguments", "name", "id", "call_id"); err != nil {
		return err
	}
	if err := c.markFields(function, "name", "id", "call_id"); err != nil {
		return err
	}
	arguments, ok, err := c.stringField(function, "arguments", false)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return c.add(arguments, ScopeToolInput, TargetKindEncodedJSON, MutabilityEncodedJSON)
}
