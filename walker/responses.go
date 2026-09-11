package walker

import (
	"fmt"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

func walkResponses(c *collector, root *node) error {
	if err := c.unique(root, "instructions", "input", "prompt"); err != nil {
		return err
	}
	instructions, hasInstructions, err := c.field(root, "instructions")
	if err != nil {
		return err
	}
	if hasInstructions {
		switch instructions.kind {
		case payload.KindString:
			if err = c.add(instructions, ScopeSystem, TargetKindNaturalText, MutabilityDirect); err != nil {
				return err
			}
		case payload.KindNull:
		default:
			return c.shape(instructions, "string or null", "instructions")
		}
	}

	input, hasInput, err := c.field(root, "input")
	if err != nil {
		return err
	}
	if hasInput {
		if err = walkResponsesInput(c, input); err != nil {
			return err
		}
	}

	prompt, hasPrompt, err := c.field(root, "prompt")
	if err != nil {
		return err
	}
	if hasPrompt {
		if prompt.kind != payload.KindObject {
			return c.shape(prompt, "object", "prompt")
		}
		if err = c.unique(prompt, "variables", "id", "name"); err != nil {
			return err
		}
		if err = c.markFields(prompt, "id", "name"); err != nil {
			return err
		}
		variables, ok, fieldErr := c.field(prompt, "variables")
		if fieldErr != nil {
			return fieldErr
		}
		if ok {
			if err = c.walkStringValues(variables, ScopeUser, TargetKindJSONValue); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkResponsesInput(c *collector, input *node) error {
	switch input.kind {
	case payload.KindString:
		return c.add(input, ScopeUser, TargetKindNaturalText, MutabilityDirect)
	case payload.KindArray:
		for _, item := range input.array {
			if err := walkResponsesItem(c, item); err != nil {
				return err
			}
		}
		return nil
	default:
		return c.shape(input, "string or array", "input")
	}
}

func walkResponsesItem(c *collector, item *node) error {
	if item.kind != payload.KindObject {
		c.unsupported(item, "input array element is not an object")
		return nil
	}
	if err := c.unique(item, "type", "role", "content", "text", "arguments", "output", "id", "name", "call_id", "signature", "encrypted_content"); err != nil {
		return err
	}
	if err := c.markFields(item, "id", "name", "call_id", "signature", "encrypted_content"); err != nil {
		return err
	}
	typeNode, hasType, err := c.stringField(item, "type", false)
	if err != nil {
		return err
	}
	itemType := ""
	if hasType {
		itemType = typeNode.token.Value
		if err = c.markOpaque(typeNode); err != nil {
			return err
		}
	}
	if !hasType {
		if _, hasContent, fieldErr := c.field(item, "content"); fieldErr != nil {
			return fieldErr
		} else if hasContent {
			return walkResponsesMessage(c, item)
		}
		c.unsupported(item, "input item has no type")
		return nil
	}

	switch itemType {
	case "message":
		return walkResponsesMessage(c, item)
	case "function_call":
		arguments, ok, fieldErr := c.stringField(item, "arguments", false)
		if fieldErr != nil {
			return fieldErr
		}
		if ok {
			return c.add(arguments, ScopeToolInput, TargetKindEncodedJSON, MutabilityEncodedJSON)
		}
		return nil
	case "function_call_output", "custom_tool_call_output":
		output, ok, fieldErr := c.stringField(item, "output", false)
		if fieldErr != nil {
			return fieldErr
		}
		if ok {
			return c.add(output, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
		}
		return nil
	case "text", "input_text", "output_text":
		text, _, fieldErr := c.stringField(item, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		scope := ScopeUser
		if itemType == "output_text" {
			scope = ScopeAssistant
		}
		return c.add(text, scope, TargetKindNaturalText, MutabilityDirect)
	case "reasoning", "thought", "computer_call", "computer_call_output", "web_search_call", "file_search_call", "image_generation_call", "local_shell_call", "shell_call", "mcp_call", "mcp_approval_request", "mcp_approval_response":
		return c.markOpaque(item)
	default:
		c.unsupported(item, fmt.Sprintf("unknown input item type %q", itemType))
		return nil
	}
}

func walkResponsesMessage(c *collector, message *node) error {
	roleNode, _, err := c.stringField(message, "role", true)
	if err != nil {
		return err
	}
	scope, ok := scopeForRole(roleNode.token.Value)
	if err = c.markOpaque(roleNode); err != nil {
		return err
	}
	if !ok {
		c.unsupported(roleNode, fmt.Sprintf("unknown message role %q", roleNode.token.Value))
		return nil
	}
	content, present, err := c.field(message, "content")
	if err != nil {
		return err
	}
	if !present {
		return c.missing(message, "content", "string, array, or null")
	}
	return c.walkTypedTextContent(content, scope)
}
