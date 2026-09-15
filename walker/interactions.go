package walker

import "github.com/ahoo/cpa-plugin-privacyfilter/payload"

var interactionsRootControlFields = []string{
	"model", "agent", "agent_config", "background", "environment", "labels", "previous_interaction_id",
	"previous_response_id", "response_format", "response_mime_type", "response_modalities", "safety_settings",
	"service_tier", "store", "stream", "generation_config", "generationConfig", "webhook_config",
	"tool_choice", "ToolChoice", "parallel_tool_calls", "seed", "user", "metadata", "include", "truncation",
	"reasoning", "environment_id",
}

func walkInteractions(c *collector, root *node) error {
	if err := c.unique(root, "system_instruction", "systemInstruction", "input", "steps", "tools"); err != nil {
		return err
	}
	if err := c.markFields(root, interactionsRootControlFields...); err != nil {
		return err
	}
	system, _, hasSystem, err := c.oneOf(root, "system_instruction", "systemInstruction")
	if err != nil {
		return err
	}
	if hasSystem {
		if err = walkInteractionsSystem(c, system); err != nil {
			return err
		}
	}
	input, hasInput, err := c.field(root, "input")
	if err != nil {
		return err
	}
	if hasInput {
		if err = walkInteractionsInput(c, input, ScopeUser); err != nil {
			return err
		}
	}
	steps, hasSteps, err := c.field(root, "steps")
	if err != nil {
		return err
	}
	if hasSteps {
		if steps.kind != payload.KindArray {
			return c.shape(steps, "array", "steps")
		}
		for _, step := range steps.array {
			if err = walkInteractionItem(c, step, ScopeUser); err != nil {
				return err
			}
		}
	}
	return walkInteractionsToolDefinitions(c, root)
}

func markInteractionsOpaqueStringFields(c *collector, object *node, keys ...string) error {
	for _, key := range keys {
		if err := c.markOpaqueStringField(object, key, false, true); err != nil {
			return err
		}
	}
	return nil
}

func walkInteractionsToolDefinitions(c *collector, root *node) error {
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
		if err = c.unique(tool, "type", "name", "description", "parameters", "strict", "defer_loading"); err != nil {
			return err
		}
		typeNode, _, fieldErr := c.stringField(tool, "type", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.markOpaque(typeNode); err != nil {
			return err
		}
		if typeNode.token.Value != "function" {
			c.unsupportedValue(tool, "unknown tool definition type ", typeNode.token.Value)
			continue
		}
		if err = c.markOpaqueStringField(tool, "name", true, false); err != nil {
			return err
		}
		if err = c.addStringField(tool, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
			return err
		}
		if err = c.walkStringObjectField(tool, "parameters", true, false, ScopeSystem); err != nil {
			return err
		}
	}
	return nil
}

func walkInteractionsSystem(c *collector, system *node) error {
	switch system.kind {
	case payload.KindString:
		return c.add(system, ScopeSystem, TargetKindNaturalText, MutabilityDirect)
	case payload.KindObject:
		if err := c.unique(system, "text", "parts", "content", "role", "type", "id", "name", "signature"); err != nil {
			return err
		}
		if err := markInteractionsOpaqueStringFields(c, system, "role", "type", "id", "name", "signature"); err != nil {
			return err
		}
		text, hasText, err := c.stringField(system, "text", false)
		if err != nil {
			return err
		}
		parts, hasParts, err := c.field(system, "parts")
		if err != nil {
			return err
		}
		if hasText && hasParts {
			return &AmbiguityError{Protocol: c.protocol, Path: system.path.Clone(), Keys: []string{"text", "parts"}}
		}
		if hasText {
			return c.add(text, ScopeSystem, TargetKindNaturalText, MutabilityDirect)
		}
		if hasParts {
			return walkInteractionsParts(c, parts, ScopeSystem)
		}
		content, hasContent, err := c.field(system, "content")
		if err != nil {
			return err
		}
		if hasContent {
			return walkInteractionsNaturalContent(c, content, ScopeSystem)
		}
		c.unsupported(system, "system instruction has no text or parts")
		return nil
	default:
		return c.shape(system, "string or object", "system instruction")
	}
}

func walkInteractionsInput(c *collector, input *node, inherited Scope) error {
	switch input.kind {
	case payload.KindString:
		return c.add(input, inherited, TargetKindNaturalText, MutabilityDirect)
	case payload.KindArray:
		for _, item := range input.array {
			if err := walkInteractionItem(c, item, inherited); err != nil {
				return err
			}
		}
		return nil
	case payload.KindObject:
		return walkInteractionItem(c, input, inherited)
	default:
		return c.shape(input, "string, object, or array", "input")
	}
}

func walkInteractionItem(c *collector, item *node, inherited Scope) error {
	if item.kind == payload.KindString {
		return c.add(item, inherited, TargetKindNaturalText, MutabilityDirect)
	}
	if item.kind != payload.KindObject {
		c.unsupported(item, "step is neither a string nor object")
		return nil
	}
	controls := []string{
		"type", "role", "steps", "content", "parts", "text", "summary", "arguments", "result", "output",
		"thought", "thinking", "redacted_thinking", "signature", "thoughtSignature", "thought_signature",
		"id", "name", "call_id", "tool_use_id", "model",
	}
	if err := c.unique(item, controls...); err != nil {
		return err
	}
	if err := markInteractionsOpaqueStringFields(c, item, "signature", "thoughtSignature", "thought_signature", "id", "name", "call_id", "tool_use_id", "model"); err != nil {
		return err
	}

	scope, roleOK, err := interactionRoleScope(c, item, inherited)
	if err != nil {
		return err
	}
	steps, hasSteps, err := c.field(item, "steps")
	if err != nil {
		return err
	}
	if hasSteps && steps.kind != payload.KindArray {
		return c.shape(steps, "array", "nested steps")
	}

	typeNode, hasType, err := c.stringField(item, "type", false)
	if err != nil {
		return err
	}
	if hasType {
		if err = c.markOpaque(typeNode); err != nil {
			return err
		}
	}
	if !hasType {
		if hasSteps && roleOK {
			if err = walkInteractionSteps(c, steps, scope); err != nil {
				return err
			}
		}
		processed, processErr := walkInteractionNaturalFields(c, item, scope, roleOK)
		if processErr != nil {
			return processErr
		}
		if !processed && !hasSteps {
			c.unsupported(item, "step has no recognized type or natural-text field")
		}
		return nil
	}

	switch itemType := typeNode.token.Value; itemType {
	case "user_input":
		if !roleOK {
			return nil
		}
		if hasSteps {
			if err = walkInteractionSteps(c, steps, ScopeUser); err != nil {
				return err
			}
		}
		_, err = walkInteractionNaturalFields(c, item, ScopeUser, true)
		return err
	case "model_output":
		if err = walkInteractionsOpaqueReasoningFields(c, item); err != nil {
			return err
		}
		if !roleOK {
			return nil
		}
		if hasSteps {
			if err = walkInteractionSteps(c, steps, ScopeAssistant); err != nil {
				return err
			}
		}
		_, err = walkInteractionNaturalFields(c, item, ScopeAssistant, true)
		return err
	case "thought", "reasoning":
		if err = walkInteractionsOpaqueReasoningFields(c, item); err != nil {
			return err
		}
		_, err = walkInteractionNaturalFields(c, item, ScopeAssistant, true)
		return err
	case "function_call":
		arguments, ok, fieldErr := c.field(item, "arguments")
		if fieldErr != nil {
			return fieldErr
		}
		if !ok || arguments.kind == payload.KindNull {
			return nil
		}
		if arguments.kind == payload.KindString {
			return c.add(arguments, ScopeToolInput, TargetKindEncodedJSON, MutabilityEncodedJSON)
		}
		return c.walkStringValues(arguments, ScopeToolInput, TargetKindJSONValue)
	case "function_result":
		result, ok, fieldErr := c.field(item, "result")
		if fieldErr != nil {
			return fieldErr
		}
		if !ok || result.kind == payload.KindNull {
			return nil
		}
		return walkInteractionToolOutput(c, result)
	case "function_call_output", "custom_tool_call_output":
		output, ok, fieldErr := c.field(item, "output")
		if fieldErr != nil {
			return fieldErr
		}
		if !ok || output.kind == payload.KindNull {
			return nil
		}
		return walkInteractionToolOutput(c, output)
	case "text", "input_text", "output_text":
		if !roleOK {
			return nil
		}
		text, _, fieldErr := c.stringField(item, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		textScope := scope
		if itemType == "output_text" {
			textScope = ScopeAssistant
		}
		return c.add(text, textScope, TargetKindNaturalText, MutabilityDirect)
	case "image", "audio", "video", "document", "file", "computer_call", "web_search_call", "file_search_call", "image_generation_call":
		c.unsupported(item, "typed interaction item is not safely mutable")
		return nil
	default:
		c.unsupportedValue(item, "unknown step type ", itemType)
		return nil
	}
}

func walkInteractionsOpaqueReasoningFields(c *collector, item *node) error {
	for _, key := range []string{"thought", "thinking", "redacted_thinking"} {
		value, present, err := c.field(item, key)
		if err != nil || !present || value.kind == payload.KindNull {
			if err != nil {
				return err
			}
			continue
		}
		switch value.kind {
		case payload.KindString:
			if err = c.markOpaque(value); err != nil {
				return err
			}
		case payload.KindBoolean:
		default:
			c.unsupported(value, "structured reasoning integrity field is not admitted")
		}
	}
	return nil
}

func walkInteractionSteps(c *collector, steps *node, scope Scope) error {
	if steps.kind != payload.KindArray {
		return c.shape(steps, "array", "nested steps")
	}
	for _, nested := range steps.array {
		if err := walkInteractionItem(c, nested, scope); err != nil {
			return err
		}
	}
	return nil
}

func interactionRoleScope(c *collector, item *node, inherited Scope) (Scope, bool, error) {
	role, ok, err := c.stringField(item, "role", false)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return inherited, true, nil
	}
	if err = c.markOpaque(role); err != nil {
		return "", false, err
	}
	scope, known := scopeForRole(role.token.Value)
	if !known {
		c.unsupportedValue(role, "unknown step role ", role.token.Value)
		return inherited, false, nil
	}
	return scope, true, nil
}

func walkInteractionNaturalFields(c *collector, item *node, scope Scope, roleOK bool) (bool, error) {
	processed := false
	content, hasContent, err := c.field(item, "content")
	if err != nil {
		return false, err
	}
	if hasContent {
		processed = true
		if roleOK {
			if err = walkInteractionsNaturalContent(c, content, scope); err != nil {
				return false, err
			}
		}
	}
	parts, hasParts, err := c.field(item, "parts")
	if err != nil {
		return false, err
	}
	if hasParts {
		processed = true
		if roleOK {
			if err = walkInteractionsParts(c, parts, scope); err != nil {
				return false, err
			}
		}
	}
	text, hasText, err := c.stringField(item, "text", false)
	if err != nil {
		return false, err
	}
	if hasText {
		processed = true
		if roleOK {
			if err = c.add(text, scope, TargetKindNaturalText, MutabilityDirect); err != nil {
				return false, err
			}
		}
	}
	summary, hasSummary, err := c.field(item, "summary")
	if err != nil {
		return false, err
	}
	if hasSummary {
		processed = true
		if roleOK {
			if err = walkInteractionsNaturalContent(c, summary, scope); err != nil {
				return false, err
			}
		}
	}
	return processed, nil
}

func walkInteractionsNaturalContent(c *collector, content *node, scope Scope) error {
	switch content.kind {
	case payload.KindString:
		return c.add(content, scope, TargetKindNaturalText, MutabilityDirect)
	case payload.KindObject:
		return walkInteractionsPart(c, content, scope)
	case payload.KindArray:
		for _, part := range content.array {
			if err := walkInteractionsPart(c, part, scope); err != nil {
				return err
			}
		}
		return nil
	case payload.KindNull:
		return nil
	default:
		return c.shape(content, "string, object, array, or null", "natural content")
	}
}

func walkInteractionsParts(c *collector, parts *node, scope Scope) error {
	if parts.kind != payload.KindArray {
		return c.shape(parts, "array", "parts")
	}
	for _, part := range parts.array {
		if err := walkInteractionsPart(c, part, scope); err != nil {
			return err
		}
	}
	return nil
}

func walkInteractionsPart(c *collector, part *node, scope Scope) error {
	if part.kind == payload.KindString {
		return c.add(part, scope, TargetKindNaturalText, MutabilityDirect)
	}
	if part.kind != payload.KindObject {
		c.unsupported(part, "content part is neither string nor object")
		return nil
	}
	if err := c.unique(
		part,
		"type", "text", "content", "summary", "thought", "thinking", "signature", "thoughtSignature",
		"thought_signature", "id", "name", "call_id", "data", "url", "file_uri", "fileUri", "file_id",
		"file_data", "filename", "image_url", "mime_type", "mimeType", "annotations",
	); err != nil {
		return err
	}
	for _, key := range []string{"signature", "thoughtSignature", "thought_signature", "id", "call_id"} {
		if err := c.markOpaqueStringField(part, key, false, true); err != nil {
			return err
		}
	}
	typeNode, hasType, err := c.stringField(part, "type", false)
	if err != nil {
		return err
	}
	if !hasType {
		text, ok, textErr := c.stringField(part, "text", false)
		if textErr != nil {
			return textErr
		}
		if ok {
			return c.add(text, scope, TargetKindNaturalText, MutabilityDirect)
		}
		c.unsupported(part, "content part has no type")
		return nil
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch partType := typeNode.token.Value; partType {
	case "text", "input_text", "output_text":
		if err = c.markOpaqueStringField(part, "name", false, true); err != nil {
			return err
		}
		annotations, hasAnnotations, fieldErr := c.field(part, "annotations")
		if fieldErr != nil {
			return fieldErr
		}
		if hasAnnotations && annotations.kind != payload.KindNull {
			if annotations.kind != payload.KindArray {
				return c.shape(annotations, "array or null", "annotations")
			}
			if len(annotations.array) != 0 {
				c.unsupported(annotations, "text annotations are integrity-coupled")
			}
		}
		text, _, textErr := c.stringField(part, "text", true)
		if textErr != nil {
			return textErr
		}
		return c.add(text, scope, TargetKindNaturalText, MutabilityDirect)
	case "thought", "reasoning":
		if err = walkInteractionsOpaqueReasoningFields(c, part); err != nil {
			return err
		}
		processed := false
		for _, key := range []string{"text", "content", "summary"} {
			value, present, fieldErr := c.field(part, key)
			if fieldErr != nil {
				return fieldErr
			}
			if present {
				processed = true
				if err = walkInteractionsNaturalContent(c, value, ScopeAssistant); err != nil {
					return err
				}
			}
		}
		if !processed {
			return nil
		}
		return nil
	case "image", "audio", "video", "document", "file", "input_image", "output_image", "input_audio":
		return walkCommonOpaqueContentFields(c, part, []string{
			"data", "url", "file_uri", "fileUri", "file_id", "file_data", "filename", "image_url", "mime_type", "mimeType",
		})
	default:
		c.unsupportedValue(part, "unknown content part type ", partType)
		return nil
	}
}

func walkInteractionToolOutput(c *collector, output *node) error {
	if output.kind == payload.KindString {
		return c.add(output, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
	}
	return c.walkStringValues(output, ScopeToolOutput, TargetKindJSONValue)
}
