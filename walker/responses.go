package walker

import "github.com/ahoo/cpa-plugin-privacyfilter/payload"

func walkResponses(c *collector, root *node) error {
	if err := c.unique(root, "instructions", "input", "prompt", "context_management", "conversation", "tools"); err != nil {
		return err
	}
	if err := walkResponsesRootControls(c, root); err != nil {
		return err
	}
	if err := walkResponsesRootReferences(c, root); err != nil {
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
	if hasInput && input.kind != payload.KindNull {
		if err = walkResponsesInput(c, input); err != nil {
			return err
		}
	}

	prompt, hasPrompt, err := c.field(root, "prompt")
	if err != nil {
		return err
	}
	if hasPrompt {
		if err = walkResponsesPrompt(c, prompt); err != nil {
			return err
		}
	}

	tools, hasTools, err := c.field(root, "tools")
	if err != nil {
		return err
	}
	if hasTools {
		return walkResponsesRootTools(c, tools)
	}
	return nil
}

func walkResponsesRootControls(c *collector, root *node) error {
	if err := c.unique(
		root,
		"model", "background", "max_output_tokens", "max_tool_calls", "parallel_tool_calls",
		"previous_response_id", "store", "temperature", "top_logprobs", "top_p", "prompt_cache_key",
		"safety_identifier", "user", "include", "metadata", "moderation", "prompt_cache_retention",
		"service_tier", "stream", "stream_options", "truncation", "prompt_cache_options", "reasoning",
		"text", "tool_choice",
	); err != nil {
		return err
	}
	for _, key := range []string{
		"model", "previous_response_id", "prompt_cache_key", "safety_identifier", "user",
		"prompt_cache_retention", "service_tier", "truncation",
	} {
		if err := c.markOpaqueStringField(root, key, false, true); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		key  string
		kind payload.Kind
	}{
		{"background", payload.KindBoolean},
		{"max_output_tokens", payload.KindNumber},
		{"max_tool_calls", payload.KindNumber},
		{"parallel_tool_calls", payload.KindBoolean},
		{"store", payload.KindBoolean},
		{"temperature", payload.KindNumber},
		{"top_logprobs", payload.KindNumber},
		{"top_p", payload.KindNumber},
		{"stream", payload.KindBoolean},
	} {
		if _, _, err := responsesFieldOfKind(c, root, field.key, field.kind, false, true); err != nil {
			return err
		}
	}
	if err := c.markOpaqueStringArrayField(root, "include", false, true); err != nil {
		return err
	}
	metadata, present, err := responsesFieldOfKind(c, root, "metadata", payload.KindObject, false, true)
	if err != nil {
		return err
	}
	if present {
		if err = c.markOpaque(metadata); err != nil {
			return err
		}
	}
	if err = walkResponsesModeration(c, root); err != nil {
		return err
	}
	if err = walkResponsesPromptCacheOptions(c, root); err != nil {
		return err
	}
	if err = walkResponsesStreamOptions(c, root); err != nil {
		return err
	}
	if err = walkResponsesReasoningConfig(c, root); err != nil {
		return err
	}
	if err = walkResponsesTextConfig(c, root); err != nil {
		return err
	}
	return walkResponsesToolChoice(c, root)
}

func markResponsesOpaqueStringFields(c *collector, object *node, keys ...string) error {
	for _, key := range keys {
		if err := c.markOpaqueStringField(object, key, false, true); err != nil {
			return err
		}
	}
	return nil
}

func responsesFieldOfKind(
	c *collector,
	object *node,
	key string,
	expected payload.Kind,
	required, nullable bool,
) (*node, bool, error) {
	value, present, err := c.field(object, key)
	if err != nil {
		return nil, false, err
	}
	if !present {
		if required {
			return nil, false, c.missing(object, key, expected.String())
		}
		return nil, false, nil
	}
	if value.kind == payload.KindNull && nullable {
		return nil, false, nil
	}
	if value.kind != expected {
		label := expected.String()
		if nullable {
			label += " or null"
		}
		return nil, false, c.shape(value, label, key)
	}
	return value, true, nil
}

func walkResponsesModeration(c *collector, root *node) error {
	moderation, present, err := responsesFieldOfKind(c, root, "moderation", payload.KindObject, false, true)
	if err != nil || !present {
		return err
	}
	if err = c.unique(moderation, "model", "policy"); err != nil {
		return err
	}
	if err = c.markOpaqueStringField(moderation, "model", true, false); err != nil {
		return err
	}
	policy, hasPolicy, err := responsesFieldOfKind(c, moderation, "policy", payload.KindObject, false, true)
	if err != nil || !hasPolicy {
		return err
	}
	if err = c.unique(policy, "input", "output"); err != nil {
		return err
	}
	for _, key := range []string{"input", "output"} {
		direction, hasDirection, fieldErr := responsesFieldOfKind(c, policy, key, payload.KindObject, false, true)
		if fieldErr != nil {
			return fieldErr
		}
		if !hasDirection {
			continue
		}
		if err = c.unique(direction, "mode"); err != nil {
			return err
		}
		if err = c.markOpaqueStringField(direction, "mode", true, false); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesPromptCacheOptions(c *collector, root *node) error {
	options, present, err := responsesFieldOfKind(c, root, "prompt_cache_options", payload.KindObject, false, true)
	if err != nil || !present {
		return err
	}
	if err = c.unique(options, "mode", "ttl"); err != nil {
		return err
	}
	if err = c.markOpaqueStringField(options, "mode", false, true); err != nil {
		return err
	}
	return c.markOpaqueStringField(options, "ttl", false, true)
}

func walkResponsesStreamOptions(c *collector, root *node) error {
	options, present, err := responsesFieldOfKind(c, root, "stream_options", payload.KindObject, false, true)
	if err != nil || !present {
		return err
	}
	if err = c.unique(options, "include_obfuscation"); err != nil {
		return err
	}
	_, _, err = responsesFieldOfKind(c, options, "include_obfuscation", payload.KindBoolean, false, true)
	return err
}

func walkResponsesReasoningConfig(c *collector, root *node) error {
	reasoning, present, err := responsesFieldOfKind(c, root, "reasoning", payload.KindObject, false, true)
	if err != nil || !present {
		return err
	}
	if err = c.unique(reasoning, "context", "effort", "generate_summary", "summary", "mode"); err != nil {
		return err
	}
	for _, key := range []string{"context", "effort", "generate_summary", "summary", "mode"} {
		if err = c.markOpaqueStringField(reasoning, key, false, true); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesTextConfig(c *collector, root *node) error {
	text, present, err := responsesFieldOfKind(c, root, "text", payload.KindObject, false, true)
	if err != nil || !present {
		return err
	}
	if err = c.unique(text, "verbosity", "format"); err != nil {
		return err
	}
	if err = c.markOpaqueStringField(text, "verbosity", false, true); err != nil {
		return err
	}
	format, hasFormat, err := responsesFieldOfKind(c, text, "format", payload.KindObject, false, true)
	if err != nil || !hasFormat {
		return err
	}
	formatType, _, err := c.stringField(format, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(formatType); err != nil {
		return err
	}
	switch formatType.token.Value {
	case "text", "json_object":
		return c.unique(format, "type")
	case "json_schema":
		if err = c.unique(format, "type", "name", "schema", "strict", "description"); err != nil {
			return err
		}
		if err = c.markOpaqueStringField(format, "name", true, false); err != nil {
			return err
		}
		if err = c.addStringField(format, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
			return err
		}
		schema, _, fieldErr := responsesFieldOfKind(c, format, "schema", payload.KindObject, true, false)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.walkStringValues(schema, ScopeSystem, TargetKindJSONValue); err != nil {
			return err
		}
		_, _, err = responsesFieldOfKind(c, format, "strict", payload.KindBoolean, false, true)
		return err
	default:
		c.unsupportedValue(format, "unknown response text format type ", formatType.token.Value)
		return nil
	}
}

func walkResponsesToolChoice(c *collector, root *node) error {
	choice, present, err := c.field(root, "tool_choice")
	if err != nil || !present || choice.kind == payload.KindNull {
		return err
	}
	if choice.kind == payload.KindString {
		return c.markOpaque(choice)
	}
	if choice.kind != payload.KindObject {
		return c.shape(choice, "string, object, or null", "tool_choice")
	}
	typeNode, _, err := c.stringField(choice, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "allowed_tools":
		if err = c.unique(choice, "type", "mode", "tools"); err != nil {
			return err
		}
		if err = c.markOpaqueStringField(choice, "mode", true, false); err != nil {
			return err
		}
		tools, _, fieldErr := responsesFieldOfKind(c, choice, "tools", payload.KindArray, true, false)
		if fieldErr != nil {
			return fieldErr
		}
		for _, tool := range tools.array {
			if tool.kind != payload.KindObject {
				return c.shape(tool, "object", "allowed tool definition")
			}
			if err = c.markOpaque(tool); err != nil {
				return err
			}
		}
		return nil
	case "function", "custom":
		if err = c.unique(choice, "type", "name"); err != nil {
			return err
		}
		return c.markOpaqueStringField(choice, "name", true, false)
	case "mcp":
		if err = c.unique(choice, "type", "server_label", "name"); err != nil {
			return err
		}
		if err = c.markOpaqueStringField(choice, "server_label", true, false); err != nil {
			return err
		}
		return c.markOpaqueStringField(choice, "name", false, true)
	case "file_search", "web_search_preview", "computer", "computer_use_preview", "computer_use",
		"web_search_preview_2025_03_11", "image_generation", "code_interpreter",
		"programmatic_tool_calling", "apply_patch", "shell":
		return c.unique(choice, "type")
	default:
		c.unsupportedValue(choice, "unknown tool-choice type ", typeNode.token.Value)
		return nil
	}
}

func walkResponsesRootReferences(c *collector, root *node) error {
	contextManagement, hasContextManagement, err := c.field(root, "context_management")
	if err != nil {
		return err
	}
	if hasContextManagement {
		if contextManagement.kind != payload.KindArray {
			return c.shape(contextManagement, "array", "context_management")
		}
		for _, entry := range contextManagement.array {
			if entry.kind != payload.KindObject {
				c.unsupported(entry, "context_management element is not an object")
				continue
			}
			if err = c.unique(entry, "type", "compact_threshold"); err != nil {
				return err
			}
			typeNode, _, fieldErr := c.stringField(entry, "type", true)
			if fieldErr != nil {
				return fieldErr
			}
			if err = c.markOpaque(typeNode); err != nil {
				return err
			}
			if typeNode.token.Value != "compaction" {
				c.unsupportedValue(entry, "unknown context-management type ", typeNode.token.Value)
			}
		}
	}

	conversation, hasConversation, err := c.field(root, "conversation")
	if err != nil {
		return err
	}
	if !hasConversation || conversation.kind == payload.KindNull {
		return nil
	}
	switch conversation.kind {
	case payload.KindString:
		return c.markOpaque(conversation)
	case payload.KindObject:
		if err = c.unique(conversation, "id"); err != nil {
			return err
		}
		id, _, fieldErr := c.stringField(conversation, "id", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.markOpaque(id)
	default:
		return c.shape(conversation, "string or object", "conversation")
	}
}

func walkResponsesPrompt(c *collector, prompt *node) error {
	if prompt.kind != payload.KindObject {
		return c.shape(prompt, "object", "prompt")
	}
	if err := c.unique(prompt, "variables", "id", "version", "name"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, prompt, "id", "version", "name"); err != nil {
		return err
	}
	variables, present, err := c.field(prompt, "variables")
	if err != nil {
		return err
	}
	if !present || variables.kind == payload.KindNull {
		return nil
	}
	if variables.kind != payload.KindObject {
		return c.shape(variables, "object", "prompt variables")
	}
	for _, variable := range variables.object {
		switch variable.value.kind {
		case payload.KindString:
			if err = c.add(variable.value, ScopeUser, TargetKindJSONValue, MutabilityDirect); err != nil {
				return err
			}
		case payload.KindObject:
			if err = walkResponsesInputContent(c, variable.value, ScopeUser, TargetKindJSONValue); err != nil {
				return err
			}
		default:
			c.unsupported(variable.value, "prompt variable is not a supported v3.42.0 variant")
		}
	}
	return nil
}

func walkResponsesRootTools(c *collector, tools *node) error {
	if tools.kind != payload.KindArray {
		return c.shape(tools, "array", "tools")
	}
	for _, tool := range tools.array {
		if tool.kind != payload.KindObject {
			c.unsupported(tool, "tool definition is not an object")
			continue
		}
		typeNode, _, err := c.stringField(tool, "type", true)
		if err != nil {
			return err
		}
		if err = c.markOpaque(typeNode); err != nil {
			return err
		}
		switch typeNode.token.Value {
		case "function":
			if err = walkResponsesFunctionTool(c, tool); err != nil {
				return err
			}
		case "file_search", "computer", "computer_use_preview", "web_search", "web_search_2025_08_26",
			"mcp", "code_interpreter", "programmatic_tool_calling", "image_generation", "local_shell",
			"shell", "custom", "namespace", "tool_search", "web_search_preview",
			"web_search_preview_2025_03_11", "apply_patch":
			c.unsupported(tool, "root tool definition variant is not admitted")
		default:
			c.unsupportedValue(tool, "unknown root tool definition type ", typeNode.token.Value)
		}
	}
	return nil
}

func walkResponsesFunctionTool(c *collector, tool *node) error {
	if err := c.unique(
		tool,
		"type", "name", "description", "parameters", "strict", "allowed_callers", "defer_loading", "output_schema",
	); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(tool, "name", true, false); err != nil {
		return err
	}
	if err := c.addStringField(tool, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
		return err
	}
	if err := c.walkStringObjectField(tool, "parameters", true, false, ScopeSystem); err != nil {
		return err
	}
	if err := c.markOpaqueStringArrayField(tool, "allowed_callers", false, true); err != nil {
		return err
	}
	return c.walkStringObjectField(tool, "output_schema", false, true, ScopeSystem)
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
	typeNode, hasType, err := c.stringField(item, "type", false)
	if err != nil {
		return err
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
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}

	switch typeNode.token.Value {
	case "message":
		return walkResponsesMessage(c, item)
	case "file_search_call":
		return walkResponsesFileSearch(c, item)
	case "computer_call":
		return walkResponsesComputerCall(c, item)
	case "computer_call_output":
		return walkResponsesComputerOutput(c, item)
	case "web_search_call":
		return walkResponsesWebSearch(c, item)
	case "function_call":
		return walkResponsesFunctionCall(c, item)
	case "function_call_output":
		return walkResponsesCallOutput(c, item, false)
	case "tool_search_call":
		return walkResponsesToolSearchCall(c, item)
	case "tool_search_output":
		c.unsupported(item, "tool-search output definitions are not admitted")
		return nil
	case "additional_tools":
		c.unsupported(item, "additional tool definitions are not admitted")
		return nil
	case "reasoning":
		return walkResponsesReasoningReplay(c, item)
	case "compaction":
		return walkResponsesCompactionReplay(c, item)
	case "image_generation_call":
		return walkResponsesImageGenerationReplay(c, item)
	case "code_interpreter_call":
		return walkResponsesCodeInterpreter(c, item)
	case "local_shell_call":
		return walkResponsesLocalShell(c, item)
	case "local_shell_call_output":
		return walkResponsesLocalShellOutput(c, item)
	case "shell_call":
		return walkResponsesShellCall(c, item)
	case "shell_call_output":
		return walkResponsesShellOutput(c, item)
	case "apply_patch_call":
		return walkResponsesApplyPatch(c, item)
	case "apply_patch_call_output":
		return walkResponsesApplyPatchOutput(c, item)
	case "mcp_list_tools":
		return walkResponsesMCPListTools(c, item)
	case "mcp_approval_request":
		return walkResponsesMCPApprovalRequest(c, item)
	case "mcp_approval_response":
		return walkResponsesMCPApprovalResponse(c, item)
	case "mcp_call":
		return walkResponsesMCPCall(c, item)
	case "custom_tool_call_output":
		return walkResponsesCallOutput(c, item, true)
	case "custom_tool_call":
		return walkResponsesCustomCall(c, item)
	case "compaction_trigger":
		return c.unique(item, "type")
	case "item_reference":
		return walkResponsesReferenceItem(c, item)
	case "program":
		c.unsupported(item, "program code is integrity-coupled to its fingerprint")
		return nil
	case "program_output":
		return walkResponsesProgramOutput(c, item)
	case "text", "input_text", "output_text":
		return walkResponsesCompatibilityText(c, item, typeNode.token.Value)
	case "thought":
		c.unsupported(item, "legacy thought item semantics are not admitted")
		return nil
	default:
		c.unsupportedValue(item, "unknown input item type ", typeNode.token.Value)
		return nil
	}
}

func walkResponsesMessage(c *collector, message *node) error {
	if err := c.unique(message, "type", "role", "content", "id", "status", "phase"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, message, "id", "status", "phase"); err != nil {
		return err
	}
	roleNode, _, err := c.stringField(message, "role", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(roleNode); err != nil {
		return err
	}
	scope, roleOK := scopeForRole(roleNode.token.Value)
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
	if content.kind == payload.KindString {
		if scope == ScopeToolOutput {
			return c.add(content, scope, TargetKindToolOutput, MutabilityJSONOrPlain)
		}
		return c.add(content, scope, TargetKindNaturalText, MutabilityDirect)
	}
	if content.kind != payload.KindArray {
		return c.shape(content, "string or array", "message content")
	}
	for _, block := range content.array {
		if block.kind != payload.KindObject {
			c.unsupported(block, "message content element is not an object")
			continue
		}
		blockType, _, fieldErr := c.stringField(block, "type", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.markOpaque(blockType); err != nil {
			return err
		}
		switch blockType.token.Value {
		case "input_text", "input_image", "input_file":
			if err = walkResponsesInputContent(c, block, scope, TargetKindNaturalText); err != nil {
				return err
			}
		case "output_text", "refusal":
			if scope != ScopeAssistant {
				c.unsupported(block, "output content outside assistant message")
				continue
			}
			if err = walkResponsesOutputContent(c, block); err != nil {
				return err
			}
		case "text":
			if err = c.unique(block, "type", "text", "id", "name", "call_id", "signature", "prompt_cache_breakpoint"); err != nil {
				return err
			}
			if err = markResponsesOpaqueStringFields(c, block, "id", "name", "call_id", "signature"); err != nil {
				return err
			}
			if err = walkResponsesCacheBreakpoint(c, block); err != nil {
				return err
			}
			text, _, textErr := c.stringField(block, "text", true)
			if textErr != nil {
				return textErr
			}
			kind := TargetKindNaturalText
			mutable := MutabilityDirect
			if scope == ScopeToolOutput {
				kind = TargetKindToolOutput
				mutable = MutabilityDirect
			}
			if err = c.add(text, scope, kind, mutable); err != nil {
				return err
			}
		default:
			c.unsupportedValue(block, "unknown message content type ", blockType.token.Value)
		}
	}
	return nil
}

func walkResponsesInputContent(c *collector, block *node, scope Scope, kind TargetKind) error {
	if block.kind != payload.KindObject {
		return c.shape(block, "object", "input content")
	}
	if err := c.unique(
		block,
		"type", "text", "file_id", "image_url", "detail", "file_data", "file_url", "filename", "prompt_cache_breakpoint",
	); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(block, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	if err = walkResponsesCacheBreakpoint(c, block); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "input_text":
		text, _, fieldErr := c.stringField(block, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(text, scope, kind, MutabilityDirect)
	case "input_image":
		return markResponsesOpaqueStringFields(c, block, "file_id", "image_url", "detail")
	case "input_file":
		return markResponsesOpaqueStringFields(c, block, "file_data", "file_id", "file_url", "filename", "detail")
	default:
		c.unsupportedValue(block, "unknown input content type ", typeNode.token.Value)
		return nil
	}
}

func walkResponsesCacheBreakpoint(c *collector, object *node) error {
	breakpoint, present, err := c.field(object, "prompt_cache_breakpoint")
	if err != nil || !present || breakpoint.kind == payload.KindNull {
		return err
	}
	if breakpoint.kind != payload.KindObject {
		return c.shape(breakpoint, "object", "prompt_cache_breakpoint")
	}
	if err = c.unique(breakpoint, "mode"); err != nil {
		return err
	}
	mode, _, err := c.stringField(breakpoint, "mode", true)
	if err != nil {
		return err
	}
	return c.markOpaque(mode)
}

func walkResponsesOutputContent(c *collector, block *node) error {
	if err := c.unique(block, "type", "text", "refusal", "annotations", "logprobs"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(block, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	if typeNode.token.Value == "output_text" {
		annotationsSafe, fieldErr := walkResponsesOutputAnnotations(c, block)
		if fieldErr != nil {
			return fieldErr
		}
		if !annotationsSafe {
			return nil
		}
		logprobs, present, fieldErr := c.field(block, "logprobs")
		if fieldErr != nil {
			return fieldErr
		}
		if present && logprobs.kind != payload.KindNull {
			if logprobs.kind != payload.KindArray {
				return c.shape(logprobs, "array or null", "logprobs")
			}
			if len(logprobs.array) != 0 {
				c.unsupported(block, "output text has integrity-coupled logprobs")
				return nil
			}
		}
		text, _, fieldErr := c.stringField(block, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(text, ScopeAssistant, TargetKindNaturalText, MutabilityDirect)
	}
	if typeNode.token.Value == "refusal" {
		refusal, _, fieldErr := c.stringField(block, "refusal", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(refusal, ScopeAssistant, TargetKindNaturalText, MutabilityDirect)
	}
	c.unsupportedValue(block, "unknown output content type ", typeNode.token.Value)
	return nil
}

func walkResponsesOutputAnnotations(c *collector, block *node) (bool, error) {
	annotations, present, err := c.field(block, "annotations")
	if err != nil || !present || annotations.kind == payload.KindNull {
		return true, err
	}
	if annotations.kind != payload.KindArray {
		return false, c.shape(annotations, "array or null", "annotations")
	}
	for _, annotation := range annotations.array {
		if annotation.kind != payload.KindObject {
			c.unsupported(block, "output-text annotation is not an object")
			return false, nil
		}
		annotationType, _, fieldErr := c.stringField(annotation, "type", true)
		if fieldErr != nil {
			return false, fieldErr
		}
		if err = c.markOpaque(annotationType); err != nil {
			return false, err
		}
		switch annotationType.token.Value {
		case "file_citation":
			if err = c.unique(annotation, "type", "file_id", "filename", "index"); err != nil {
				return false, err
			}
			if err = c.markOpaqueStringField(annotation, "file_id", true, false); err != nil {
				return false, err
			}
			if err = c.markOpaqueStringField(annotation, "filename", true, false); err != nil {
				return false, err
			}
			if _, _, err = responsesFieldOfKind(c, annotation, "index", payload.KindNumber, true, false); err != nil {
				return false, err
			}
		case "file_path":
			if err = c.unique(annotation, "type", "file_id", "index"); err != nil {
				return false, err
			}
			if err = c.markOpaqueStringField(annotation, "file_id", true, false); err != nil {
				return false, err
			}
			if _, _, err = responsesFieldOfKind(c, annotation, "index", payload.KindNumber, true, false); err != nil {
				return false, err
			}
		case "url_citation", "container_file_citation":
			c.unsupported(block, "output text has position-coupled annotations")
			return false, nil
		default:
			c.unsupportedValue(block, "unknown output-text annotation type ", annotationType.token.Value)
			return false, nil
		}
	}
	return true, nil
}

func walkResponsesFileSearch(c *collector, item *node) error {
	if err := c.unique(item, "type", "id", "queries", "status", "results"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "status"); err != nil {
		return err
	}
	queries, _, err := c.arrayField(item, "queries", true)
	if err != nil {
		return err
	}
	for _, query := range queries.array {
		if query.kind != payload.KindString {
			c.unsupported(query, "file-search query is not a string")
			continue
		}
		if err = c.add(query, ScopeToolInput, TargetKindNaturalText, MutabilityDirect); err != nil {
			return err
		}
	}
	results, present, err := c.field(item, "results")
	if err != nil || !present || results.kind == payload.KindNull {
		return err
	}
	if results.kind != payload.KindArray {
		return c.shape(results, "array", "file-search results")
	}
	for _, result := range results.array {
		if result.kind != payload.KindObject {
			c.unsupported(result, "file-search result is not an object")
			continue
		}
		if err = c.unique(result, "file_id", "filename", "score", "text", "attributes"); err != nil {
			return err
		}
		if err = markResponsesOpaqueStringFields(c, result, "file_id", "filename"); err != nil {
			return err
		}
		text, hasText, fieldErr := c.stringField(result, "text", false)
		if fieldErr != nil {
			return fieldErr
		}
		if hasText {
			if err = c.add(text, ScopeToolOutput, TargetKindToolOutput, MutabilityDirect); err != nil {
				return err
			}
		}
		attributes, hasAttributes, fieldErr := c.field(result, "attributes")
		if fieldErr != nil {
			return fieldErr
		}
		if hasAttributes {
			if attributes.kind != payload.KindObject {
				return c.shape(attributes, "object", "file-search attributes")
			}
			for _, attribute := range attributes.object {
				switch attribute.value.kind {
				case payload.KindString:
					if err = c.add(attribute.value, ScopeToolOutput, TargetKindJSONValue, MutabilityDirect); err != nil {
						return err
					}
				case payload.KindNumber, payload.KindBoolean:
				default:
					c.unsupported(attribute.value, "file-search attribute has unsupported type")
				}
			}
		}
	}
	return nil
}

func walkResponsesComputerCall(c *collector, item *node) error {
	if err := c.unique(item, "type", "id", "call_id", "pending_safety_checks", "status", "action", "actions"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "call_id", "status"); err != nil {
		return err
	}
	if err := walkResponsesSafetyChecks(c, item, "pending_safety_checks", true); err != nil {
		return err
	}
	action, hasAction, err := c.field(item, "action")
	if err != nil {
		return err
	}
	actions, hasActions, err := c.field(item, "actions")
	if err != nil {
		return err
	}
	if hasAction {
		if err = walkResponsesComputerAction(c, action); err != nil {
			return err
		}
	}
	if hasActions {
		if actions.kind != payload.KindArray {
			return c.shape(actions, "array", "computer actions")
		}
		for _, action := range actions.array {
			if err = walkResponsesComputerAction(c, action); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkResponsesComputerAction(c *collector, action *node) error {
	if action.kind != payload.KindObject {
		c.unsupported(action, "computer action is not an object")
		return nil
	}
	if err := c.unique(action, "type", "text", "button", "keys", "path", "x", "y", "scroll_x", "scroll_y"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(action, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "type":
		if err = c.unique(action, "type", "text"); err != nil {
			return err
		}
		text, _, fieldErr := c.stringField(action, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(text, ScopeToolInput, TargetKindNaturalText, MutabilityDirect)
	case "click":
		if err = c.unique(action, "type", "button", "keys", "x", "y"); err != nil {
			return err
		}
		if err = c.markOpaqueStringField(action, "button", true, false); err != nil {
			return err
		}
		if err = c.markOpaqueStringArrayField(action, "keys", false, true); err != nil {
			return err
		}
		return walkResponsesCoordinates(c, action, "x", "y")
	case "double_click":
		if err = c.unique(action, "type", "keys", "x", "y"); err != nil {
			return err
		}
		if err = c.markOpaqueStringArrayField(action, "keys", true, false); err != nil {
			return err
		}
		return walkResponsesCoordinates(c, action, "x", "y")
	case "drag":
		if err = c.unique(action, "type", "path", "keys"); err != nil {
			return err
		}
		if err = c.markOpaqueStringArrayField(action, "keys", false, true); err != nil {
			return err
		}
		return walkResponsesDragPath(c, action)
	case "keypress":
		if err = c.unique(action, "type", "keys"); err != nil {
			return err
		}
		return c.markOpaqueStringArrayField(action, "keys", true, false)
	case "move":
		if err = c.unique(action, "type", "keys", "x", "y"); err != nil {
			return err
		}
		if err = c.markOpaqueStringArrayField(action, "keys", false, true); err != nil {
			return err
		}
		return walkResponsesCoordinates(c, action, "x", "y")
	case "scroll":
		if err = c.unique(action, "type", "keys", "scroll_x", "scroll_y", "x", "y"); err != nil {
			return err
		}
		if err = c.markOpaqueStringArrayField(action, "keys", false, true); err != nil {
			return err
		}
		return walkResponsesCoordinates(c, action, "scroll_x", "scroll_y", "x", "y")
	case "screenshot", "wait":
		return c.unique(action, "type")
	default:
		c.unsupportedValue(action, "unknown computer action type ", typeNode.token.Value)
		return nil
	}
}

func walkResponsesCoordinates(c *collector, action *node, keys ...string) error {
	for _, key := range keys {
		if _, _, err := responsesFieldOfKind(c, action, key, payload.KindNumber, true, false); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesDragPath(c *collector, action *node) error {
	path, _, err := responsesFieldOfKind(c, action, "path", payload.KindArray, true, false)
	if err != nil {
		return err
	}
	for _, point := range path.array {
		if point.kind != payload.KindObject {
			return c.shape(point, "object", "drag path element")
		}
		if err = c.unique(point, "x", "y"); err != nil {
			return err
		}
		if err = walkResponsesCoordinates(c, point, "x", "y"); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesSafetyChecks(c *collector, item *node, key string, required bool) error {
	checks, present, err := c.field(item, key)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return c.missing(item, key, "array")
		}
		return nil
	}
	if checks.kind != payload.KindArray {
		return c.shape(checks, "array", key)
	}
	for _, check := range checks.array {
		if check.kind != payload.KindObject {
			c.unsupported(check, "safety check is not an object")
			continue
		}
		if err = c.unique(check, "id", "code", "message"); err != nil {
			return err
		}
		if err = markResponsesOpaqueStringFields(c, check, "id", "code", "message"); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesComputerOutput(c *collector, item *node) error {
	if err := c.unique(item, "type", "call_id", "output", "id", "acknowledged_safety_checks", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "id", "status"); err != nil {
		return err
	}
	if err := walkResponsesSafetyChecks(c, item, "acknowledged_safety_checks", false); err != nil {
		return err
	}
	output, _, err := c.objectField(item, "output", true)
	if err != nil {
		return err
	}
	if err = c.unique(output, "type", "file_id", "image_url"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(output, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	if typeNode.token.Value != "computer_screenshot" {
		c.unsupportedValue(output, "unknown computer output type ", typeNode.token.Value)
		return nil
	}
	return markResponsesOpaqueStringFields(c, output, "file_id", "image_url")
}

func walkResponsesWebSearch(c *collector, item *node) error {
	if err := c.unique(item, "type", "id", "action", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "status"); err != nil {
		return err
	}
	action, _, err := c.objectField(item, "action", true)
	if err != nil {
		return err
	}
	if err = c.unique(action, "type", "query", "queries", "sources", "url", "pattern"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(action, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "search":
		query, hasQuery, fieldErr := c.stringField(action, "query", false)
		if fieldErr != nil {
			return fieldErr
		}
		if hasQuery {
			if err = c.add(query, ScopeToolInput, TargetKindNaturalText, MutabilityDirect); err != nil {
				return err
			}
		}
		queries, hasQueries, fieldErr := c.field(action, "queries")
		if fieldErr != nil {
			return fieldErr
		}
		if hasQueries {
			if queries.kind != payload.KindArray {
				return c.shape(queries, "array", "web-search queries")
			}
			for _, query := range queries.array {
				if query.kind != payload.KindString {
					c.unsupported(query, "web-search query is not a string")
					continue
				}
				if err = c.add(query, ScopeToolInput, TargetKindNaturalText, MutabilityDirect); err != nil {
					return err
				}
			}
		}
		return walkResponsesWebSearchSources(c, action)
	case "open_page":
		return c.markOpaqueStringField(action, "url", false, true)
	case "find_in_page":
		if err = c.markOpaqueStringField(action, "url", true, false); err != nil {
			return err
		}
		pattern, _, fieldErr := c.stringField(action, "pattern", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(pattern, ScopeToolInput, TargetKindNaturalText, MutabilityDirect)
	default:
		c.unsupportedValue(action, "unknown web-search action type ", typeNode.token.Value)
		return nil
	}
}

func walkResponsesWebSearchSources(c *collector, action *node) error {
	sources, present, err := c.field(action, "sources")
	if err != nil || !present || sources.kind == payload.KindNull {
		return err
	}
	if sources.kind != payload.KindArray {
		return c.shape(sources, "array", "web-search sources")
	}
	for _, source := range sources.array {
		if source.kind != payload.KindObject {
			c.unsupported(source, "web-search source is not an object")
			continue
		}
		if err = c.unique(source, "type", "url"); err != nil {
			return err
		}
		typeNode, _, fieldErr := c.stringField(source, "type", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.markOpaque(typeNode); err != nil {
			return err
		}
		if typeNode.token.Value != "url" {
			c.unsupportedValue(source, "unknown web-search source type ", typeNode.token.Value)
			continue
		}
		url, _, fieldErr := c.stringField(source, "url", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.markOpaque(url); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesFunctionCall(c *collector, item *node) error {
	if err := c.unique(item, "type", "arguments", "call_id", "id", "name", "namespace", "caller", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "id", "name", "namespace", "status"); err != nil {
		return err
	}
	if err := walkResponsesCallerField(c, item); err != nil {
		return err
	}
	arguments, _, err := c.stringField(item, "arguments", true)
	if err != nil {
		return err
	}
	return c.add(arguments, ScopeToolInput, TargetKindEncodedJSON, MutabilityEncodedJSON)
}

func walkResponsesCallOutput(c *collector, item *node, custom bool) error {
	if err := c.unique(item, "type", "output", "call_id", "id", "caller", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "id", "status"); err != nil {
		return err
	}
	if err := walkResponsesCallerField(c, item); err != nil {
		return err
	}
	output, present, err := c.field(item, "output")
	if err != nil {
		return err
	}
	if !present {
		return c.missing(item, "output", "string or content list")
	}
	switch output.kind {
	case payload.KindString:
		return c.add(output, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
	case payload.KindArray:
		for _, block := range output.array {
			if err = walkResponsesInputContent(c, block, ScopeToolOutput, TargetKindToolOutput); err != nil {
				return err
			}
		}
		return nil
	default:
		label := "function-call output"
		if custom {
			label = "custom-tool-call output"
		}
		return c.shape(output, "string or array", label)
	}
}

func walkResponsesToolSearchCall(c *collector, item *node) error {
	if err := c.unique(item, "type", "arguments", "id", "call_id", "status", "execution"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "call_id", "status", "execution"); err != nil {
		return err
	}
	arguments, present, err := c.field(item, "arguments")
	if err != nil {
		return err
	}
	if !present {
		return c.missing(item, "arguments", "JSON value")
	}
	return c.walkStringValues(arguments, ScopeToolInput, TargetKindJSONValue)
}

func walkResponsesReasoningReplay(c *collector, item *node) error {
	if err := c.unique(item, "type", "id", "summary", "encrypted_content", "content", "status"); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(item, "id", true, false); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(item, "encrypted_content", false, true); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(item, "status", false, true); err != nil {
		return err
	}
	if err := walkResponsesReasoningParts(c, item, "summary", "summary_text", true); err != nil {
		return err
	}
	return walkResponsesReasoningParts(c, item, "content", "reasoning_text", false)
}

func walkResponsesReasoningParts(c *collector, item *node, key, expectedType string, required bool) error {
	parts, present, err := responsesFieldOfKind(c, item, key, payload.KindArray, required, !required)
	if err != nil || !present {
		return err
	}
	for _, part := range parts.array {
		if part.kind != payload.KindObject {
			return c.shape(part, "object", key+" element")
		}
		if err = c.unique(part, "type", "text"); err != nil {
			return err
		}
		partType, _, fieldErr := c.stringField(part, "type", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.markOpaque(partType); err != nil {
			return err
		}
		if partType.token.Value != expectedType {
			c.unsupportedValue(part, "unknown reasoning replay content type ", partType.token.Value)
			continue
		}
		text, _, fieldErr := c.stringField(part, "text", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.add(text, ScopeAssistant, TargetKindNaturalText, MutabilityDirect); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesCompactionReplay(c *collector, item *node) error {
	if err := c.unique(item, "type", "encrypted_content", "id"); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(item, "encrypted_content", true, false); err != nil {
		return err
	}
	return c.markOpaqueStringField(item, "id", false, true)
}

func walkResponsesImageGenerationReplay(c *collector, item *node) error {
	if err := c.unique(item, "type", "result", "id", "status"); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(item, "result", true, true); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(item, "id", true, false); err != nil {
		return err
	}
	return c.markOpaqueStringField(item, "status", true, false)
}

func walkResponsesCodeInterpreter(c *collector, item *node) error {
	if err := c.unique(item, "type", "code", "outputs", "id", "container_id", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "container_id", "status"); err != nil {
		return err
	}
	code, hasCode, err := c.field(item, "code")
	if err != nil {
		return err
	}
	if hasCode && code.kind != payload.KindNull {
		if code.kind != payload.KindString {
			return c.shape(code, "string or null", "code")
		}
		if err = c.add(code, ScopeToolInput, TargetKindCode, MutabilityDirect); err != nil {
			return err
		}
	}
	outputs, present, err := c.field(item, "outputs")
	if err != nil || !present || outputs.kind == payload.KindNull {
		return err
	}
	if outputs.kind != payload.KindArray {
		return c.shape(outputs, "array or null", "code-interpreter outputs")
	}
	for _, output := range outputs.array {
		if output.kind != payload.KindObject {
			c.unsupported(output, "code-interpreter output is not an object")
			continue
		}
		if err = c.unique(output, "type", "logs", "url"); err != nil {
			return err
		}
		typeNode, _, fieldErr := c.stringField(output, "type", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.markOpaque(typeNode); err != nil {
			return err
		}
		switch typeNode.token.Value {
		case "logs":
			logs, _, logsErr := c.stringField(output, "logs", true)
			if logsErr != nil {
				return logsErr
			}
			if err = c.add(logs, ScopeToolOutput, TargetKindExecutionOutput, MutabilityDirect); err != nil {
				return err
			}
		case "image":
			if err = c.markOpaqueStringField(output, "url", true, false); err != nil {
				return err
			}
		default:
			c.unsupportedValue(output, "unknown code-interpreter output type ", typeNode.token.Value)
		}
	}
	return nil
}

func walkResponsesLocalShell(c *collector, item *node) error {
	if err := c.unique(item, "type", "id", "action", "call_id", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "call_id", "status"); err != nil {
		return err
	}
	action, _, err := c.objectField(item, "action", true)
	if err != nil {
		return err
	}
	if err = c.unique(action, "type", "command", "env", "timeout_ms", "user", "working_directory"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(action, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	if typeNode.token.Value != "exec" {
		c.unsupportedValue(action, "unknown local-shell action type ", typeNode.token.Value)
		return nil
	}
	if err = markResponsesOpaqueStringFields(c, action, "user", "working_directory"); err != nil {
		return err
	}
	commands, _, err := c.arrayField(action, "command", true)
	if err != nil {
		return err
	}
	for _, command := range commands.array {
		if command.kind != payload.KindString {
			c.unsupported(command, "local-shell command is not a string")
			continue
		}
		if err = c.add(command, ScopeToolInput, TargetKindCode, MutabilityDirect); err != nil {
			return err
		}
	}
	env, present, err := c.field(action, "env")
	if err != nil {
		return err
	}
	if !present {
		return c.missing(action, "env", "object")
	}
	return walkResponsesStringMap(c, env, ScopeToolInput)
}

func walkResponsesStringMap(c *collector, value *node, scope Scope) error {
	if value.kind != payload.KindObject {
		return c.shape(value, "object", "string map")
	}
	for _, entry := range value.object {
		if entry.value.kind != payload.KindString {
			c.unsupported(entry.value, "string-map value is not a string")
			continue
		}
		if err := c.add(entry.value, scope, TargetKindJSONValue, MutabilityDirect); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesLocalShellOutput(c *collector, item *node) error {
	if err := c.unique(item, "type", "id", "output", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "status"); err != nil {
		return err
	}
	output, _, err := c.stringField(item, "output", true)
	if err != nil {
		return err
	}
	return c.add(output, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
}

func walkResponsesShellCall(c *collector, item *node) error {
	if err := c.unique(item, "type", "action", "call_id", "id", "caller", "environment", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "id", "status"); err != nil {
		return err
	}
	if err := walkResponsesCallerField(c, item); err != nil {
		return err
	}
	if err := walkResponsesEnvironmentField(c, item); err != nil {
		return err
	}
	action, _, err := c.objectField(item, "action", true)
	if err != nil {
		return err
	}
	if err = c.unique(action, "commands", "max_output_length", "timeout_ms"); err != nil {
		return err
	}
	commands, _, err := c.arrayField(action, "commands", true)
	if err != nil {
		return err
	}
	for _, command := range commands.array {
		if command.kind != payload.KindString {
			c.unsupported(command, "shell command is not a string")
			continue
		}
		if err = c.add(command, ScopeToolInput, TargetKindCode, MutabilityDirect); err != nil {
			return err
		}
	}
	return nil
}

func walkResponsesShellOutput(c *collector, item *node) error {
	if err := c.unique(item, "type", "call_id", "output", "id", "max_output_length", "caller", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "id", "status"); err != nil {
		return err
	}
	if err := walkResponsesCallerField(c, item); err != nil {
		return err
	}
	output, _, err := c.arrayField(item, "output", true)
	if err != nil {
		return err
	}
	for _, chunk := range output.array {
		if chunk.kind != payload.KindObject {
			c.unsupported(chunk, "shell output chunk is not an object")
			continue
		}
		if err = c.unique(chunk, "outcome", "stderr", "stdout"); err != nil {
			return err
		}
		outcome, _, fieldErr := c.objectField(chunk, "outcome", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.unique(outcome, "type", "exit_code"); err != nil {
			return err
		}
		outcomeType, _, fieldErr := c.stringField(outcome, "type", true)
		if fieldErr != nil {
			return fieldErr
		}
		if err = c.markOpaque(outcomeType); err != nil {
			return err
		}
		if outcomeType.token.Value != "timeout" && outcomeType.token.Value != "exit" {
			c.unsupportedValue(outcome, "unknown shell outcome type ", outcomeType.token.Value)
		}
		for _, key := range []string{"stdout", "stderr"} {
			text, _, textErr := c.stringField(chunk, key, true)
			if textErr != nil {
				return textErr
			}
			if err = c.add(text, ScopeToolOutput, TargetKindExecutionOutput, MutabilityDirect); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkResponsesApplyPatch(c *collector, item *node) error {
	if err := c.unique(item, "type", "call_id", "operation", "status", "id", "caller"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "status", "id"); err != nil {
		return err
	}
	if err := walkResponsesCallerField(c, item); err != nil {
		return err
	}
	operation, _, err := c.objectField(item, "operation", true)
	if err != nil {
		return err
	}
	if err = c.unique(operation, "type", "diff", "path"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(operation, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	if err = c.markOpaqueStringField(operation, "path", true, false); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "create_file", "update_file":
		diff, _, fieldErr := c.stringField(operation, "diff", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.add(diff, ScopeToolInput, TargetKindCode, MutabilityDirect)
	case "delete_file":
		return nil
	default:
		c.unsupportedValue(operation, "unknown apply-patch operation type ", typeNode.token.Value)
		return nil
	}
}

func walkResponsesApplyPatchOutput(c *collector, item *node) error {
	if err := c.unique(item, "type", "call_id", "status", "id", "output", "caller"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "status", "id"); err != nil {
		return err
	}
	if err := walkResponsesCallerField(c, item); err != nil {
		return err
	}
	output, present, err := c.field(item, "output")
	if err != nil || !present || output.kind == payload.KindNull {
		return err
	}
	if output.kind != payload.KindString {
		return c.shape(output, "string or null", "apply-patch output")
	}
	return c.add(output, ScopeToolOutput, TargetKindExecutionOutput, MutabilityDirect)
}

func walkResponsesMCPListTools(c *collector, item *node) error {
	if err := c.unique(item, "type", "id", "server_label", "tools", "error"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "server_label"); err != nil {
		return err
	}
	errorText, present, err := c.field(item, "error")
	if err != nil {
		return err
	}
	if present && errorText.kind != payload.KindNull {
		if errorText.kind != payload.KindString {
			return c.shape(errorText, "string or null", "MCP list-tools error")
		}
		if err = c.add(errorText, ScopeToolOutput, TargetKindToolOutput, MutabilityDirect); err != nil {
			return err
		}
	}
	tools, hasTools, err := c.field(item, "tools")
	if err != nil || !hasTools || tools.kind == payload.KindNull {
		return err
	}
	if tools.kind != payload.KindArray {
		return c.shape(tools, "array or null", "MCP listed tools")
	}
	for _, tool := range tools.array {
		if tool.kind != payload.KindObject {
			c.unsupported(tool, "MCP listed tool is not an object")
			continue
		}
		if err = c.unique(tool, "name", "description", "input_schema", "annotations"); err != nil {
			return err
		}
		if err = c.markOpaqueStringField(tool, "name", true, false); err != nil {
			return err
		}
		if err = c.addStringField(tool, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
			return err
		}
		inputSchema, present, fieldErr := c.field(tool, "input_schema")
		if fieldErr != nil {
			return fieldErr
		}
		if !present {
			return c.missing(tool, "input_schema", "JSON value")
		}
		if err = c.walkStringValues(inputSchema, ScopeSystem, TargetKindJSONValue); err != nil {
			return err
		}
		annotations, hasAnnotations, fieldErr := c.field(tool, "annotations")
		if fieldErr != nil {
			return fieldErr
		}
		if hasAnnotations {
			if err = c.walkStringValues(annotations, ScopeSystem, TargetKindJSONValue); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkResponsesMCPApprovalRequest(c *collector, item *node) error {
	if err := c.unique(item, "type", "arguments", "id", "name", "server_label"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "name", "server_label"); err != nil {
		return err
	}
	arguments, _, err := c.stringField(item, "arguments", true)
	if err != nil {
		return err
	}
	return c.add(arguments, ScopeToolInput, TargetKindEncodedJSON, MutabilityEncodedJSON)
}

func walkResponsesMCPApprovalResponse(c *collector, item *node) error {
	if err := c.unique(item, "type", "approval_request_id", "approve", "id", "reason"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "approval_request_id", "id"); err != nil {
		return err
	}
	reason, present, err := c.field(item, "reason")
	if err != nil || !present || reason.kind == payload.KindNull {
		return err
	}
	if reason.kind != payload.KindString {
		return c.shape(reason, "string or null", "MCP approval reason")
	}
	return c.add(reason, ScopeUser, TargetKindNaturalText, MutabilityDirect)
}

func walkResponsesMCPCall(c *collector, item *node) error {
	if err := c.unique(
		item,
		"type", "arguments", "error", "output", "id", "approval_request_id", "name", "server_label", "status",
	); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "approval_request_id", "name", "server_label", "status"); err != nil {
		return err
	}
	arguments, hasArguments, err := c.stringField(item, "arguments", false)
	if err != nil {
		return err
	}
	if hasArguments {
		if err = c.add(arguments, ScopeToolInput, TargetKindEncodedJSON, MutabilityEncodedJSON); err != nil {
			return err
		}
	}
	errorText, hasError, err := c.field(item, "error")
	if err != nil {
		return err
	}
	if hasError && errorText.kind != payload.KindNull {
		if errorText.kind != payload.KindString {
			return c.shape(errorText, "string or null", "MCP error")
		}
		if err = c.add(errorText, ScopeToolOutput, TargetKindToolOutput, MutabilityDirect); err != nil {
			return err
		}
	}
	output, hasOutput, err := c.field(item, "output")
	if err != nil || !hasOutput || output.kind == payload.KindNull {
		return err
	}
	if output.kind != payload.KindString {
		return c.shape(output, "string or null", "MCP output")
	}
	return c.add(output, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
}

func walkResponsesCustomCall(c *collector, item *node) error {
	if err := c.unique(item, "type", "input", "call_id", "id", "name", "namespace", "caller"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "call_id", "id", "name", "namespace"); err != nil {
		return err
	}
	if err := walkResponsesCallerField(c, item); err != nil {
		return err
	}
	input, _, err := c.stringField(item, "input", true)
	if err != nil {
		return err
	}
	return c.add(input, ScopeToolInput, TargetKindEncodedJSON, MutabilityJSONOrPlain)
}

func walkResponsesReferenceItem(c *collector, item *node) error {
	if err := c.unique(item, "type", "id"); err != nil {
		return err
	}
	id, _, err := c.stringField(item, "id", true)
	if err != nil {
		return err
	}
	return c.markOpaque(id)
}

func walkResponsesProgramOutput(c *collector, item *node) error {
	if err := c.unique(item, "type", "result", "id", "call_id", "status"); err != nil {
		return err
	}
	if err := markResponsesOpaqueStringFields(c, item, "id", "call_id", "status"); err != nil {
		return err
	}
	result, _, err := c.stringField(item, "result", true)
	if err != nil {
		return err
	}
	return c.add(result, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain)
}

func walkResponsesCompatibilityText(c *collector, item *node, itemType string) error {
	if err := c.unique(item, "type", "text"); err != nil {
		return err
	}
	text, _, err := c.stringField(item, "text", true)
	if err != nil {
		return err
	}
	scope := ScopeUser
	if itemType == "output_text" {
		scope = ScopeAssistant
	}
	return c.add(text, scope, TargetKindNaturalText, MutabilityDirect)
}

func walkResponsesCallerField(c *collector, object *node) error {
	caller, present, err := c.field(object, "caller")
	if err != nil || !present || caller.kind == payload.KindNull {
		return err
	}
	if caller.kind != payload.KindObject {
		return c.shape(caller, "object", "caller")
	}
	if err = c.unique(caller, "type", "caller_id"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(caller, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "direct":
		return nil
	case "program":
		callerID, _, fieldErr := c.stringField(caller, "caller_id", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.markOpaque(callerID)
	default:
		c.unsupportedValue(caller, "unknown caller type ", typeNode.token.Value)
		return nil
	}
}

func walkResponsesEnvironmentField(c *collector, object *node) error {
	environment, present, err := c.field(object, "environment")
	if err != nil || !present || environment.kind == payload.KindNull {
		return err
	}
	if environment.kind != payload.KindObject {
		return c.shape(environment, "object", "environment")
	}
	if err = c.unique(environment, "type", "container_id", "skills"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(environment, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	switch typeNode.token.Value {
	case "container_reference":
		containerID, _, fieldErr := c.stringField(environment, "container_id", true)
		if fieldErr != nil {
			return fieldErr
		}
		return c.markOpaque(containerID)
	case "local":
		skills, present, fieldErr := c.field(environment, "skills")
		if fieldErr != nil || !present || skills.kind == payload.KindNull {
			return fieldErr
		}
		if skills.kind != payload.KindArray {
			return c.shape(skills, "array", "local skills")
		}
		for _, skill := range skills.array {
			if skill.kind != payload.KindObject {
				c.unsupported(skill, "local skill is not an object")
				continue
			}
			if err = c.unique(skill, "name", "description", "path"); err != nil {
				return err
			}
			if err = markResponsesOpaqueStringFields(c, skill, "name", "path"); err != nil {
				return err
			}
			if err = c.addStringField(skill, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
				return err
			}
		}
		return nil
	default:
		c.unsupportedValue(environment, "unknown environment type ", typeNode.token.Value)
		return nil
	}
}
