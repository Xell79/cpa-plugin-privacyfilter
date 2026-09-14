package walker

import "github.com/ahoo/cpa-plugin-privacyfilter/payload"

var openAIRootControlFields = []string{
	"audio", "frequency_penalty", "function_call", "logit_bias", "logprobs",
	"max_completion_tokens", "max_tokens", "metadata", "modalities", "moderation", "n",
	"parallel_tool_calls", "presence_penalty", "prompt_cache_key", "prompt_cache_options",
	"prompt_cache_retention", "reasoning_effort", "response_format", "safety_identifier", "seed",
	"service_tier", "stop", "store", "stream", "stream_options", "temperature", "tool_choice",
	"top_logprobs", "top_p", "user", "verbosity", "web_search_options",
}

func walkOpenAI(c *collector, root *node) error {
	if err := c.unique(root, "messages", "prediction", "tools", "functions"); err != nil {
		return err
	}
	if err := c.markFields(root, openAIRootControlFields...); err != nil {
		return err
	}
	messages, _, err := c.arrayField(root, "messages", true)
	if err != nil {
		return err
	}
	for _, message := range messages.array {
		if err = walkOpenAIMessage(c, message); err != nil {
			return err
		}
	}
	prediction, hasPrediction, err := c.field(root, "prediction")
	if err != nil {
		return err
	}
	if hasPrediction {
		if err = walkOpenAIPrediction(c, prediction); err != nil {
			return err
		}
	}
	return walkOpenAIToolDefinitions(c, root)
}

func walkOpenAIToolDefinitions(c *collector, root *node) error {
	tools, hasTools, err := c.field(root, "tools")
	if err != nil {
		return err
	}
	if hasTools {
		if tools.kind != payload.KindArray {
			return c.shape(tools, "array", "tools")
		}
		for _, tool := range tools.array {
			if tool.kind != payload.KindObject {
				c.unsupported(tool, "tool definition is not an object")
				continue
			}
			if err = c.unique(tool, "type", "function"); err != nil {
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
			function, _, fieldErr := c.objectField(tool, "function", true)
			if fieldErr != nil {
				return fieldErr
			}
			if err = walkOpenAIFunctionDefinition(c, function); err != nil {
				return err
			}
		}
	}
	functions, hasFunctions, err := c.field(root, "functions")
	if err != nil || !hasFunctions {
		return err
	}
	if functions.kind != payload.KindArray {
		return c.shape(functions, "array", "functions")
	}
	for _, function := range functions.array {
		if function.kind != payload.KindObject {
			c.unsupported(function, "legacy function definition is not an object")
			continue
		}
		if err = walkOpenAIFunctionDefinition(c, function); err != nil {
			return err
		}
	}
	return nil
}

func walkOpenAIFunctionDefinition(c *collector, function *node) error {
	if err := c.unique(function, "name", "description", "parameters", "strict"); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(function, "name", true, false); err != nil {
		return err
	}
	if err := c.addStringField(function, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
		return err
	}
	return c.walkStringObjectField(function, "parameters", false, true, ScopeSystem)
}

func walkOpenAIPrediction(c *collector, prediction *node) error {
	if prediction.kind != payload.KindObject {
		return c.shape(prediction, "object", "prediction")
	}
	if err := c.unique(prediction, "type", "content"); err != nil {
		return err
	}
	typeNode, _, err := c.stringField(prediction, "type", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(typeNode); err != nil {
		return err
	}
	if typeNode.token.Value != "content" {
		c.unsupportedValue(prediction, "unknown prediction type ", typeNode.token.Value)
		return nil
	}
	content, present, err := c.field(prediction, "content")
	if err != nil {
		return err
	}
	if !present {
		return c.missing(prediction, "content", "string or array")
	}
	return c.walkTypedTextContent(content, ScopeAssistant)
}

func walkOpenAIMessage(c *collector, message *node) error {
	if message.kind != payload.KindObject {
		return c.shape(message, "object", "messages element")
	}
	if err := c.unique(message, "role", "content", "tool_calls", "function_call", "name", "id", "call_id", "tool_call_id", "refusal", "audio"); err != nil {
		return err
	}
	for _, key := range []string{"name", "id", "call_id", "tool_call_id"} {
		if err := c.markOpaqueStringField(message, key, false, true); err != nil {
			return err
		}
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
	}

	content, hasContent, err := c.field(message, "content")
	if err != nil {
		return err
	}
	if hasContent && roleOK {
		if scope == ScopeToolOutput && content.kind == payload.KindString {
			if err = c.add(content, ScopeToolOutput, TargetKindToolOutput, MutabilityJSONOrPlain); err != nil {
				return err
			}
		} else if err = c.walkTypedTextContent(content, scope); err != nil {
			return err
		}
	}

	refusal, hasRefusal, err := c.field(message, "refusal")
	if err != nil {
		return err
	}
	if hasRefusal && refusal.kind != payload.KindNull {
		if refusal.kind != payload.KindString {
			return c.shape(refusal, "string or null", "refusal")
		}
		if roleOK && scope == ScopeAssistant {
			if err = c.add(refusal, ScopeAssistant, TargetKindNaturalText, MutabilityDirect); err != nil {
				return err
			}
		} else {
			c.unsupported(refusal, "refusal text outside an assistant message")
		}
	}

	audio, hasAudio, err := c.field(message, "audio")
	if err != nil {
		return err
	}
	if hasAudio && audio.kind != payload.KindNull {
		if audio.kind != payload.KindObject {
			return c.shape(audio, "object or null", "audio")
		}
		if err = c.markOpaqueStringField(audio, "id", false, true); err != nil {
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
	for _, key := range []string{"id", "name", "call_id"} {
		if err := c.markOpaqueStringField(call, key, false, true); err != nil {
			return err
		}
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
			c.unsupportedValue(call, "unknown tool call type ", callType.token.Value)
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
	for _, key := range []string{"name", "id", "call_id"} {
		if err := c.markOpaqueStringField(function, key, false, true); err != nil {
			return err
		}
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
