package walker

import "github.com/ahoo/cpa-plugin-privacyfilter/payload"

var geminiRootControlFields = []string{
	"model", "toolConfig", "safetySettings", "generationConfig", "cachedContent",
	"serviceTier", "store", "labels", "tool_config", "safety_settings", "generation_config",
	"cached_content", "service_tier",
}

func walkGemini(c *collector, root *node) error {
	if err := c.unique(root, "systemInstruction", "system_instruction", "contents", "tools"); err != nil {
		return err
	}
	if err := c.markFields(root, geminiRootControlFields...); err != nil {
		return err
	}
	system, _, hasSystem, err := c.oneOf(root, "systemInstruction", "system_instruction")
	if err != nil {
		return err
	}
	if hasSystem {
		if err = walkGeminiSystem(c, system); err != nil {
			return err
		}
	}
	contents, _, err := c.arrayField(root, "contents", true)
	if err != nil {
		return err
	}
	for _, content := range contents.array {
		if err = walkGeminiContent(c, content); err != nil {
			return err
		}
	}
	return walkGeminiToolDefinitions(c, root)
}

func markGeminiOpaqueStringFields(c *collector, object *node, keys ...string) error {
	for _, key := range keys {
		if err := c.markOpaqueStringField(object, key, false, true); err != nil {
			return err
		}
	}
	return nil
}

func walkGeminiToolDefinitions(c *collector, root *node) error {
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
		if err = c.unique(
			tool,
			"functionDeclarations", "function_declarations", "googleSearch", "codeExecution", "urlContext",
		); err != nil {
			return err
		}
		declarations, _, hasDeclarations, fieldErr := c.oneOf(tool, "functionDeclarations", "function_declarations")
		if fieldErr != nil {
			return fieldErr
		}
		if hasDeclarations {
			if err = walkGeminiFunctionDeclarations(c, declarations); err != nil {
				return err
			}
		}
		googleSearch, hasGoogleSearch, fieldErr := c.field(tool, "googleSearch")
		if fieldErr != nil {
			return fieldErr
		}
		if hasGoogleSearch {
			if err = walkGeminiGoogleSearch(c, googleSearch); err != nil {
				return err
			}
		}
		for _, key := range []string{"codeExecution", "urlContext"} {
			marker, hasMarker, markerErr := c.field(tool, key)
			if markerErr != nil {
				return markerErr
			}
			if hasMarker {
				if err = walkGeminiMarkerTool(c, marker, key); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func walkGeminiFunctionDeclarations(c *collector, declarations *node) error {
	if declarations.kind != payload.KindArray {
		return c.shape(declarations, "array", "function declarations")
	}
	for _, declaration := range declarations.array {
		if declaration.kind != payload.KindObject {
			c.unsupported(declaration, "function declaration is not an object")
			continue
		}
		if err := walkGeminiFunctionDeclaration(c, declaration); err != nil {
			return err
		}
	}
	return nil
}

func walkGeminiFunctionDeclaration(c *collector, declaration *node) error {
	if err := c.unique(
		declaration,
		"name", "description", "parameters", "parametersJsonSchema", "response", "responseJsonSchema", "behavior",
	); err != nil {
		return err
	}
	name, _, err := c.stringField(declaration, "name", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(name); err != nil {
		return err
	}
	if err = c.addStringField(declaration, "description", false, true, ScopeSystem, TargetKindNaturalText); err != nil {
		return err
	}
	if err = c.markOpaqueStringField(declaration, "behavior", false, true); err != nil {
		return err
	}
	for _, pair := range [][2]string{
		{"parameters", "parametersJsonSchema"},
		{"response", "responseJsonSchema"},
	} {
		first, hasFirst, fieldErr := c.field(declaration, pair[0])
		if fieldErr != nil {
			return fieldErr
		}
		second, hasSecond, fieldErr := c.field(declaration, pair[1])
		if fieldErr != nil {
			return fieldErr
		}
		if hasFirst && hasSecond {
			return &AmbiguityError{Protocol: c.protocol, Path: declaration.path.Clone(), Keys: []string{pair[0], pair[1]}}
		}
		for _, schema := range []*node{first, second} {
			if schema == nil || schema.kind == payload.KindNull {
				continue
			}
			if schema.kind != payload.KindObject {
				return c.shape(schema, "object or null", "function schema")
			}
			if err = c.walkStringValues(schema, ScopeSystem, TargetKindJSONValue); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkGeminiGoogleSearch(c *collector, search *node) error {
	if search.kind != payload.KindObject {
		return c.shape(search, "object", "googleSearch")
	}
	if err := c.unique(search, "searchTypes", "blockingConfidence", "excludeDomains", "timeRangeFilter"); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(search, "blockingConfidence", false, true); err != nil {
		return err
	}
	searchTypes, hasSearchTypes, err := c.field(search, "searchTypes")
	if err != nil {
		return err
	}
	if hasSearchTypes && searchTypes.kind != payload.KindNull {
		if searchTypes.kind != payload.KindObject {
			return c.shape(searchTypes, "object or null", "googleSearch searchTypes")
		}
		if err = c.unique(searchTypes, "webSearch", "imageSearch"); err != nil {
			return err
		}
		for _, key := range []string{"webSearch", "imageSearch"} {
			marker, present, fieldErr := c.field(searchTypes, key)
			if fieldErr != nil {
				return fieldErr
			}
			if present {
				if err = walkGeminiMarkerTool(c, marker, "googleSearch "+key); err != nil {
					return err
				}
			}
		}
	}
	domains, hasDomains, err := c.field(search, "excludeDomains")
	if err != nil {
		return err
	}
	if hasDomains && domains.kind != payload.KindNull {
		if domains.kind != payload.KindArray {
			return c.shape(domains, "array or null", "googleSearch excludeDomains")
		}
		for _, domain := range domains.array {
			if domain.kind != payload.KindString {
				return c.shape(domain, "string", "googleSearch excluded domain")
			}
			if err = c.markOpaque(domain); err != nil {
				return err
			}
		}
	}
	timeRange, hasTimeRange, err := c.field(search, "timeRangeFilter")
	if err != nil {
		return err
	}
	if hasTimeRange && timeRange.kind != payload.KindNull {
		if timeRange.kind != payload.KindObject {
			return c.shape(timeRange, "object or null", "googleSearch timeRangeFilter")
		}
		if err = c.unique(timeRange, "startTime", "endTime"); err != nil {
			return err
		}
		for _, key := range []string{"startTime", "endTime"} {
			if err = c.markOpaqueStringField(timeRange, key, false, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkGeminiMarkerTool(c *collector, marker *node, detail string) error {
	if marker.kind != payload.KindObject {
		return c.shape(marker, "object", detail)
	}
	return nil
}

func walkGeminiMediaFields(c *collector, part *node, scope Scope) (bool, error) {
	inlineData, _, hasInlineData, err := c.oneOf(part, "inlineData", "inline_data")
	if err != nil {
		return false, err
	}
	fileData, _, hasFileData, err := c.oneOf(part, "fileData", "file_data")
	if err != nil {
		return false, err
	}
	if hasInlineData {
		if err = walkGeminiInlineData(c, inlineData, scope); err != nil {
			return false, err
		}
	}
	if hasFileData {
		if err = walkGeminiFileData(c, fileData, scope); err != nil {
			return false, err
		}
	}
	return hasInlineData || hasFileData, nil
}

func walkGeminiInlineData(c *collector, data *node, scope Scope) error {
	if data.kind != payload.KindObject {
		return c.shape(data, "object", "inlineData")
	}
	if err := c.unique(data, "data", "displayName", "mimeType", "mime_type"); err != nil {
		return err
	}
	encoded, _, err := c.stringField(data, "data", true)
	if err != nil {
		return err
	}
	if err = c.markOpaque(encoded); err != nil {
		return err
	}
	if err = markGeminiMediaMIME(c, data); err != nil {
		return err
	}
	return addGeminiDisplayName(c, data, scope)
}

func walkGeminiFileData(c *collector, data *node, scope Scope) error {
	if data.kind != payload.KindObject {
		return c.shape(data, "object", "fileData")
	}
	if err := c.unique(data, "displayName", "fileUri", "file_uri", "mimeType", "mime_type"); err != nil {
		return err
	}
	uri, _, hasURI, err := c.oneOf(data, "fileUri", "file_uri")
	if err != nil {
		return err
	}
	if !hasURI {
		return c.missing(data, "fileUri", "string")
	}
	if uri.kind != payload.KindString {
		return c.shape(uri, "string", "file URI")
	}
	if err = c.markOpaque(uri); err != nil {
		return err
	}
	if err = markGeminiMediaMIME(c, data); err != nil {
		return err
	}
	return addGeminiDisplayName(c, data, scope)
}

func markGeminiMediaMIME(c *collector, data *node) error {
	mimeType, _, present, err := c.oneOf(data, "mimeType", "mime_type")
	if err != nil || !present {
		return err
	}
	if mimeType.kind != payload.KindString {
		return c.shape(mimeType, "string", "media MIME type")
	}
	return c.markOpaque(mimeType)
}

func addGeminiDisplayName(c *collector, data *node, scope Scope) error {
	displayName, present, err := c.field(data, "displayName")
	if err != nil || !present || displayName.kind == payload.KindNull {
		return err
	}
	if displayName.kind != payload.KindString {
		return c.shape(displayName, "string or null", "media displayName")
	}
	return c.add(displayName, scope, TargetKindNaturalText, MutabilityDirect)
}

func walkGeminiSystem(c *collector, system *node) error {
	if system.kind != payload.KindObject {
		return c.shape(system, "object", "system instruction")
	}
	if err := c.unique(system, "parts", "role", "id", "name"); err != nil {
		return err
	}
	if err := markGeminiOpaqueStringFields(c, system, "role", "id", "name"); err != nil {
		return err
	}
	parts, _, err := c.arrayField(system, "parts", true)
	if err != nil {
		return err
	}
	for _, part := range parts.array {
		if part.kind != payload.KindObject {
			c.unsupported(part, "system parts element is not an object")
			continue
		}
		if err = c.unique(
			part,
			"text", "thought", "thoughtSignature", "inlineData", "inline_data", "fileData", "file_data", "id", "name",
		); err != nil {
			return err
		}
		if err = markGeminiOpaqueStringFields(c, part, "thoughtSignature", "id", "name"); err != nil {
			return err
		}
		text, hasText, textErr := c.stringField(part, "text", false)
		if textErr != nil {
			return textErr
		}
		thought, hasThought, thoughtErr := c.field(part, "thought")
		if thoughtErr != nil {
			return thoughtErr
		}
		if hasThought && thought.kind != payload.KindBoolean {
			return c.shape(thought, "boolean", "thought")
		}
		_, hasSignature, signatureErr := c.field(part, "thoughtSignature")
		if signatureErr != nil {
			return signatureErr
		}
		if hasText {
			if hasSignature || hasThought && thought.boolean {
				if err = c.markOpaque(text); err != nil {
					return err
				}
			} else if err = c.add(text, ScopeSystem, TargetKindNaturalText, MutabilityDirect); err != nil {
				return err
			}
		}
		hasMedia, mediaErr := walkGeminiMediaFields(c, part, ScopeSystem)
		if mediaErr != nil {
			return mediaErr
		}
		if !hasText && !hasMedia {
			c.unsupported(part, "system part has no text or media")
		}
	}
	return nil
}

func walkGeminiContent(c *collector, content *node) error {
	if content.kind != payload.KindObject {
		return c.shape(content, "object", "contents element")
	}
	if err := c.unique(content, "role", "parts", "id", "name"); err != nil {
		return err
	}
	if err := markGeminiOpaqueStringFields(c, content, "id", "name"); err != nil {
		return err
	}
	scope := ScopeUser
	role, hasRole, err := c.stringField(content, "role", false)
	if err != nil {
		return err
	}
	roleOK := true
	if hasRole {
		if err = c.markOpaque(role); err != nil {
			return err
		}
		switch role.token.Value {
		case "user":
			scope = ScopeUser
		case "model":
			scope = ScopeAssistant
		default:
			roleOK = false
			c.unsupportedValue(role, "unknown Gemini role ", role.token.Value)
		}
	}
	parts, _, err := c.arrayField(content, "parts", true)
	if err != nil {
		return err
	}
	for _, part := range parts.array {
		if err = walkGeminiPart(c, part, scope, roleOK); err != nil {
			return err
		}
	}
	return nil
}

func walkGeminiPartMediaControls(c *collector, part *node) error {
	mediaResolution, present, err := c.field(part, "mediaResolution")
	if err != nil {
		return err
	}
	if present && mediaResolution.kind != payload.KindNull {
		if mediaResolution.kind != payload.KindObject {
			return c.shape(mediaResolution, "object or null", "mediaResolution")
		}
		if err = c.unique(mediaResolution, "level", "numTokens"); err != nil {
			return err
		}
		if err = c.markOpaqueStringField(mediaResolution, "level", false, true); err != nil {
			return err
		}
		numTokens, hasNumTokens, fieldErr := c.field(mediaResolution, "numTokens")
		if fieldErr != nil {
			return fieldErr
		}
		if hasNumTokens && numTokens.kind != payload.KindNumber && numTokens.kind != payload.KindNull {
			return c.shape(numTokens, "number or null", "mediaResolution numTokens")
		}
	}

	videoMetadata, present, err := c.field(part, "videoMetadata")
	if err != nil {
		return err
	}
	if !present || videoMetadata.kind == payload.KindNull {
		return nil
	}
	if videoMetadata.kind != payload.KindObject {
		return c.shape(videoMetadata, "object or null", "videoMetadata")
	}
	if err = c.unique(videoMetadata, "startOffset", "endOffset", "fps"); err != nil {
		return err
	}
	if err = markGeminiOpaqueStringFields(c, videoMetadata, "startOffset", "endOffset"); err != nil {
		return err
	}
	fps, hasFPS, err := c.field(videoMetadata, "fps")
	if err != nil {
		return err
	}
	if hasFPS && fps.kind != payload.KindNumber && fps.kind != payload.KindNull {
		return c.shape(fps, "number or null", "videoMetadata fps")
	}
	return nil
}

func walkGeminiPart(c *collector, part *node, naturalScope Scope, roleOK bool) error {
	if part.kind != payload.KindObject {
		c.unsupported(part, "parts element is not an object")
		return nil
	}
	controlKeys := []string{
		"text", "thought", "thoughtSignature", "functionCall", "functionResponse",
		"executableCode", "codeExecutionResult", "inlineData", "inline_data", "fileData", "file_data", "mediaResolution",
		"videoMetadata", "mediaProcessing", "partMetadata", "audioTranscription", "name", "id", "call_id", "mimeType",
	}
	if err := c.unique(part, controlKeys...); err != nil {
		return err
	}
	if err := c.markOpaqueStringField(part, "thoughtSignature", false, true); err != nil {
		return err
	}
	if err := walkGeminiPartMediaControls(c, part); err != nil {
		return err
	}
	partMetadata, hasPartMetadata, err := c.field(part, "partMetadata")
	if err != nil {
		return err
	}
	if hasPartMetadata {
		if partMetadata.kind != payload.KindObject {
			return c.shape(partMetadata, "object", "partMetadata")
		}
		if err = c.markOpaque(partMetadata); err != nil {
			return err
		}
	}

	thought := false
	thoughtNode, hasThought, err := c.field(part, "thought")
	if err != nil {
		return err
	}
	if hasThought {
		if thoughtNode.kind != payload.KindBoolean {
			return c.shape(thoughtNode, "boolean", "thought")
		}
		thought = thoughtNode.boolean
	}
	_, hasSignature, err := c.field(part, "thoughtSignature")
	if err != nil {
		return err
	}
	hasMedia, err := walkGeminiMediaFields(c, part, naturalScope)
	if err != nil {
		return err
	}

	recognized := hasThought || hasSignature || hasMedia
	text, hasText, err := c.stringField(part, "text", false)
	if err != nil {
		return err
	}
	if hasText {
		recognized = true
		if thought || hasSignature || !roleOK {
			if err = c.markOpaque(text); err != nil {
				return err
			}
		} else if err = c.add(text, naturalScope, TargetKindNaturalText, MutabilityDirect); err != nil {
			return err
		}
	}

	functionCall, hasFunctionCall, err := c.field(part, "functionCall")
	if err != nil {
		return err
	}
	if hasFunctionCall {
		recognized = true
		if functionCall.kind != payload.KindObject {
			return c.shape(functionCall, "object", "functionCall")
		}
		if err = c.unique(functionCall, "args", "partialArgs", "name", "id", "call_id", "willContinue"); err != nil {
			return err
		}
		if err = markGeminiOpaqueStringFields(c, functionCall, "name", "id", "call_id"); err != nil {
			return err
		}
		willContinue, hasWillContinue, fieldErr := c.field(functionCall, "willContinue")
		if fieldErr != nil {
			return fieldErr
		}
		if hasWillContinue && willContinue.kind != payload.KindBoolean {
			return c.shape(willContinue, "boolean", "functionCall willContinue")
		}
		args, ok, fieldErr := c.field(functionCall, "args")
		if fieldErr != nil {
			return fieldErr
		}
		if ok {
			if err = c.walkStringValues(args, ScopeToolInput, TargetKindJSONValue); err != nil {
				return err
			}
		}
		partialArgs, hasPartialArgs, fieldErr := c.field(functionCall, "partialArgs")
		if fieldErr != nil {
			return fieldErr
		}
		if hasPartialArgs {
			if err = walkGeminiPartialArgs(c, partialArgs); err != nil {
				return err
			}
		}
	}

	functionResponse, hasFunctionResponse, err := c.field(part, "functionResponse")
	if err != nil {
		return err
	}
	if hasFunctionResponse {
		recognized = true
		if functionResponse.kind != payload.KindObject {
			return c.shape(functionResponse, "object", "functionResponse")
		}
		if err = c.unique(functionResponse, "response", "parts", "name", "id", "call_id", "willContinue", "scheduling"); err != nil {
			return err
		}
		if err = markGeminiOpaqueStringFields(c, functionResponse, "name", "id", "call_id", "scheduling"); err != nil {
			return err
		}
		willContinue, hasWillContinue, fieldErr := c.field(functionResponse, "willContinue")
		if fieldErr != nil {
			return fieldErr
		}
		if hasWillContinue && willContinue.kind != payload.KindBoolean {
			return c.shape(willContinue, "boolean", "functionResponse willContinue")
		}
		response, ok, fieldErr := c.field(functionResponse, "response")
		if fieldErr != nil {
			return fieldErr
		}
		if ok {
			if err = c.walkStringValues(response, ScopeToolOutput, TargetKindJSONValue); err != nil {
				return err
			}
		}
		parts, hasParts, fieldErr := c.field(functionResponse, "parts")
		if fieldErr != nil {
			return fieldErr
		}
		if hasParts {
			if parts.kind != payload.KindArray {
				return c.shape(parts, "array", "functionResponse parts")
			}
			for _, responsePart := range parts.array {
				if err = walkGeminiPart(c, responsePart, ScopeToolOutput, true); err != nil {
					return err
				}
			}
		}
	}

	executableCode, hasExecutableCode, err := c.field(part, "executableCode")
	if err != nil {
		return err
	}
	if hasExecutableCode {
		recognized = true
		if executableCode.kind != payload.KindObject {
			return c.shape(executableCode, "object", "executableCode")
		}
		if err = c.unique(executableCode, "code", "language", "id", "name"); err != nil {
			return err
		}
		if err = markGeminiOpaqueStringFields(c, executableCode, "language", "id"); err != nil {
			return err
		}
		code, ok, fieldErr := c.stringField(executableCode, "code", false)
		if fieldErr != nil {
			return fieldErr
		}
		if ok {
			if err = c.add(code, naturalScope, TargetKindCode, MutabilityDirect); err != nil {
				return err
			}
		}
	}

	execution, hasExecution, err := c.field(part, "codeExecutionResult")
	if err != nil {
		return err
	}
	if hasExecution {
		recognized = true
		if execution.kind != payload.KindObject {
			return c.shape(execution, "object", "codeExecutionResult")
		}
		if err = c.unique(execution, "output", "outcome", "id", "name"); err != nil {
			return err
		}
		if err = markGeminiOpaqueStringFields(c, execution, "outcome", "id"); err != nil {
			return err
		}
		output, ok, fieldErr := c.stringField(execution, "output", false)
		if fieldErr != nil {
			return fieldErr
		}
		if ok {
			if err = c.add(output, ScopeToolOutput, TargetKindExecutionOutput, MutabilityDirect); err != nil {
				return err
			}
		}
	}

	if !recognized {
		c.unsupported(part, "unknown Gemini part shape")
	}
	return nil
}

func walkGeminiPartialArgs(c *collector, partialArgs *node) error {
	if partialArgs.kind != payload.KindArray {
		return c.shape(partialArgs, "array", "partialArgs")
	}
	for _, partial := range partialArgs.array {
		if partial.kind != payload.KindObject {
			c.unsupported(partial, "partialArgs element is not an object")
			continue
		}
		if err := c.unique(partial, "boolValue", "jsonPath", "nullValue", "numberValue", "stringValue", "willContinue"); err != nil {
			return err
		}
		if err := markGeminiOpaqueStringFields(c, partial, "jsonPath", "nullValue"); err != nil {
			return err
		}
		value, present, err := c.stringField(partial, "stringValue", false)
		if err != nil {
			return err
		}
		if present {
			if err = c.add(value, ScopeToolInput, TargetKindJSONValue, MutabilityDirect); err != nil {
				return err
			}
		}
	}
	return nil
}
