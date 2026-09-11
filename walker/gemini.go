package walker

import (
	"fmt"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

func walkGemini(c *collector, root *node) error {
	if err := c.unique(root, "systemInstruction", "system_instruction", "contents"); err != nil {
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
	return nil
}

func walkGeminiSystem(c *collector, system *node) error {
	if system.kind != payload.KindObject {
		return c.shape(system, "object", "system instruction")
	}
	if err := c.unique(system, "parts", "role", "id", "name"); err != nil {
		return err
	}
	if err := c.markFields(system, "role", "id", "name"); err != nil {
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
		if err = c.unique(part, "text", "thought", "thoughtSignature", "inlineData", "fileData", "id", "name"); err != nil {
			return err
		}
		if err = c.markFields(part, "thoughtSignature", "inlineData", "fileData", "id", "name"); err != nil {
			return err
		}
		text, ok, textErr := c.stringField(part, "text", false)
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
		if ok {
			if hasSignature || hasThought && thought.boolean {
				if err = c.markOpaque(text); err != nil {
					return err
				}
			} else if err = c.add(text, ScopeSystem, TargetKindNaturalText, MutabilityDirect); err != nil {
				return err
			}
			continue
		}
		_, hasInline, inlineErr := c.field(part, "inlineData")
		if inlineErr != nil {
			return inlineErr
		}
		_, hasFile, fileErr := c.field(part, "fileData")
		if fileErr != nil {
			return fileErr
		}
		if !hasInline && !hasFile {
			c.unsupported(part, "system part has no text")
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
	if err := c.markFields(content, "id", "name"); err != nil {
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
			c.unsupported(role, fmt.Sprintf("unknown Gemini role %q", role.token.Value))
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

func walkGeminiPart(c *collector, part *node, naturalScope Scope, roleOK bool) error {
	if part.kind != payload.KindObject {
		c.unsupported(part, "parts element is not an object")
		return nil
	}
	controlKeys := []string{
		"text", "thought", "thoughtSignature", "functionCall", "functionResponse",
		"executableCode", "codeExecutionResult", "inlineData", "fileData", "name", "id", "call_id", "mimeType",
	}
	if err := c.unique(part, controlKeys...); err != nil {
		return err
	}
	if err := c.markFields(part, "thoughtSignature", "inlineData", "fileData", "name", "id", "call_id", "mimeType"); err != nil {
		return err
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
	_, hasInlineData, err := c.field(part, "inlineData")
	if err != nil {
		return err
	}
	_, hasFileData, err := c.field(part, "fileData")
	if err != nil {
		return err
	}

	recognized := hasThought || hasSignature || hasInlineData || hasFileData
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
		if err = c.unique(functionCall, "args", "name", "id", "call_id"); err != nil {
			return err
		}
		if err = c.markFields(functionCall, "name", "id", "call_id"); err != nil {
			return err
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
		if err = c.unique(functionResponse, "response", "name", "id", "call_id"); err != nil {
			return err
		}
		if err = c.markFields(functionResponse, "name", "id", "call_id"); err != nil {
			return err
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
		if err = c.markFields(executableCode, "language", "id", "name"); err != nil {
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
		if err = c.markFields(execution, "outcome", "id", "name"); err != nil {
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
