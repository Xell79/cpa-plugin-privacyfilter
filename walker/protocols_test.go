package walker_test

import (
	"strings"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
)

func TestProtocolFixtures(t *testing.T) {
	t.Run("openai chat all rounds and tools", func(t *testing.T) {
		const body = `{
  "model": "gpt-test",
  "messages": [
    {"role":"system","content":"system secret"},
    {"role":"user","content":[
      {"type":"text","text":"first user"},
      {"type":"image_url","image_url":{"url":"https://example.invalid/private.png"}},
      {"type":"input_text","text":"second user"}
    ]},
    {"role":"assistant","content":[{"type":"output_text","text":"assistant history"}],
      "tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"not-json-yet"}}],
      "function_call":{"name":"legacy","arguments":"{\"customer\":\"Bob\"}"}},
    {"role":"tool","name":"lookup","tool_call_id":"call_1","content":"tool output"},
    {"role":"user","content":"last user"}
  ],
  "tools":[{"type":"function","function":{"name":"schema-name","description":"schema description","parameters":{"type":"object","properties":{"x":{"description":"schema nested"}}}}}],
  "metadata":{"note":"metadata secret"}
}`
		result := mustWalk(t, "openai", body)
		checkTargets(t, result, []wantTarget{
			{`$["messages"][0]["content"]`, "system secret", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][1]["content"][0]["text"]`, "first user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][1]["content"][2]["text"]`, "second user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][2]["content"][0]["text"]`, "assistant history", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][2]["tool_calls"][0]["function"]["arguments"]`, "not-json-yet", walker.ScopeToolInput, walker.TargetKindEncodedJSON, walker.MutabilityEncodedJSON},
			{`$["messages"][2]["function_call"]["arguments"]`, `{"customer":"Bob"}`, walker.ScopeToolInput, walker.TargetKindEncodedJSON, walker.MutabilityEncodedJSON},
			{`$["messages"][3]["content"]`, "tool output", walker.ScopeToolOutput, walker.TargetKindToolOutput, walker.MutabilityJSONOrPlain},
			{`$["messages"][4]["content"]`, "last user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["function"]["description"]`, "schema description", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["function"]["parameters"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["tools"][0]["function"]["parameters"]["properties"]["x"]["description"]`, "schema nested", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		})
		assertValuesNotTargeted(t, result,
			"gpt-test", "system", "user", "assistant", "tool", "text", "input_text", "output_text",
			"https://example.invalid/private.png", "call_1", "lookup", "legacy", "schema-name",
			"metadata secret")
		if result.Skipped <= len(result.Targets) || result.Opaque == 0 || result.UnsupportedCount != 0 {
			t.Fatalf("counters = skipped %d opaque %d unsupported %d", result.Skipped, result.Opaque, result.UnsupportedCount)
		}
	})

	t.Run("openai responses system messages tools and prompt variables", func(t *testing.T) {
		const body = `{
  "model":"response-model",
  "instructions":"response system",
  "input":[
    {"type":"message","role":"user","content":"round one"},
    {"type":"message","role":"assistant","content":[{"type":"output_text","text":"round two"}]},
    {"role":"tool","content":[{"type":"text","text":"history tool text"}]},
    {"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{not valid json"},
    {"type":"function_call_output","call_id":"call_1","output":"{\"answer\":\"Alice\"}"},
    {"type":"custom_tool_call_output","call_id":"call_2","output":"plain Bob"},
    {"type":"input_text","text":"direct input text"},
    {"type":"reasoning","id":"rs_1","encrypted_content":"opaque encrypted","summary":[{"type":"summary_text","text":"opaque thought"}]}
  ],
  "prompt":{"id":"pmpt_1","variables":{"a.b":"Carol","x/y":{"type":"input_text","text":"Dave"},"quote\"key":"Eve"}},
  "max_output_tokens":900719925474099312345,
  "tools":[{"type":"function","name":"schema function","description":"schema prose","parameters":{"type":"object","description":"schema nested"}}]
}`
		result := mustWalk(t, "openai-response", body)
		checkTargets(t, result, []wantTarget{
			{`$["instructions"]`, "response system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][0]["content"]`, "round one", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][1]["content"][0]["text"]`, "round two", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][2]["content"][0]["text"]`, "history tool text", walker.ScopeToolOutput, walker.TargetKindToolOutput, walker.MutabilityJSONOrPlain},
			{`$["input"][3]["arguments"]`, "{not valid json", walker.ScopeToolInput, walker.TargetKindEncodedJSON, walker.MutabilityEncodedJSON},
			{`$["input"][4]["output"]`, `{"answer":"Alice"}`, walker.ScopeToolOutput, walker.TargetKindToolOutput, walker.MutabilityJSONOrPlain},
			{`$["input"][5]["output"]`, "plain Bob", walker.ScopeToolOutput, walker.TargetKindToolOutput, walker.MutabilityJSONOrPlain},
			{`$["input"][6]["text"]`, "direct input text", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][7]["summary"][0]["text"]`, "opaque thought", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["prompt"]["variables"]["a.b"]`, "Carol", walker.ScopeUser, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["prompt"]["variables"]["x/y"]["text"]`, "Dave", walker.ScopeUser, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["prompt"]["variables"]["quote\"key"]`, "Eve", walker.ScopeUser, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["tools"][0]["description"]`, "schema prose", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["parameters"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["tools"][0]["parameters"]["description"]`, "schema nested", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		})
		assertValuesNotTargeted(t, result,
			"response-model", "message", "user", "assistant", "tool", "function_call", "fc_1", "call_1", "lookup",
			"opaque encrypted", "pmpt_1", "schema function")
		if result.Opaque == 0 || result.UnsupportedCount != 0 {
			t.Fatalf("counters = opaque %d unsupported %d", result.Opaque, result.UnsupportedCount)
		}
	})

	t.Run("anthropic system history tool values and opaque blocks", func(t *testing.T) {
		const body = `{
  "model":"claude-test",
  "system":[{"type":"text","text":"anthropic system"}],
  "messages":[
    {"role":"user","content":"first user"},
    {"role":"assistant","content":[
      {"type":"text","text":"assistant text"},
      {"type":"tool_use","id":"toolu_1","name":"lookup","input":{"customer":"Alice","nested":["Bob"],"id":"tool-payload-id"}},
      {"type":"thinking","thinking":"private chain","signature":"thinking signature"},
      {"type":"redacted_thinking","data":"encrypted reasoning"}
    ]},
    {"role":"user","content":[
      {"type":"tool_result","tool_use_id":"toolu_1","content":"plain tool output"},
      {"type":"tool_result","tool_use_id":"toolu_2","content":[
        {"type":"text","text":"nested tool text"},
        {"answer":"Carol","items":["Dave"],"signature":"result signature","id":"result id","name":"result name","tool_use_id":"result tool id","source":{"data":"base64 output","label":"Eve"}}
      ]},
      {"type":"image","source":{"type":"base64","media_type":"image/png","data":"image base64"}}
    ]},
    {"role":"assistant","content":"assistant final"},
    {"role":"user","content":"last user"}
  ],
  "tools":[{"name":"schema tool","description":"schema description","input_schema":{"type":"object","description":"schema nested"}}]
}`
		result := mustWalk(t, "claude", body)
		checkTargets(t, result, []wantTarget{
			{`$["system"][0]["text"]`, "anthropic system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][0]["content"]`, "first user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][1]["content"][0]["text"]`, "assistant text", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][1]["content"][1]["input"]["customer"]`, "Alice", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][1]["content"][1]["input"]["nested"][0]`, "Bob", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][1]["content"][1]["input"]["id"]`, "tool-payload-id", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][0]["content"]`, "plain tool output", walker.ScopeToolOutput, walker.TargetKindToolOutput, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][0]["text"]`, "nested tool text", walker.ScopeToolOutput, walker.TargetKindToolOutput, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["answer"]`, "Carol", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["items"][0]`, "Dave", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["signature"]`, "result signature", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["id"]`, "result id", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["name"]`, "result name", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["tool_use_id"]`, "result tool id", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["source"]["data"]`, "base64 output", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][2]["content"][1]["content"][1]["source"]["label"]`, "Eve", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["messages"][3]["content"]`, "assistant final", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][4]["content"]`, "last user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["description"]`, "schema description", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["input_schema"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["tools"][0]["input_schema"]["description"]`, "schema nested", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		})
		assertValuesNotTargeted(t, result,
			"claude-test", "toolu_1", "toolu_2", "lookup", "private chain", "thinking signature", "encrypted reasoning",
			"image base64", "schema tool")
		if result.Opaque < 6 || result.UnsupportedCount != 0 {
			t.Fatalf("counters = opaque %d unsupported %d", result.Opaque, result.UnsupportedCount)
		}
	})

	t.Run("anthropic string system", func(t *testing.T) {
		result := mustWalk(t, "claude", `{"system":"string system","messages":[{"role":"user","content":"hello"}]}`)
		checkTargets(t, result, []wantTarget{
			{`$["system"]`, "string system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["messages"][0]["content"]`, "hello", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
		})
	})

	t.Run("gemini instructions history functions and code", func(t *testing.T) {
		const body = `{
  "model":"gemini-test",
  "systemInstruction":{"parts":[{"text":"gemini system"}]},
  "contents":[
    {"role":"user","parts":[{"text":"first user"},{"thought":false,"text":"visible false-thought"}]},
    {"role":"model","parts":[
      {"text":"model history"},
      {"functionCall":{"name":"lookup","id":"fc_1","args":{"customer":"Alice","items":["Bob"],"id":"payload id"}}},
      {"executableCode":{"language":"PYTHON","code":"print('Carol')"}},
      {"codeExecutionResult":{"outcome":"OUTCOME_OK","output":"Dave output"}},
      {"thought":true,"text":"private thought","thoughtSignature":"thought sig"}
    ]},
    {"role":"user","parts":[
      {"functionResponse":{"name":"lookup","id":"fr_1","response":{"answer":"Eve","nested":["Frank"]}}},
      {"inlineData":{"mimeType":"image/png","data":"inline base64"}},
      {"fileData":{"mimeType":"text/plain","fileUri":"https://example.invalid/file"}}
    ]},
    {"role":"user","parts":[{"text":"last user"}]}
  ],
  "tools":[{"functionDeclarations":[{"name":"schema function","description":"schema prose","parameters":{"type":"object","description":"schema nested"}}]}]
}`
		result := mustWalk(t, "gemini", body)
		checkTargets(t, result, []wantTarget{
			{`$["systemInstruction"]["parts"][0]["text"]`, "gemini system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["contents"][0]["parts"][0]["text"]`, "first user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["contents"][0]["parts"][1]["text"]`, "visible false-thought", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["contents"][1]["parts"][0]["text"]`, "model history", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["contents"][1]["parts"][1]["functionCall"]["args"]["customer"]`, "Alice", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["contents"][1]["parts"][1]["functionCall"]["args"]["items"][0]`, "Bob", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["contents"][1]["parts"][1]["functionCall"]["args"]["id"]`, "payload id", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["contents"][1]["parts"][2]["executableCode"]["code"]`, "print('Carol')", walker.ScopeAssistant, walker.TargetKindCode, walker.MutabilityDirect},
			{`$["contents"][1]["parts"][3]["codeExecutionResult"]["output"]`, "Dave output", walker.ScopeToolOutput, walker.TargetKindExecutionOutput, walker.MutabilityJSONOrPlain},
			{`$["contents"][2]["parts"][0]["functionResponse"]["response"]["answer"]`, "Eve", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["contents"][2]["parts"][0]["functionResponse"]["response"]["nested"][0]`, "Frank", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["contents"][3]["parts"][0]["text"]`, "last user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["functionDeclarations"][0]["description"]`, "schema prose", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["functionDeclarations"][0]["parameters"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["tools"][0]["functionDeclarations"][0]["parameters"]["description"]`, "schema nested", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		})
		assertValuesNotTargeted(t, result,
			"gemini-test", "lookup", "fc_1", "fr_1", "PYTHON", "OUTCOME_OK", "private thought", "thought sig",
			"image/png", "inline base64", "text/plain", "https://example.invalid/file",
			"schema function")
		if result.Opaque == 0 || result.UnsupportedCount != 0 {
			t.Fatalf("counters = opaque %d unsupported %d", result.Opaque, result.UnsupportedCount)
		}
	})

	t.Run("gemini snake-case system instruction", func(t *testing.T) {
		result := mustWalk(t, "gemini", `{"system_instruction":{"parts":[{"text":"snake system"}]},"contents":[{"parts":[{"text":"default user"}]}]}`)
		checkTargets(t, result, []wantTarget{
			{`$["system_instruction"]["parts"][0]["text"]`, "snake system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["contents"][0]["parts"][0]["text"]`, "default user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
		})
	})

	t.Run("interactions nested steps tools and protected model output", func(t *testing.T) {
		const body = `{
  "model":"interactions-model",
  "system_instruction":{"parts":[{"text":"interaction system"}]},
  "input":[
    "direct user",
    {"type":"user_input","content":"round user"},
    {"type":"model_output","id":"mo_1","name":"model name","content":[
      {"type":"text","text":"model history"},
      {"type":"image","url":"https://example.invalid/image"}
    ],"thought":"private model thought","signature":"model signature"},
    {"type":"function_call","name":"lookup","call_id":"call_1","arguments":"not-json"},
    {"type":"function_call","arguments":{"customer":"Alice","nested":["Bob"],"id":"payload id"}},
    {"type":"function_result","name":"lookup","call_id":"call_1","result":{"answer":"Carol","nested":["Dave"]}},
    {"type":"function_call_output","call_id":"call_2","output":"plain Eve"},
    {"steps":[
      {"type":"user_input","parts":[{"text":"nested user"}]},
      {"role":"assistant","steps":["deep assistant"]}
    ]},
    {"type":"thought","content":[{"type":"text","text":"opaque reasoning"}],"signature":"thought signature"}
  ],
  "steps":[{"type":"model_output","text":"root-step model"}],
  "tools":[{"type":"function","name":"schema name","description":"schema prose","parameters":{"type":"object","description":"schema nested"}}],
  "agent_config":{"note":"control note"}
}`
		result := mustWalk(t, "interactions", body)
		checkTargets(t, result, []wantTarget{
			{`$["system_instruction"]["parts"][0]["text"]`, "interaction system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][0]`, "direct user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][1]["content"]`, "round user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][2]["content"][0]["text"]`, "model history", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][3]["arguments"]`, "not-json", walker.ScopeToolInput, walker.TargetKindEncodedJSON, walker.MutabilityEncodedJSON},
			{`$["input"][4]["arguments"]["customer"]`, "Alice", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["input"][4]["arguments"]["nested"][0]`, "Bob", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["input"][4]["arguments"]["id"]`, "payload id", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["input"][5]["result"]["answer"]`, "Carol", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["input"][5]["result"]["nested"][0]`, "Dave", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
			{`$["input"][6]["output"]`, "plain Eve", walker.ScopeToolOutput, walker.TargetKindToolOutput, walker.MutabilityJSONOrPlain},
			{`$["input"][7]["steps"][0]["parts"][0]["text"]`, "nested user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][7]["steps"][1]["steps"][0]`, "deep assistant", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"][8]["content"][0]["text"]`, "opaque reasoning", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["steps"][0]["text"]`, "root-step model", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["description"]`, "schema prose", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["tools"][0]["parameters"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
			{`$["tools"][0]["parameters"]["description"]`, "schema nested", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		})
		assertValuesNotTargeted(t, result,
			"interactions-model", "mo_1", "model name", "private model thought", "model signature",
			"https://example.invalid/image", "lookup", "call_1", "call_2", "thought signature",
			"schema name", "control note")
		if result.Opaque == 0 || result.UnsupportedCount != 0 {
			t.Fatalf("counters = opaque %d unsupported %d", result.Opaque, result.UnsupportedCount)
		}
	})

	t.Run("interactions camel-case system instruction", func(t *testing.T) {
		result := mustWalk(t, "interactions", `{"systemInstruction":{"text":"camel system"},"input":{"type":"user_input","content":[{"text":"user text"}]}}`)
		checkTargets(t, result, []wantTarget{
			{`$["systemInstruction"]["text"]`, "camel system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
			{`$["input"]["content"][0]["text"]`, "user text", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
		})
	})
}

func TestGeminiMediaAndBuiltInToolsUseExactDisposition(t *testing.T) {
	const body = `{
	  "systemInstruction":{"parts":[
	    {"inline_data":{"mime_type":"text/plain","data":"system bytes","displayName":"system attachment"}}
	  ]},
	  "contents":[
	    {"role":"user","parts":[
	      {"inlineData":{"mimeType":"image/png","data":"user bytes","displayName":"user image"}},
	      {"file_data":{"mime_type":"text/plain","file_uri":"https://example.invalid/user","displayName":"user file"}},
	      {"functionResponse":{"name":"lookup","parts":[
	        {"fileData":{"mimeType":"text/plain","fileUri":"https://example.invalid/tool","displayName":"tool file"}}
	      ]}}
	    ]}
	  ],
	  "tools":[
	    {"functionDeclarations":[{
	      "name":"lookup","description":"interface","parameters":{"type":"object"},
	      "response":{"type":"object"},"behavior":"BLOCKING"
	    }]},
	    {"function_declarations":[{
	      "name":"lookup_json","parametersJsonSchema":{"type":"object"},
	      "responseJsonSchema":{"type":"object"}
	    }]},
	    {"googleSearch":{
	      "searchTypes":{"webSearch":{},"imageSearch":{}},
	      "blockingConfidence":"BLOCK_LOW_AND_ABOVE",
	      "excludeDomains":["example.invalid"],
	      "timeRangeFilter":{"startTime":"2026-01-01T00:00:00Z","endTime":"2026-02-01T00:00:00Z"}
	    }},
	    {"codeExecution":{}},
	    {"urlContext":{}}
	  ]
	}`
	result := mustWalk(t, "gemini", body)
	if result.UnsupportedCount != 0 {
		t.Fatalf("valid Gemini media/tools produced %d unsupported entries", result.UnsupportedCount)
	}
	checkTargets(t, result, []wantTarget{
		{`$["systemInstruction"]["parts"][0]["inline_data"]["displayName"]`, "system attachment", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["contents"][0]["parts"][0]["inlineData"]["displayName"]`, "user image", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["contents"][0]["parts"][1]["file_data"]["displayName"]`, "user file", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["contents"][0]["parts"][2]["functionResponse"]["parts"][0]["fileData"]["displayName"]`, "tool file", walker.ScopeToolOutput, walker.TargetKindNaturalText, walker.MutabilityJSONOrPlain},
		{`$["tools"][0]["functionDeclarations"][0]["description"]`, "interface", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["tools"][0]["functionDeclarations"][0]["parameters"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		{`$["tools"][0]["functionDeclarations"][0]["response"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		{`$["tools"][1]["function_declarations"][0]["parametersJsonSchema"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		{`$["tools"][1]["function_declarations"][0]["responseJsonSchema"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
	})
	assertValuesNotTargeted(t, result,
		"system bytes", "user bytes", "https://example.invalid/user", "https://example.invalid/tool",
		"lookup", "lookup_json", "BLOCKING", "BLOCK_LOW_AND_ABOVE", "example.invalid",
		"2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z",
	)
}

func TestGeminiMediaAndBuiltInToolStringExtensionsAreUnsupported(t *testing.T) {
	tests := []string{
		`{"contents":[{"parts":[{"inlineData":{"data":"bytes","future":"extension"}}]}]}`,
		`{"contents":[{"parts":[{"fileData":{"fileUri":"https://example.invalid","future":"extension"}}]}]}`,
		`{"contents":[],"tools":[{"googleSearch":{"future":"extension"}}]}`,
		`{"contents":[],"tools":[{"googleSearch":{"searchTypes":{"webSearch":{"future":"extension"}}}}]}`,
	}
	for index, body := range tests {
		result := mustWalk(t, "gemini", body)
		if result.UnsupportedCount != 1 {
			t.Fatalf("case %d unsupported count = %d, want 1", index, result.UnsupportedCount)
		}
		assertValuesNotTargeted(t, result, "extension")
	}
}

func TestProtocolStringExtensionsAreUnsupported(t *testing.T) {
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{"openai message", "openai", `{"messages":[{"role":"user","content":"ok","future":{"nested":"extension text"}}]}`},
		{"responses message", "openai-response", `{"input":[{"type":"message","role":"user","content":"ok","future":{"nested":"extension text"}}]}`},
		{"anthropic content block", "claude", `{"messages":[{"role":"user","content":[{"type":"text","text":"ok","future":{"nested":"extension text"}}]}]}`},
		{"anthropic cache control", "claude", `{"messages":[{"role":"user","content":[{"type":"text","text":"ok","cache_control":{"type":"ephemeral","future":"extension text"}}]}]}`},
		{"gemini part", "gemini", `{"contents":[{"role":"user","parts":[{"text":"ok","future":{"nested":"extension text"}}]}]}`},
		{"gemini media resolution", "gemini", `{"contents":[{"role":"user","parts":[{"text":"ok","mediaResolution":{"level":"MEDIA_RESOLUTION_LOW","future":"extension text"}}]}]}`},
		{"gemini video metadata", "gemini", `{"contents":[{"role":"user","parts":[{"text":"ok","videoMetadata":{"startOffset":"0s","future":"extension text"}}]}]}`},
		{"interactions item", "interactions", `{"input":[{"type":"user_input","content":"ok","future":{"nested":"extension text"}}]}`},
		{"interactions reasoning integrity", "interactions", `{"input":[{"type":"model_output","content":"ok","thinking":{"future":"extension text"}}]}`},
		{"interactions text annotations", "interactions", `{"input":[{"type":"user_input","content":[{"type":"text","text":"ok","annotations":[{"future":"extension text"}]}]}]}`},
		{"interactions media", "interactions", `{"input":[{"type":"user_input","content":[{"type":"image","image_url":{"url":"https://example.invalid","future":"extension text"}}]}]}`},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, testCase.format, testCase.body)
			if result.UnsupportedCount == 0 {
				t.Fatal("unknown string-bearing sibling was not marked unsupported")
			}
			assertValuesNotTargeted(t, result, "extension text")
		})
	}
}

func TestCommonMediaAndCacheControlsUseExactDisposition(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantUnsupported int
	}{
		{
			"valid image reference",
			`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid","detail":"auto"}}]}]}`,
			0,
		},
		{
			"image reference string extension",
			`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid","future":"extension"}}]}]}`,
			1,
		},
		{
			"image reference scalar extension",
			`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid","future":{"n":1,"b":true,"z":null}}}]}]}`,
			0,
		},
		{
			"cache breakpoint string extension",
			`{"messages":[{"role":"user","content":[{"type":"text","text":"ok","prompt_cache_breakpoint":{"mode":"default","future":"extension"}}]}]}`,
			1,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai", testCase.body)
			if result.UnsupportedCount != testCase.wantUnsupported {
				t.Fatalf("unsupported count = %d, want %d", result.UnsupportedCount, testCase.wantUnsupported)
			}
			assertValuesNotTargeted(t, result, "https://example.invalid", "auto", "default", "extension")
		})
	}
}

func TestProtocolScalarOnlyExtensionsRemainCompatible(t *testing.T) {
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{"openai message", "openai", `{"messages":[{"role":"user","content":"ok","future":{"n":1,"b":true,"z":null}}]}`},
		{"responses message", "openai-response", `{"input":[{"type":"message","role":"user","content":"ok","future":{"n":1,"b":true,"z":null}}]}`},
		{"anthropic content block", "claude", `{"messages":[{"role":"user","content":[{"type":"text","text":"ok","future":{"n":1,"b":true,"z":null}}]}]}`},
		{"gemini part", "gemini", `{"contents":[{"role":"user","parts":[{"text":"ok","future":{"n":1,"b":true,"z":null}}]}]}`},
		{"interactions item", "interactions", `{"input":[{"type":"user_input","content":"ok","future":{"n":1,"b":true,"z":null}}]}`},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, testCase.format, testCase.body)
			if result.UnsupportedCount != 0 {
				t.Fatalf("scalar-only extension produced %d unsupported entries", result.UnsupportedCount)
			}
		})
	}
}

func TestProtocolToolDefinitionsSanitizeMetadataAndRejectUnknownStrings(t *testing.T) {
	tests := []struct {
		name            string
		format          string
		body            string
		wantUnsupported int
	}{
		{"openai valid", "openai", `{"messages":[],"tools":[{"type":"function","function":{"name":"lookup","description":"interface","parameters":{"type":"object"}}}]}`, 0},
		{"openai string extension", "openai", `{"messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{},"future":"extension"}}]}`, 1},
		{"openai scalar extension", "openai", `{"messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{},"future":{"n":1,"b":true,"z":null}}}]}`, 0},
		{"responses valid", "openai-response", `{"input":"ok","tools":[{"type":"function","name":"lookup","description":"interface","parameters":{"type":"object"}}]}`, 0},
		{"responses string extension", "openai-response", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{},"future":"extension"}]}`, 1},
		{"responses scalar extension", "openai-response", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{},"future":{"n":1,"b":true,"z":null}}]}`, 0},
		{"anthropic valid", "claude", `{"messages":[],"tools":[{"name":"lookup","description":"interface","input_schema":{"type":"object"}}]}`, 0},
		{"anthropic string extension", "claude", `{"messages":[],"tools":[{"name":"lookup","input_schema":{},"future":"extension"}]}`, 1},
		{"anthropic scalar extension", "claude", `{"messages":[],"tools":[{"name":"lookup","input_schema":{},"future":{"n":1,"b":true,"z":null}}]}`, 0},
		{"gemini valid", "gemini", `{"contents":[],"tools":[{"functionDeclarations":[{"name":"lookup","description":"interface","parameters":{"type":"object"}}]}]}`, 0},
		{"gemini string extension", "gemini", `{"contents":[],"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{},"future":"extension"}]}]}`, 1},
		{"gemini scalar extension", "gemini", `{"contents":[],"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{},"future":{"n":1,"b":true,"z":null}}]}]}`, 0},
		{"interactions valid", "interactions", `{"input":"ok","tools":[{"type":"function","name":"lookup","description":"interface","parameters":{"type":"object"}}]}`, 0},
		{"interactions string extension", "interactions", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{},"future":"extension"}]}`, 1},
		{"interactions scalar extension", "interactions", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{},"future":{"n":1,"b":true,"z":null}}]}`, 0},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, testCase.format, testCase.body)
			if result.UnsupportedCount != testCase.wantUnsupported {
				t.Fatalf("unsupported count = %d, want %d", result.UnsupportedCount, testCase.wantUnsupported)
			}
			descriptionTargeted := false
			for _, target := range result.Targets {
				if target.Token.Value == "interface" {
					descriptionTargeted = true
					if target.Scope != walker.ScopeSystem || target.Kind != walker.TargetKindNaturalText {
						t.Fatal("tool description did not use system natural-text disposition")
					}
				}
			}
			wantDescriptionTargeted := strings.Contains(testCase.body, `"description":"interface"`)
			if descriptionTargeted != wantDescriptionTargeted {
				t.Fatalf("description targeted = %v, want %v", descriptionTargeted, wantDescriptionTargeted)
			}
			assertValuesNotTargeted(t, result, "extension")
		})
	}
}

func TestTargetContextCarriesFieldsAndToolScope(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		body       string
		path       string
		immediate  string
		ancestors  []string
		toolScope  walker.Scope
		structured bool
		encoded    bool
	}{
		{
			name: "openai encoded input", format: "openai",
			body:      `{"messages":[{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"f","arguments":"{}"}}]}]}`,
			path:      `$["messages"][0]["tool_calls"][0]["function"]["arguments"]`,
			immediate: "arguments", ancestors: []string{"function", "tool_calls", "messages"},
			toolScope: walker.ScopeToolInput, encoded: true,
		},
		{
			name: "openai encoded output", format: "openai",
			body: `{"messages":[{"role":"tool","content":"{}"}]}`,
			path: `$["messages"][0]["content"]`, immediate: "content", ancestors: []string{"messages"},
			toolScope: walker.ScopeToolOutput, encoded: true,
		},
		{
			name: "anthropic native array input", format: "claude",
			body:      `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{"token":["x"]}}]}]}`,
			path:      `$["messages"][0]["content"][0]["input"]["token"][0]`,
			ancestors: []string{"token", "input", "content", "messages"},
			toolScope: walker.ScopeToolInput, structured: true,
		},
		{
			name: "gemini normalized native input", format: "gemini",
			body:      `{"contents":[{"role":"model","parts":[{"functionCall":{"name":"f","args":{"API-Key":"x"}}}]}]}`,
			path:      `$["contents"][0]["parts"][0]["functionCall"]["args"]["API-Key"]`,
			immediate: "api_key", ancestors: []string{"args", "functioncall", "parts", "contents"},
			toolScope: walker.ScopeToolInput, structured: true,
		},
		{
			name: "interactions native array output", format: "interactions",
			body:      `{"input":[{"type":"function_result","result":{"credential":["x"]}}]}`,
			path:      `$["input"][0]["result"]["credential"][0]`,
			ancestors: []string{"credential", "result", "input"},
			toolScope: walker.ScopeToolOutput, structured: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, testCase.format, testCase.body)
			var target *walker.Target
			for index := range result.Targets {
				if result.Targets[index].Path.String() == testCase.path {
					target = &result.Targets[index]
					break
				}
			}
			if target == nil {
				t.Fatal("expected target path was not selected")
			}
			context := target.Context
			if context.Fields.ImmediateKey != testCase.immediate ||
				context.ToolScope != testCase.toolScope ||
				context.Structured != testCase.structured || context.Encoded != testCase.encoded ||
				int(context.Fields.AncestorCount) != len(testCase.ancestors) {
				t.Fatal("target context metadata mismatch")
			}
			for index, want := range testCase.ancestors {
				if context.Fields.Ancestors[index] != want {
					t.Fatalf("ancestor %d mismatch", index)
				}
			}
		})
	}
}
