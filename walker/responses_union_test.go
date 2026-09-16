package walker_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
)

func TestResponsesInputUnionHasExplicitDisposition(t *testing.T) {
	tests := []struct {
		name            string
		item            string
		wantTargets     int
		wantUnsupported int
	}{
		{"easy message", `{"type":"message","role":"user","content":"visible"}`, 1, 0},
		{"input message", `{"type":"message","role":"developer","status":"completed","content":[{"type":"input_text","text":"visible"}]}`, 1, 0},
		{"output message", `{"type":"message","id":"msg_1","role":"assistant","status":"completed","phase":"final_answer","content":[{"type":"output_text","text":"visible","annotations":[],"logprobs":[]}]}`, 1, 0},
		{"file search call", `{"type":"file_search_call","id":"fs_1","status":"completed","queries":["visible"]}`, 1, 0},
		{"computer call", `{"type":"computer_call","id":"cc_1","call_id":"call_1","status":"completed","pending_safety_checks":[],"action":{"type":"type","text":"visible"}}`, 1, 0},
		{"computer call output", `{"type":"computer_call_output","id":"cco_1","call_id":"call_1","status":"completed","acknowledged_safety_checks":[],"output":{"type":"computer_screenshot","file_id":"file_1"}}`, 0, 0},
		{"web search call", `{"type":"web_search_call","id":"ws_1","status":"completed","action":{"type":"search","query":"visible","sources":[{"type":"url","url":"https://example.invalid"}]}}`, 1, 0},
		{"function call", `{"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{}"}`, 1, 0},
		{"function call output list", `{"type":"function_call_output","id":"fco_1","call_id":"call_1","output":[{"type":"input_text","text":"visible"}]}`, 1, 0},
		{"tool search call", `{"type":"tool_search_call","id":"ts_1","call_id":"call_1","execution":"client","status":"completed","arguments":{"query":"visible"}}`, 1, 0},
		{"tool search output", `{"type":"tool_search_output","id":"tso_1","tools":[]}`, 0, 1},
		{"additional tools", `{"type":"additional_tools","id":"at_1","role":"developer","tools":[]}`, 0, 0},
		{"reasoning", `{"type":"reasoning","id":"rs_1","status":"completed","encrypted_content":"ciphertext","summary":[{"type":"summary_text","text":"replay text"}]}`, 1, 0},
		{"compaction", `{"type":"compaction","id":"cp_1","encrypted_content":"ciphertext"}`, 0, 0},
		{"image generation call", `{"type":"image_generation_call","id":"ig_1","status":"completed","result":"base64"}`, 0, 0},
		{"code interpreter call", `{"type":"code_interpreter_call","id":"ci_1","container_id":"ctr_1","status":"completed","code":"visible code","outputs":[{"type":"logs","logs":"visible output"}]}`, 2, 0},
		{"local shell call", `{"type":"local_shell_call","id":"ls_1","call_id":"call_1","status":"completed","action":{"type":"exec","command":["visible command"],"env":{"TOKEN":"visible value"}}}`, 2, 0},
		{"local shell output", `{"type":"local_shell_call_output","id":"lso_1","status":"completed","output":"{}"}`, 1, 0},
		{"shell call", `{"type":"shell_call","id":"sh_1","call_id":"call_1","status":"completed","action":{"commands":["visible command"]},"caller":{"type":"direct"},"environment":{"type":"container_reference","container_id":"ctr_1"}}`, 1, 0},
		{"shell call output", `{"type":"shell_call_output","id":"sho_1","call_id":"call_1","status":"completed","caller":{"type":"program","caller_id":"pc_1"},"output":[{"outcome":{"type":"exit","exit_code":0},"stdout":"visible stdout","stderr":"visible stderr"}]}`, 2, 0},
		{"apply patch call", `{"type":"apply_patch_call","id":"ap_1","call_id":"call_1","status":"completed","operation":{"type":"update_file","path":"file.txt","diff":"visible diff"}}`, 1, 0},
		{"apply patch output", `{"type":"apply_patch_call_output","id":"apo_1","call_id":"call_1","status":"completed","output":"visible output"}`, 1, 0},
		{"MCP list tools", `{"type":"mcp_list_tools","id":"ml_1","server_label":"server","error":"visible error","tools":[{"name":"lookup","description":"interface","input_schema":{"type":"object"},"annotations":{"title":"tool"}}]}`, 4, 0},
		{"MCP approval request", `{"type":"mcp_approval_request","id":"ma_1","server_label":"server","name":"lookup","arguments":"{}"}`, 1, 0},
		{"MCP approval response", `{"type":"mcp_approval_response","id":"mar_1","approval_request_id":"ma_1","approve":false,"reason":"visible reason"}`, 1, 0},
		{"MCP call", `{"type":"mcp_call","id":"mc_1","server_label":"server","name":"lookup","status":"completed","arguments":"{}","error":"visible error","output":"visible output"}`, 3, 0},
		{"custom tool call output list", `{"type":"custom_tool_call_output","id":"cto_1","call_id":"call_1","output":[{"type":"input_text","text":"visible"}]}`, 1, 0},
		{"custom tool call", `{"type":"custom_tool_call","id":"ct_1","call_id":"call_1","name":"freeform","status":"completed","input":"visible input"}`, 1, 0},
		{"compaction trigger", `{"type":"compaction_trigger"}`, 0, 0},
		{"item reference", `{"type":"item_reference","id":"item_1"}`, 0, 0},
		{"program", `{"type":"program","id":"pg_1","call_id":"call_1","code":"replay code","fingerprint":"fingerprint"}`, 0, 1},
		{"program output", `{"type":"program_output","id":"pgo_1","call_id":"call_1","status":"completed","result":"visible output"}`, 1, 0},
	}

	if len(tests) != 32 {
		t.Fatalf("fixture count = %d, want all 32 v3.42.0 union arms", len(tests))
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai-response", `{"input":[`+testCase.item+`]}`)
			if len(result.Targets) != testCase.wantTargets {
				t.Fatalf("target count = %d, want %d", len(result.Targets), testCase.wantTargets)
			}
			if result.UnsupportedCount != testCase.wantUnsupported {
				t.Fatalf("unsupported count = %d, want %d", result.UnsupportedCount, testCase.wantUnsupported)
			}
		})
	}
}

func TestResponsesOpenPageURLIsOptionalAndOpaque(t *testing.T) {
	for _, action := range []string{
		`{"type":"open_page"}`,
		`{"type":"open_page","url":null}`,
		`{"type":"open_page","url":"https://example.invalid"}`,
	} {
		result := mustWalk(t, "openai-response", `{"input":[{"type":"web_search_call","action":`+action+`}]}`)
		if len(result.Targets) != 0 || result.UnsupportedCount != 0 {
			t.Fatalf("open_page disposition = targets %d unsupported %d, want 0/0", len(result.Targets), result.UnsupportedCount)
		}
	}
}

func TestResponsesRootToolUnionHasExplicitDisposition(t *testing.T) {
	tests := []struct {
		name            string
		tool            string
		wantUnsupported int
	}{
		{"function", `{"type":"function","name":"lookup","parameters":{}}`, 0},
		{"file search", `{"type":"file_search"}`, 1},
		{"computer", `{"type":"computer"}`, 1},
		{"computer use preview", `{"type":"computer_use_preview"}`, 1},
		{"web search", `{"type":"web_search"}`, 0},
		{"web search 2025-08-26", `{"type":"web_search_2025_08_26"}`, 0},
		{"MCP", `{"type":"mcp"}`, 1},
		{"code interpreter", `{"type":"code_interpreter"}`, 1},
		{"programmatic tool calling", `{"type":"programmatic_tool_calling"}`, 1},
		{"image generation", `{"type":"image_generation"}`, 1},
		{"local shell", `{"type":"local_shell"}`, 1},
		{"shell", `{"type":"shell"}`, 1},
		{"custom", `{"type":"custom","name":"freeform","description":"interface","format":{"type":"grammar","syntax":"lark","definition":"start: WORD"}}`, 0},
		{"namespace", `{"type":"namespace","name":"functions","description":"interfaces","tools":[{"type":"function","name":"lookup","parameters":{}}]}`, 0},
		{"tool search", `{"type":"tool_search","execution":"client","description":"find a tool","parameters":{}}`, 0},
		{"web search preview", `{"type":"web_search_preview"}`, 0},
		{"web search preview 2025-03-11", `{"type":"web_search_preview_2025_03_11"}`, 0},
		{"apply patch", `{"type":"apply_patch"}`, 1},
	}

	if len(tests) != 18 {
		t.Fatalf("fixture count = %d, want all 18 v3.42.0 root tool union arms", len(tests))
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai-response", `{"input":"ok","tools":[`+testCase.tool+`]}`)
			if result.UnsupportedCount != testCase.wantUnsupported {
				t.Fatalf("unsupported count = %d, want %d", result.UnsupportedCount, testCase.wantUnsupported)
			}
		})
	}

	result := mustWalk(t, "openai-response", `{"input":"ok","tools":[{"type":"future_tool"}]}`)
	if result.UnsupportedCount != 1 {
		t.Fatalf("unknown tool unsupported count = %d, want 1", result.UnsupportedCount)
	}
}

func TestResponsesLiteAdditionalToolsAndClientMetadata(t *testing.T) {
	const body = `{
	  "client_metadata": {
	    "x-codex-installation-id": "install_1",
	    "session_id": "session_1",
	    "thread_id": "thread_1",
	    "x-codex-window-id": "window_1",
	    "turn_id": "turn_1",
	    "root_turn_id": "root_1",
	    "x-codex-turn-metadata": "{\"api_key\":\"short-value\"}",
	    "future_transport_key": {"nested": "opaque transport value"}
	  },
	  "input": [
	    {
	      "type": "additional_tools",
	      "id": "at_1",
	      "role": "developer",
	      "tools": [
	        {
	          "type": "namespace",
	          "name": "functions",
	          "description": "namespace description",
	          "tools": [
	            {
	              "type": "function",
	              "name": "lookup",
	              "description": "function description",
	              "parameters": {"type": "object", "properties": {"query": {"description": "query description"}}}
	            },
	            {
	              "type": "custom",
	              "name": "freeform",
	              "description": "custom description",
	              "format": {"type": "grammar", "syntax": "lark", "definition": "start: WORD"}
	            }
	          ]
	        },
	        {"type": "tool_search", "execution": "client", "description": "search description", "parameters": {"type": "object"}},
	        {
	          "type": "web_search",
	          "external_web_access": true,
	          "filters": {"allowed_domains": ["example.invalid"], "blocked_domains": ["blocked.invalid"]},
	          "user_location": {"type": "approximate", "country": "US"},
	          "search_context_size": "medium",
	          "search_content_types": ["text"],
	          "return_token_budget": 2048
	        }
	      ]
	    },
	    {
	      "type": "custom_tool_call",
	      "id": "ct_1",
	      "call_id": "call_1",
	      "name": "freeform",
	      "status": "completed",
	      "internal_chat_message_metadata_passthrough": {
	        "turn_id": "turn_1",
	        "create_time": 1.5,
	        "content_item_kinds": ["custom_tool_call"],
	        "executed_tool_calls": [{"arguments": {"api_key": "short-value"}}],
	        "tool_calls_complete": true
	      },
	      "input": "{\"AK\":\"short-value\"}"
	    }
	  ]
	}`

	result := mustWalk(t, "openai-response", body)
	if result.UnsupportedCount != 0 {
		t.Fatalf("unsupported count = %d, want 0", result.UnsupportedCount)
	}

	targetPaths := make(map[string]struct{}, len(result.Targets))
	for _, target := range result.Targets {
		targetPaths[target.Path.String()] = struct{}{}
	}
	for _, path := range []string{
		`$["client_metadata"]["x-codex-turn-metadata"]`,
		`$["client_metadata"]["future_transport_key"]["nested"]`,
		`$["input"][0]["tools"][0]["description"]`,
		`$["input"][0]["tools"][0]["tools"][0]["description"]`,
		`$["input"][0]["tools"][0]["tools"][1]["format"]["definition"]`,
		`$["input"][0]["tools"][1]["description"]`,
		`$["input"][1]["internal_chat_message_metadata_passthrough"]["executed_tool_calls"][0]["arguments"]["api_key"]`,
		`$["input"][1]["input"]`,
	} {
		if _, ok := targetPaths[path]; !ok {
			t.Fatalf("expected target path %s", path)
		}
	}
	for _, path := range []string{
		`$["client_metadata"]["session_id"]`,
		`$["input"][1]["status"]`,
	} {
		if _, ok := targetPaths[path]; ok {
			t.Fatalf("control metadata unexpectedly targeted at %s", path)
		}
	}
}

func TestResponsesMetadataRejectsDuplicateKeys(t *testing.T) {
	bodies := []string{
		`{"input":"ok","client_metadata":{"session_id":"one","session_id":"two"}}`,
		`{"input":[{"type":"custom_tool_call","name":"tool","input":"ok","internal_chat_message_metadata_passthrough":{"executed_tool_calls":[{"arguments":{"api_key":"one","api_key":"two"}}]}}]}`,
	}
	for index, body := range bodies {
		_, err := walker.Walk(
			context.Background(),
			"openai-response",
			[]byte(body),
		)
		if !errors.Is(err, walker.ErrAmbiguousPath) {
			t.Fatalf("duplicate metadata key was not rejected as ambiguous index=%d", index)
		}
	}
}

func TestResponsesRootControlsAndPromptVariableVariants(t *testing.T) {
	const body = `{
	  "model":"gpt-test",
	  "instructions":"system text",
	  "input":"user text",
	  "previous_response_id":"resp_1",
	  "prompt_cache_key":"cache-key",
	  "safety_identifier":"safety-id",
	  "user":"user-id",
	  "context_management":[{"type":"compaction","compact_threshold":1000}],
	  "conversation":{"id":"conv_1"},
	  "include":["reasoning.encrypted_content"],
	  "metadata":{"trace":"control"},
	  "moderation":{"model":"moderation-model","policy":{"input":{"mode":"auto"},"output":{"mode":"auto"}}},
	  "prompt":{"id":"prompt_1","version":"2","variables":{
	    "plain":"plain variable",
	    "text":{"type":"input_text","text":"typed variable","prompt_cache_breakpoint":{"mode":"default"}},
	    "image":{"type":"input_image","file_id":"file_1","detail":"auto"},
	    "file":{"type":"input_file","file_data":"base64","filename":"doc.txt"}
	  }},
	  "prompt_cache_retention":"24h",
	  "prompt_cache_options":{"mode":"auto","ttl":"30m"},
	  "service_tier":"default",
	  "truncation":"disabled",
	  "reasoning":{"effort":"medium","summary":"auto"},
	  "text":{"format":{"type":"text"}},
	  "tool_choice":"auto",
	  "tools":[{"type":"function","name":"lookup","description":"interface prose","parameters":{"type":"object","properties":{}},"strict":true,"allowed_callers":["direct","programmatic"],"defer_loading":true,"output_schema":{"type":"object"}}]
	}`
	result := mustWalk(t, "openai-response", body)
	if result.UnsupportedCount != 0 {
		t.Fatalf("valid root controls produced %d unsupported entries", result.UnsupportedCount)
	}
	checkTargets(t, result, []wantTarget{
		{`$["instructions"]`, "system text", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["input"]`, "user text", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["prompt"]["variables"]["plain"]`, "plain variable", walker.ScopeUser, walker.TargetKindJSONValue, walker.MutabilityDirect},
		{`$["prompt"]["variables"]["text"]["text"]`, "typed variable", walker.ScopeUser, walker.TargetKindJSONValue, walker.MutabilityDirect},
		{`$["tools"][0]["description"]`, "interface prose", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["tools"][0]["parameters"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
		{`$["tools"][0]["output_schema"]["type"]`, "object", walker.ScopeSystem, walker.TargetKindJSONValue, walker.MutabilityDirect},
	})
	assertValuesNotTargeted(t, result, "file_1", "base64", "doc.txt", "direct", "programmatic")
}

func TestResponsesCurrentValidCompatibilityShapes(t *testing.T) {
	tests := []struct {
		name        string
		item        string
		wantTargets int
	}{
		{
			"assistant easy input message",
			`{"type":"message","role":"assistant","content":[{"type":"input_text","text":"visible"},{"type":"input_image","detail":"auto","file_id":"file_1"},{"type":"input_file","file_id":"file_2"}]}`,
			1,
		},
		{
			"computer call without actions",
			`{"type":"computer_call","id":"cc_1","call_id":"call_1","status":"in_progress","pending_safety_checks":[]}`,
			0,
		},
		{
			"computer call with both action forms",
			`{"type":"computer_call","id":"cc_1","call_id":"call_1","status":"in_progress","pending_safety_checks":[],"action":{"type":"type","text":"first"},"actions":[{"type":"type","text":"second"}]}`,
			2,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai-response", `{"input":[`+testCase.item+`]}`)
			if len(result.Targets) != testCase.wantTargets || result.UnsupportedCount != 0 {
				t.Fatalf("targets = %d, unsupported = %d; want %d, 0", len(result.Targets), result.UnsupportedCount, testCase.wantTargets)
			}
		})
	}
}

func TestResponsesComputerActionVariantsUseExactDisposition(t *testing.T) {
	tests := []struct {
		name            string
		action          string
		wantTargets     int
		wantUnsupported int
	}{
		{"click", `{"type":"click","button":"left","x":1,"y":2,"keys":["SHIFT"]}`, 0, 0},
		{"double click", `{"type":"double_click","x":1,"y":2,"keys":[]}`, 0, 0},
		{"drag", `{"type":"drag","path":[{"x":1,"y":2},{"x":3,"y":4}],"keys":["SHIFT"]}`, 0, 0},
		{"keypress", `{"type":"keypress","keys":["CTRL","C"]}`, 0, 0},
		{"move", `{"type":"move","x":1,"y":2,"keys":[]}`, 0, 0},
		{"screenshot", `{"type":"screenshot"}`, 0, 0},
		{"scroll", `{"type":"scroll","scroll_x":1,"scroll_y":2,"x":3,"y":4,"keys":[]}`, 0, 0},
		{"type", `{"type":"type","text":"visible"}`, 1, 0},
		{"wait", `{"type":"wait"}`, 0, 0},
		{"wait wrong-arm keys", `{"type":"wait","keys":["opaque"]}`, 0, 1},
		{"screenshot wrong-arm button", `{"type":"screenshot","button":"opaque"}`, 0, 1},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			body := `{"input":[{"type":"computer_call","id":"cc_1","call_id":"call_1","status":"completed","pending_safety_checks":[],"action":` + testCase.action + `}]}`
			result := mustWalk(t, "openai-response", body)
			if len(result.Targets) != testCase.wantTargets || result.UnsupportedCount != testCase.wantUnsupported {
				t.Fatalf(
					"targets = %d, unsupported = %d; want %d, %d",
					len(result.Targets), result.UnsupportedCount, testCase.wantTargets, testCase.wantUnsupported,
				)
			}
		})
	}
}

func TestResponsesOutputTextAnnotationDisposition(t *testing.T) {
	wrap := func(block string) string {
		return `{"input":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[` + block + `]}]}`
	}
	tests := []struct {
		name            string
		block           string
		wantTargets     int
		wantUnsupported int
	}{
		{
			"file citation",
			`{"type":"output_text","text":"answer","annotations":[{"type":"file_citation","file_id":"file_1","filename":"doc.txt","index":0}]}`,
			1,
			0,
		},
		{
			"file path",
			`{"type":"output_text","text":"answer","annotations":[{"type":"file_path","file_id":"file_1","index":0}]}`,
			1,
			0,
		},
		{
			"URL citation",
			`{"type":"output_text","text":"answer","annotations":[{"type":"url_citation","start_index":0,"end_index":6,"title":"title","url":"https://example.invalid"}]}`,
			0,
			1,
		},
		{
			"container file citation",
			`{"type":"output_text","text":"answer","annotations":[{"type":"container_file_citation","container_id":"ctr_1","file_id":"file_1","filename":"doc.txt","start_index":0,"end_index":6}]}`,
			0,
			1,
		},
		{
			"logprobs",
			`{"type":"output_text","text":"a","annotations":[],"logprobs":[{"token":"a","bytes":[97],"logprob":-0.1,"top_logprobs":[]}]}`,
			0,
			1,
		},
		{
			"unknown annotation type",
			`{"type":"output_text","text":"answer","annotations":[{"type":"future_citation","value":"opaque"}]}`,
			0,
			1,
		},
		{
			"file citation string extension",
			`{"type":"output_text","text":"answer","annotations":[{"type":"file_citation","file_id":"file_1","filename":"doc.txt","index":0,"future":"opaque"}]}`,
			1,
			1,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai-response", wrap(testCase.block))
			if len(result.Targets) != testCase.wantTargets || result.UnsupportedCount != testCase.wantUnsupported {
				t.Fatalf(
					"targets = %d, unsupported = %d; want %d, %d",
					len(result.Targets), result.UnsupportedCount, testCase.wantTargets, testCase.wantUnsupported,
				)
			}
		})
	}
}

func TestResponsesRootTypedControlsUseExactDisposition(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"moderation", `{"input":"ok","moderation":{"model":"omni-moderation-latest","future":"opaque"}}`},
		{"prompt cache options", `{"input":"ok","prompt_cache_options":{"mode":"implicit","future":"opaque"}}`},
		{"stream options", `{"input":"ok","stream_options":{"include_obfuscation":true,"future":"opaque"}}`},
		{"reasoning config", `{"input":"ok","reasoning":{"effort":"medium","future":"opaque"}}`},
		{"text config", `{"input":"ok","text":{"verbosity":"low","future":"opaque"}}`},
		{"tool choice", `{"input":"ok","tool_choice":{"type":"function","name":"lookup","future":"opaque"}}`},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai-response", testCase.body)
			if result.UnsupportedCount != 1 {
				t.Fatalf("unsupported count = %d, want 1", result.UnsupportedCount)
			}
		})
	}
}

func TestResponsesCurrentRootTypedControlVariantsRemainCompatible(t *testing.T) {
	const body = `{
	  "input":"ok",
	  "moderation":{"model":"omni-moderation-latest","policy":{"input":{"mode":"score"},"output":{"mode":"block"}}},
	  "prompt_cache_options":{"mode":"explicit","ttl":"30m"},
	  "stream_options":{"include_obfuscation":true},
	  "reasoning":{"context":"all_turns","effort":"medium","generate_summary":"auto","summary":"detailed","mode":"standard"},
	  "text":{"verbosity":"low","format":{"type":"json_schema","name":"result","description":"format","schema":{"type":"object","properties":{"value":{"type":"string"}}},"strict":true}},
	  "tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"lookup"}]}
	}`
	result := mustWalk(t, "openai-response", body)
	if result.UnsupportedCount != 0 || len(result.Targets) != 4 {
		t.Fatalf("targets = %d, unsupported = %d; want 4, 0", len(result.Targets), result.UnsupportedCount)
	}
	assertValuesNotTargeted(t, result, "all_turns", "lookup")
}

func TestResponsesReasoningReplayUsesExactDisposition(t *testing.T) {
	tests := []struct {
		name string
		item string
	}{
		{
			"summary extension",
			`{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"replay","future":"opaque"}]}`,
		},
		{
			"content extension",
			`{"type":"reasoning","id":"rs_1","summary":[],"content":[{"type":"reasoning_text","text":"replay","future":"opaque"}]}`,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai-response", `{"input":[`+testCase.item+`]}`)
			if len(result.Targets) != 1 || result.UnsupportedCount != 1 {
				t.Fatalf("targets = %d, unsupported = %d; want 1, 1", len(result.Targets), result.UnsupportedCount)
			}
			if result.Targets[0].Token.Value != "replay" || result.Targets[0].Scope != walker.ScopeAssistant {
				t.Fatal("reasoning replay text did not use assistant disposition")
			}
		})
	}
}

func TestResponsesIntegrityAndDefinitionObjectsRejectUnknownStrings(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantUnsupported int
	}{
		{
			"function tool string extension",
			`{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"},"future":"extension"}]}`,
			1,
		},
		{
			"function tool scalar extension",
			`{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"},"future":{"n":1,"b":true,"z":null}}]}`,
			0,
		},
		{
			"web source string extension",
			`{"input":[{"type":"web_search_call","action":{"type":"search","query":"ok","sources":[{"type":"url","url":"https://example.invalid","future":"extension"}]}}]}`,
			1,
		},
		{
			"web source scalar extension",
			`{"input":[{"type":"web_search_call","action":{"type":"search","query":"ok","sources":[{"type":"url","url":"https://example.invalid","future":1}]}}]}`,
			0,
		},
		{
			"pending safety-check string extension",
			`{"input":[{"type":"computer_call","pending_safety_checks":[{"id":"safe_1","code":"policy","message":"control","future":"extension"}],"action":{"type":"wait"}}]}`,
			1,
		},
		{
			"acknowledged safety-check string extension",
			`{"input":[{"type":"computer_call_output","acknowledged_safety_checks":[{"id":"safe_1","code":"policy","message":"control","future":"extension"}],"output":{"type":"computer_screenshot","file_id":"file_1"}}]}`,
			1,
		},
		{
			"safety-check scalar extension",
			`{"input":[{"type":"computer_call","pending_safety_checks":[{"id":"safe_1","code":"policy","message":"control","future":true}],"action":{"type":"wait"}}]}`,
			0,
		},
		{
			"image revised prompt",
			`{"input":[{"type":"image_generation_call","id":"ig_1","status":"completed","result":"base64","revised_prompt":"visible prompt"}]}`,
			1,
		},
		{
			"program replay",
			`{"input":[{"type":"program","id":"pg_1","call_id":"call_1","code":"replay code","fingerprint":"fingerprint"}]}`,
			1,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := mustWalk(t, "openai-response", testCase.body)
			if result.UnsupportedCount != testCase.wantUnsupported {
				t.Fatalf("unsupported count = %d, want %d", result.UnsupportedCount, testCase.wantUnsupported)
			}
		})
	}
}
