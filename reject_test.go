package main

import (
	"encoding/json"
	"testing"
)

func TestTerminateRequestUsesProtocolEnvelope(t *testing.T) {
	tests := []struct {
		format string
		check  func(t *testing.T, body map[string]any)
	}{
		{
			format: "openai",
			check: func(t *testing.T, body map[string]any) {
				if _, ok := body["error"].(map[string]any); !ok {
					t.Fatalf("OpenAI error envelope mismatch: field_count=%d", len(body))
				}
			},
		},
		{
			format: "openai-response",
			check: func(t *testing.T, body map[string]any) {
				if _, ok := body["error"].(map[string]any); !ok {
					t.Fatalf("Responses error envelope mismatch: field_count=%d", len(body))
				}
			},
		},
		{
			format: "claude",
			check: func(t *testing.T, body map[string]any) {
				if body["type"] != "error" {
					t.Fatalf("Claude error envelope mismatch: field_count=%d", len(body))
				}
			},
		},
		{
			format: "gemini",
			check: func(t *testing.T, body map[string]any) {
				errorBody, ok := body["error"].(map[string]any)
				if !ok || errorBody["status"] != "INVALID_ARGUMENT" {
					t.Fatalf("Gemini error envelope mismatch: field_count=%d", len(body))
				}
			},
		},
		{
			format: "interactions",
			check: func(t *testing.T, body map[string]any) {
				errorBody, ok := body["error"].(map[string]any)
				if !ok || errorBody["status"] != "INVALID_ARGUMENT" {
					t.Fatalf("Interactions error envelope mismatch: field_count=%d", len(body))
				}
			},
		},
		{
			format: "gemini-cli",
			check: func(t *testing.T, body map[string]any) {
				errorBody, ok := body["error"].(map[string]any)
				if !ok || errorBody["status"] != "INVALID_ARGUMENT" {
					t.Fatalf("Gemini CLI error envelope mismatch: field_count=%d", len(body))
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			resp := terminateRequest(tc.format, 422, "privacy_filter_rejected", "request blocked")
			if !resp.Terminate || resp.StatusCode != 422 || resp.ResponseHeaders.Get("Content-Type") != "application/json" {
				t.Fatalf("response terminate=%t status=%d body_len=%d header_count=%d", resp.Terminate, resp.StatusCode, len(resp.ResponseBody), len(resp.ResponseHeaders))
			}
			var body map[string]any
			if err := json.Unmarshal(resp.ResponseBody, &body); err != nil {
				t.Fatal(err)
			}
			tc.check(t, body)
		})
	}
}
