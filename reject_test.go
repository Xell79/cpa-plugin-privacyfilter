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
					t.Fatalf("OpenAI error body = %#v", body)
				}
			},
		},
		{
			format: "openai-response",
			check: func(t *testing.T, body map[string]any) {
				if _, ok := body["error"].(map[string]any); !ok {
					t.Fatalf("Responses error body = %#v", body)
				}
			},
		},
		{
			format: "claude",
			check: func(t *testing.T, body map[string]any) {
				if body["type"] != "error" {
					t.Fatalf("Claude error body = %#v", body)
				}
			},
		},
		{
			format: "gemini",
			check: func(t *testing.T, body map[string]any) {
				errorBody, ok := body["error"].(map[string]any)
				if !ok || errorBody["status"] != "INVALID_ARGUMENT" {
					t.Fatalf("Gemini error body = %#v", body)
				}
			},
		},
		{
			format: "interactions",
			check: func(t *testing.T, body map[string]any) {
				errorBody, ok := body["error"].(map[string]any)
				if !ok || errorBody["status"] != "INVALID_ARGUMENT" {
					t.Fatalf("Interactions error body = %#v", body)
				}
			},
		},
		{
			format: "gemini-cli",
			check: func(t *testing.T, body map[string]any) {
				errorBody, ok := body["error"].(map[string]any)
				if !ok || errorBody["status"] != "INVALID_ARGUMENT" {
					t.Fatalf("Gemini CLI error body = %#v", body)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			resp := terminateRequest(tc.format, 422, "privacy_filter_rejected", "request blocked")
			if !resp.Terminate || resp.StatusCode != 422 || resp.ResponseHeaders.Get("Content-Type") != "application/json" {
				t.Fatalf("response = %+v", resp)
			}
			var body map[string]any
			if err := json.Unmarshal(resp.ResponseBody, &body); err != nil {
				t.Fatal(err)
			}
			tc.check(t, body)
		})
	}
}
