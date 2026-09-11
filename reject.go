package main

import (
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func terminateRequest(sourceFormat string, status int, code, message string) pluginapi.RequestInterceptResponse {
	var body any
	switch sourceFormat {
	case "claude":
		body = map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    code,
				"message": message,
			},
		}
	case "gemini", "interactions", "gemini-cli":
		body = map[string]any{
			"error": map[string]any{
				"code":    status,
				"message": message,
				"status":  "INVALID_ARGUMENT",
			},
		}
	default:
		body = map[string]any{
			"error": map[string]string{
				"type":    code,
				"code":    code,
				"message": message,
			},
		}
	}
	raw, _ := json.Marshal(body)
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      status,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    raw,
	}
}
