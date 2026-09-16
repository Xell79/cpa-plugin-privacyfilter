// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginPhaseReadyNoStanza(t *testing.T) {
	ready := pluginListResponse{
		PluginsEnabled: true,
		Plugins: []pluginListEntry{{
			ID: pluginID,
		}},
	}
	if !pluginPhaseReady("verify-no-stanza", ready) {
		t.Fatal("expected exact no-stanza state to be ready")
	}

	cases := []pluginListResponse{
		{},
		{PluginsEnabled: true},
		{PluginsEnabled: true, Plugins: []pluginListEntry{{ID: pluginID, Configured: true}}},
		{PluginsEnabled: true, Plugins: []pluginListEntry{{ID: pluginID, Registered: true}}},
		{PluginsEnabled: true, Plugins: []pluginListEntry{{ID: pluginID, Enabled: true}}},
		{PluginsEnabled: true, Plugins: []pluginListEntry{{ID: pluginID, EffectiveEnabled: true}}},
		{PluginsEnabled: true, Plugins: []pluginListEntry{{ID: "other"}}},
	}
	for index, response := range cases {
		if pluginPhaseReady("verify-no-stanza", response) {
			t.Fatalf("unexpected ready no-stanza case index=%d", index)
		}
	}
}

func TestPluginPhaseReadyExplicit(t *testing.T) {
	entry := func(id string) pluginListEntry {
		return pluginListEntry{
			ID:               id,
			Configured:       true,
			Registered:       true,
			Enabled:          true,
			EffectiveEnabled: true,
		}
	}
	ready := pluginListResponse{
		PluginsEnabled: true,
		Plugins: []pluginListEntry{
			entry(pluginID),
			entry("order-low"),
			entry("order-high"),
		},
	}
	if !pluginPhaseReady("verify-explicit", ready) {
		t.Fatal("expected exact explicit state to be ready")
	}

	mutations := []func(*pluginListEntry){
		func(value *pluginListEntry) { value.Configured = false },
		func(value *pluginListEntry) { value.Registered = false },
		func(value *pluginListEntry) { value.Enabled = false },
		func(value *pluginListEntry) { value.EffectiveEnabled = false },
	}
	for mutationIndex, mutate := range mutations {
		for pluginIndex := range ready.Plugins {
			changed := ready
			changed.Plugins = append([]pluginListEntry(nil), ready.Plugins...)
			mutate(&changed.Plugins[pluginIndex])
			if pluginPhaseReady("verify-explicit", changed) {
				t.Fatalf("unexpected ready explicit mutation=%d plugin=%d", mutationIndex, pluginIndex)
			}
		}
	}
	cases := []pluginListResponse{
		{PluginsEnabled: false, Plugins: ready.Plugins},
		{PluginsEnabled: true, Plugins: ready.Plugins[:2]},
		{PluginsEnabled: true, Plugins: append(append([]pluginListEntry(nil), ready.Plugins...), entry(pluginID))},
	}
	withUnknown := ready
	withUnknown.Plugins = append([]pluginListEntry(nil), ready.Plugins...)
	withUnknown.Plugins[0].ID = "other"
	cases = append(cases, withUnknown)
	for index, response := range cases {
		if pluginPhaseReady("verify-explicit", response) {
			t.Fatalf("unexpected ready explicit shape index=%d", index)
		}
	}
	if pluginPhaseReady("unknown", ready) {
		t.Fatal("unexpected ready state for unknown phase")
	}
}

func TestVerifyNoStanza(t *testing.T) {
	response := pluginListResponse{
		PluginsEnabled: true,
		Plugins:        []pluginListEntry{{ID: pluginID}},
	}
	assertions, err := verifyNoStanza(response)
	if err != nil {
		t.Fatal("exact no-stanza state was rejected")
	}
	if !allTrue(
		assertions.PluginsEnabled,
		assertions.Discovered,
		assertions.NotConfigured,
		assertions.NotRegistered,
		assertions.Disabled,
		assertions.NotEffective,
		assertions.MetadataAbsent,
		assertions.OnlyCandidateID,
	) {
		t.Fatal("no-stanza assertions were incomplete")
	}

	response.Plugins[0].Metadata = &pluginMetadata{}
	if _, err = verifyNoStanza(response); err == nil {
		t.Fatal("no-stanza state with metadata was accepted")
	}
}

func TestValidRedactedToolRequest(t *testing.T) {
	valid := []byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\"}"}}]}]}`)
	if !validRedactedToolRequest(valid) {
		t.Fatal("exact redacted tool request was rejected")
	}

	cases := [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"model":"other","messages":[]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"before-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\"}"}}]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"user","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\"}"}}]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"other","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\"}"}}]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"other","arguments":"{\"api_key\":\"[密钥]\"}"}}]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"not-json"}}]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\",\"extra\":true}"}}]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\"}"}},{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\"}"}}]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"[密钥]\"}"}}]},{"role":"assistant","tool_calls":[]}]}`),
		[]byte(`{"model":"mock-model","messages":[{"role":"assistant","tool_calls":[{"id":"after-probe","type":"function","function":{"name":"probe","arguments":"{\"api_key\":\"not-redacted\"}"}}]}]}`),
	}
	for index, body := range cases {
		if validRedactedToolRequest(body) {
			t.Fatalf("invalid tool request accepted index=%d body_len=%d", index, len(body))
		}
	}
}

func TestValidRedactedResponsesLiteRequest(t *testing.T) {
	valid := []byte(`{
	  "model":"mock-model",
	  "client_metadata":{
	    "session_id":"session_1",
	    "x-codex-turn-metadata":"{\"api_key\":\"[密钥]\"}"
	  },
	  "input":[
	    {"type":"additional_tools","tools":[{"type":"namespace"}]},
	    {"type":"custom_tool_call","status":"completed","input":"{\"AK\":\"[密钥]\"}"}
	  ]
	}`)
	if !validRedactedResponsesLiteRequest(valid) {
		t.Fatal("exact redacted Responses Lite request was rejected")
	}

	cases := [][]byte{
		nil,
		[]byte(`{}`),
		bytes.Replace(valid, []byte(`"model":"mock-model"`), []byte(`"model":"other"`), 1),
		bytes.Replace(valid, []byte(`"session_id":"session_1"`), []byte(`"session_id":"other"`), 1),
		bytes.Replace(valid, []byte(`"status":"completed"`), []byte(`"status":"failed"`), 1),
		bytes.Replace(valid, []byte(`{\"AK\":\"[密钥]\"}`), []byte(`{\"AK\":\"q7z\"}`), 1),
		bytes.Replace(valid, []byte(`{\"api_key\":\"[密钥]\"}`), []byte(`{\"api_key\":\"q7z\"}`), 1),
	}
	for index, body := range cases {
		if validRedactedResponsesLiteRequest(body) {
			t.Fatalf("invalid Responses Lite request accepted index=%d body_len=%d", index, len(body))
		}
	}
}

func TestValidReasoningReplayRequest(t *testing.T) {
	valid := []byte(`{
	  "model":"mock-model",
	  "messages":[
	    {"role":"user","content":"[邮箱]"},
	    {
	      "role":"assistant",
	      "content":"answer",
	      "reasoning":"integrity-replay-value",
	      "reasoning_content":"integrity-replay-value",
	      "reasoning_details":[
	        {"type":"reasoning.text","text":"integrity-replay-value","signature":"integrity-signature","id":"rd_1","format":"unknown","index":0},
	        {"type":"reasoning.summary","summary":"integrity-replay-value","id":"rd_2","format":"openai-responses-v1","index":1},
	        {"type":"reasoning.encrypted","data":"integrity-replay-value","id":"rd_3","format":"anthropic-claude-v1","index":2}
	      ]
	    }
	  ]
	}`)
	if !validReasoningReplayRequest(valid) {
		t.Fatal("exact reasoning replay request was rejected")
	}

	cases := [][]byte{
		nil,
		[]byte(`{}`),
		bytes.Replace(valid, []byte(`"model":"mock-model"`), []byte(`"model":"other"`), 1),
		bytes.Replace(valid, []byte(`"content":"[邮箱]"`), []byte(`"content":"replay@example.test"`), 1),
		bytes.Replace(valid, []byte(`"content":"answer"`), []byte(`"content":"other"`), 1),
		bytes.Replace(valid, []byte(`"reasoning":"integrity-replay-value"`), []byte(`"reasoning":"changed"`), 1),
		bytes.Replace(valid, []byte(`"reasoning_content":"integrity-replay-value"`), []byte(`"reasoning_content":"changed"`), 1),
		bytes.Replace(valid, []byte(`"text":"integrity-replay-value"`), []byte(`"text":"changed"`), 1),
		bytes.Replace(valid, []byte(`"signature":"integrity-signature"`), []byte(`"signature":"changed"`), 1),
		bytes.Replace(valid, []byte(`"summary":"integrity-replay-value"`), []byte(`"summary":"changed"`), 1),
		bytes.Replace(valid, []byte(`"data":"integrity-replay-value"`), []byte(`"data":"changed"`), 1),
		bytes.Replace(valid, []byte(`"format":"unknown"`), []byte(`"format":"changed"`), 1),
		bytes.Replace(valid, []byte(`"index":0`), []byte(`"index":9`), 1),
	}
	for index, body := range cases {
		if validReasoningReplayRequest(body) {
			t.Fatalf("invalid reasoning replay request accepted index=%d body_len=%d", index, len(body))
		}
	}
}

func TestSummarizePluginStateIsBoundedAndValueFree(t *testing.T) {
	response := pluginListResponse{
		PluginsEnabled: true,
		Plugins: []pluginListEntry{
			{ID: "order-high", Configured: true},
			{ID: "order-low", Registered: true},
			{ID: pluginID, EffectiveEnabled: true},
			{ID: "untrusted-plugin-identifier", Metadata: &pluginMetadata{Version: "untrusted-version"}},
		},
	}
	summary := summarizePluginState(response)
	if strings.Contains(summary, "untrusted") {
		t.Fatal("plugin state summary exposed an untrusted field")
	}
	expected := "plugins_enabled=true count=4 high_configured=true high_registered=false high_enabled=false high_effective=false low_configured=false low_registered=true low_enabled=false low_effective=false privacy_configured=false privacy_registered=false privacy_enabled=false privacy_effective=true"
	if summary != expected {
		t.Fatalf("unexpected plugin state summary length=%d", len(summary))
	}
}

func TestJSONNumber(t *testing.T) {
	cases := []struct {
		value any
		want  int
	}{
		{value: json.Number("0"), want: 0},
		{value: json.Number("50"), want: 50},
		{value: json.Number("1073741824"), want: 1 << 30},
		{value: json.Number("1073741825"), want: -1},
		{value: json.Number("-1"), want: -1},
		{value: json.Number("1.5"), want: -1},
		{value: "1", want: -1},
		{value: nil, want: -1},
	}
	for index, test := range cases {
		if got := jsonNumber(test.value); got != test.want {
			t.Fatalf("unexpected JSON number result index=%d got=%d", index, got)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("controlled read failure")
}

func TestReadBounded(t *testing.T) {
	cases := []struct {
		reader  *strings.Reader
		wantLen int
		wantErr bool
	}{
		{reader: strings.NewReader(""), wantLen: 0},
		{reader: strings.NewReader("small"), wantLen: 5},
		{reader: strings.NewReader(strings.Repeat("x", maxHTTPBody)), wantLen: maxHTTPBody},
		{reader: strings.NewReader(strings.Repeat("x", maxHTTPBody+1)), wantLen: maxHTTPBody + 1, wantErr: true},
	}
	for index, test := range cases {
		body, err := readBounded(test.reader)
		if len(body) != test.wantLen || (err != nil) != test.wantErr {
			t.Fatalf("unexpected bounded read result index=%d body_len=%d has_error=%t", index, len(body), err != nil)
		}
	}
	if body, err := readBounded(failingReader{}); err == nil || len(body) != 0 {
		t.Fatalf("read failure was not propagated body_len=%d", len(body))
	}
}

func TestWriteReportExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase.json")
	report := phaseReport{
		SchemaVersion: 1,
		Mode:          "verify-no-stanza",
		Plugin: reportPlugin{
			ID:            pluginID,
			Version:       "0.3.0-dev",
			LibrarySHA256: strings.Repeat("a", 64),
		},
	}
	if err := writeReportExclusive(path, report); err != nil {
		t.Fatal("exclusive report creation failed")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("exclusive report was not created")
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected report mode=%#o", info.Mode().Perm())
	}
	original, err := os.ReadFile(path)
	if err != nil || len(original) == 0 {
		t.Fatal("exclusive report could not be read")
	}
	if err = writeReportExclusive(path, report); err == nil {
		t.Fatal("existing report was replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(original) {
		t.Fatal("existing report changed after refused replacement")
	}
}
