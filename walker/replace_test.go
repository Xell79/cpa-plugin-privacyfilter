package walker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/walker"
)

func TestSelectedTargetReplacePreservesAllOtherBytes(t *testing.T) {
	body := []byte(" \n{\n" +
		"  \"model\" : \"gpt-test\",\n" +
		"  \"input\" : [\n" +
		"    {\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"secr\\u0065t\"}]},\n" +
		"    {\"type\":\"function_call\",\"name\":\"lookup\",\"arguments\":\"{\\\"value\\\":\\\"leave escaped\\u0020bytes\\\"}\"},\n" +
		"    {\"type\":\"reasoning\",\"encrypted_content\":\"opaque\\u0020bytes\",\"signature\":\"opaque-signature\"}\n" +
		"  ],\n" +
		"  \"big\" : 900719925474099312345678901234567890,\n" +
		"  \"decimal\" : -1.2300e+009,\n" +
		"  \"duplicate\" : \"first\", \"duplicate\" : \"second\",\n" +
		"  \"random\" : \"preserve\\/slash and \\u263a\"\n" +
		"}\t")
	original := append([]byte(nil), body...)
	result, err := walker.Walk(context.Background(), "openai-response", body)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	var selected *walker.Target
	for i := range result.Targets {
		if result.Targets[i].Path.String() == `$["input"][0]["content"][0]["text"]` {
			selected = &result.Targets[i]
			break
		}
	}
	if selected == nil || selected.Token.Value != "secret" {
		t.Fatalf("escaped target not selected: %#v", result.Targets)
	}

	out, changed, err := result.Document.Replace(context.Background(), []payload.Replacement{{
		Token: selected.Token,
		Value: `REDACTED<&>`,
	}})
	if err != nil || !changed {
		t.Fatalf("Replace = changed %v, err %v", changed, err)
	}
	if !bytes.Equal(body, original) {
		t.Fatal("Replace mutated original body")
	}
	want := bytes.Replace(original, []byte(`"secr\u0065t"`), []byte(`"REDACTED<&>"`), 1)
	if !bytes.Equal(out, want) {
		t.Fatalf("replacement changed bytes outside selected token:\n got %s\nwant %s", out, want)
	}
	if !json.Valid(out) {
		t.Fatalf("replacement is invalid JSON: %s", out)
	}
	for _, exact := range [][]byte{
		[]byte(`900719925474099312345678901234567890`),
		[]byte(`-1.2300e+009`),
		[]byte(`"{\"value\":\"leave escaped\u0020bytes\"}"`),
		[]byte(`"opaque\u0020bytes"`),
		[]byte(`"opaque-signature"`),
		[]byte(`"duplicate" : "first", "duplicate" : "second"`),
		[]byte(`"preserve\/slash and \u263a"`),
	} {
		if !bytes.Contains(out, exact) {
			t.Errorf("exact opaque/format bytes %q were not preserved", exact)
		}
	}
}

func TestEveryTargetTokenBelongsToReturnedDocument(t *testing.T) {
	const body = `{
  "instructions":"system",
  "input":[
    {"type":"message","role":"user","content":"user"},
    {"type":"function_call","arguments":"{}"},
    {"type":"function_call_output","output":"tool"}
  ],
  "prompt":{"variables":{"x":"variable"}}
}`
	result := mustWalk(t, "openai-response", body)
	replacements := make([]payload.Replacement, len(result.Targets))
	for i, target := range result.Targets {
		replacements[i] = payload.Replacement{Token: target.Token, Value: target.Token.Value + "-changed"}
	}
	out, changed, err := result.Document.Replace(context.Background(), replacements)
	if err != nil || !changed || !json.Valid(out) {
		t.Fatalf("Replace all targets = changed %v valid %v err %v", changed, json.Valid(out), err)
	}
	for _, target := range result.Targets {
		if !bytes.Contains(out, []byte(target.Token.Value+"-changed")) {
			t.Errorf("replacement for %s is missing", target.Path)
		}
	}
}
