package payload_test

// The byte-preservation cases in this file selectively carry forward the
// replacement and JSON-edge corpus from ToS0/cpa-plugin-privacyfilter's
// pseudonymize branch. Policy-specific deny/deep-walk cases are intentionally
// absent: these tests make an upper layer select exact value tokens.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

func mustScan(t *testing.T, body []byte, opts payload.ScanOptions) *payload.Document {
	t.Helper()
	doc, err := payload.Scan(context.Background(), body, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return doc
}

func mustScanObject(t *testing.T, body []byte, opts payload.ScanOptions) *payload.Document {
	t.Helper()
	doc, err := payload.ScanObject(context.Background(), body, opts)
	if err != nil {
		t.Fatalf("ScanObject: %v", err)
	}
	return doc
}

func mustStringAt(t *testing.T, doc *payload.Document, path payload.Path) payload.StringToken {
	t.Helper()
	token, err := doc.StringAt(path)
	if err != nil {
		t.Fatalf("StringAt(%s): %v", path, err)
	}
	return token
}

func sameBacking(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == 0 && len(b) == 0
	}
	return &a[0] == &b[0]
}

func TestPathTypedSegmentsAndEscaping(t *testing.T) {
	path := payload.Path{
		payload.Key("a.b"),
		payload.Key("x/y"),
		payload.Key(`quote" and [bracket]`),
		payload.Key("0"),
		payload.Index(0),
		payload.Key(""),
	}
	const want = `$["a.b"]["x/y"]["quote\" and [bracket]"]["0"][0][""]`
	if got := path.String(); got != want {
		t.Fatalf("Path.String() = %q, want %q", got, want)
	}
	if (payload.Path{payload.Key("0")}).Equal(payload.Path{payload.Index(0)}) {
		t.Fatal("numeric object key must not equal an array index")
	}
	if !path.HasPrefix(path[:3]) || path.HasPrefix(payload.Path{payload.Key("a")}) {
		t.Fatal("typed prefix comparison is wrong")
	}
	if key, ok := path[0].KeyValue(); !ok || key != "a.b" {
		t.Fatalf("KeyValue() = %q, %v", key, ok)
	}
	if index, ok := path[4].IndexValue(); !ok || index != 0 {
		t.Fatalf("IndexValue() = %d, %v", index, ok)
	}
	if _, ok := payload.Index(-1).IndexValue(); ok {
		t.Fatal("a negative array index must be invalid")
	}

	clone := path.Clone()
	clone[0] = payload.Key("changed")
	if path[0] == clone[0] {
		t.Fatal("Clone returned aliased path storage")
	}
}

func TestScanEnumeratesValueStringsWithRawContext(t *testing.T) {
	body := []byte(" \n{\n  \"a\\/b\": {\"arr\": [17, \"line\\n\\u4e16\\u754c\"]},\n  \"key-only\": false\n}\t")
	doc := mustScanObject(t, body, payload.ScanOptions{})
	if doc.RootKind() != payload.KindObject {
		t.Fatalf("RootKind() = %s", doc.RootKind())
	}
	root := doc.RootSpan()
	if got := string(body[root.Start:root.End]); !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") {
		t.Fatalf("RootSpan() mismatch selected_len=%d", len(got))
	}

	tokens := doc.Strings()
	if len(tokens) != 1 {
		t.Fatalf("Strings() returned %d tokens; object keys must not be tokens", len(tokens))
	}
	token := tokens[0]
	wantPath := payload.Path{payload.Key("a/b"), payload.Key("arr"), payload.Index(1)}
	if !token.Path.Equal(wantPath) {
		t.Fatalf("token path = %s, want %s", token.Path, wantPath)
	}
	if token.Value != "line\n世界" {
		t.Fatalf("decoded value mismatch: got_len=%d", len(token.Value))
	}
	if token.ParentKind != payload.KindArray || token.Depth != 4 {
		t.Fatalf("context = parent %s depth %d, want array depth 4", token.ParentKind, token.Depth)
	}
	raw, err := doc.RawString(token)
	if err != nil {
		t.Fatal(err)
	}
	wantRaw := `"line` + string('\\') + `n` + string('\\') + `u4e16` + string('\\') + `u754c"`
	if got := string(raw); got != wantRaw {
		t.Fatalf("raw token mismatch: got_len=%d want_len=%d", len(got), len(wantRaw))
	}
	if token.Span.Len() != len(raw) || !bytes.Equal(raw, body[token.Span.Start:token.Span.End]) {
		t.Fatal("raw span does not refer to the original body")
	}
	if got := doc.StringsAt(wantPath); len(got) != 1 || got[0].Value != token.Value {
		t.Fatalf("StringsAt() mismatch: count=%d", len(got))
	}

	// Returned path storage is independent from the document's index.
	tokens[0].Path[0] = payload.Key("mutated")
	again := mustStringAt(t, doc, wantPath)
	if !again.Path.Equal(wantPath) {
		t.Fatal("caller mutation changed the document index")
	}
}

func TestStringKeyContextIsBoundedNormalizedAndValueFree(t *testing.T) {
	body := []byte(`{"API-Key":"first","outer":{"token":["second",{"inner":"third"}]},"bad key":{"SK":"fourth"},"token":{"bad key":{"worse.key":["fifth"]}}}`)
	doc := mustScanObject(t, body, payload.ScanOptions{})
	if doc.StringCount() != 5 {
		t.Fatalf("StringCount() = %d, want 5", doc.StringCount())
	}

	cases := []struct {
		index     int
		immediate string
		ancestors []string
	}{
		{index: 0, immediate: "api_key"},
		{index: 1, ancestors: []string{"token", "outer"}},
		{index: 2, immediate: "inner", ancestors: []string{"token", "outer"}},
		{index: 3, immediate: "sk"},
		{index: 4, ancestors: []string{"token"}},
	}
	for _, testCase := range cases {
		context, ok := doc.StringKeyContextAt(testCase.index)
		if !ok {
			t.Fatalf("context %d unavailable", testCase.index)
		}
		if context.ImmediateKey != testCase.immediate || int(context.AncestorCount) != len(testCase.ancestors) {
			t.Fatalf("context %d metadata mismatch", testCase.index)
		}
		for ancestorIndex, want := range testCase.ancestors {
			if context.Ancestors[ancestorIndex] != want {
				t.Fatalf("context %d ancestor %d mismatch", testCase.index, ancestorIndex)
			}
		}
	}
	if _, ok := doc.StringKeyContextAt(-1); ok {
		t.Fatal("negative string index returned context")
	}
	if _, ok := doc.StringKeyContextAt(doc.StringCount()); ok {
		t.Fatal("out-of-range string index returned context")
	}

	deep := mustScanObject(t, []byte(`{"one":{"two":{"three":{"four":{"five":{"six":"value"}}}}}}`), payload.ScanOptions{})
	bounded, ok := deep.StringKeyContextAt(0)
	if !ok || bounded.ImmediateKey != "six" || bounded.AncestorCount != payload.MaxContextAncestors {
		t.Fatal("deep field context was not bounded")
	}
	wantAncestors := []string{"five", "four", "three", "two"}
	for index, want := range wantAncestors {
		if bounded.Ancestors[index] != want {
			t.Fatalf("bounded ancestor %d mismatch", index)
		}
	}
}

func TestScanRootDocumentAndObjectValidation(t *testing.T) {
	validRoots := []struct {
		body string
		kind payload.Kind
	}{
		{`null`, payload.KindNull},
		{`true`, payload.KindBoolean},
		{`9007199254740993`, payload.KindNumber},
		{`"root"`, payload.KindString},
		{`["root"]`, payload.KindArray},
		{" \r\n{}\t", payload.KindObject},
	}
	for index, tc := range validRoots {
		doc, err := payload.Scan(context.Background(), []byte(tc.body), payload.ScanOptions{})
		if err != nil {
			t.Errorf("Scan root index=%d body_len=%d: %v", index, len(tc.body), err)
			continue
		}
		if doc.RootKind() != tc.kind {
			t.Errorf("Scan root index=%d kind=%s want=%s", index, doc.RootKind(), tc.kind)
		}
		_, objectErr := payload.ScanObject(context.Background(), []byte(tc.body), payload.ScanOptions{})
		if tc.kind == payload.KindObject && objectErr != nil {
			t.Errorf("ScanObject root index=%d body_len=%d: %v", index, len(tc.body), objectErr)
		}
		if tc.kind != payload.KindObject && !errors.Is(objectErr, payload.ErrRootNotObject) {
			t.Errorf("ScanObject root index=%d error=%v want=ErrRootNotObject", index, objectErr)
		}
	}

	invalid := []string{
		``, ` `, `{} {}`, `[] trailing`, `{"a":}`, `{"a":1,}`, `[1,]`,
		`{"a":"bad\x"}`, `{"a":"unterminated}`, `01`, `1.`, `1e`, `-`,
		"{\"a\":\"line\nbreak\"}",
	}
	for index, body := range invalid {
		if _, err := payload.Scan(context.Background(), []byte(body), payload.ScanOptions{}); !errors.Is(err, payload.ErrInvalidJSON) {
			t.Errorf("invalid JSON index=%d body_len=%d error=%v want=ErrInvalidJSON", index, len(body), err)
		}
	}
}

func TestReplacePreservesUnselectedBytes(t *testing.T) {
	body := []byte(` {
  "big": 9007199254740993,
  "exponent": -1.2300e+09,
  "html": "<&>",
  "escapes": "quote:\" slash:\/ backslash:\\ ctl:\b\f\n\r\t unicode:☺",
  "duplicate": "first",
  "duplicate": "second",
  "surrogate": "\ud800",
  "unicode": "你好 😀",
  "target": "replace me"
}
`)
	original := append([]byte(nil), body...)
	doc := mustScanObject(t, body, payload.ScanOptions{})
	target := mustStringAt(t, doc, payload.Path{payload.Key("target")})

	replacement := `<tag>& "quoted" 世界`
	out, changed, err := doc.Replace(context.Background(), []payload.Replacement{{Token: target, Value: replacement}})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !changed {
		t.Fatal("Replace reported unchanged")
	}
	if sameBacking(out, body) {
		t.Fatal("changed output unexpectedly aliases input")
	}
	if !bytes.Equal(body, original) {
		t.Fatal("Replace mutated its input")
	}

	want := bytes.Replace(body, []byte(`"replace me"`), []byte(`"<tag>& \"quoted\" 世界"`), 1)
	if !bytes.Equal(out, want) {
		t.Fatalf("only selected raw span may change: got_len=%d want_len=%d", len(out), len(want))
	}
	if !json.Valid(out) {
		t.Fatalf("output is invalid JSON: output_len=%d", len(out))
	}
	for index, preserved := range [][]byte{
		[]byte(`9007199254740993`),
		[]byte(`-1.2300e+09`),
		[]byte(`"<&>"`),
		[]byte(`slash:\/`),
		[]byte(`unicode:☺`),
		[]byte(`"duplicate": "first"`),
		[]byte(`"duplicate": "second"`),
		[]byte(`"surrogate": "\ud800"`),
		[]byte(`"unicode": "你好 😀"`),
	} {
		if !bytes.Contains(out, preserved) {
			t.Errorf("preserved byte fixture %d missing from output", index)
		}
	}
	if !bytes.Contains(out, []byte(`<tag>&`)) {
		t.Fatalf("replacement HTML characters were escaped: output_len=%d", len(out))
	}
}

func TestUnchangedReturnsOriginalBackingBytes(t *testing.T) {
	body := []byte(`{"escaped":"same` + string('\\') + `u0020value","n":1.0}`)
	doc := mustScanObject(t, body, payload.ScanOptions{})

	out, changed, err := doc.Replace(context.Background(), nil)
	if err != nil || changed {
		t.Fatalf("empty Replace = changed %v, err %v", changed, err)
	}
	if !bytes.Equal(out, body) || !sameBacking(out, body) {
		t.Fatal("empty replacement did not return original slice")
	}

	token := mustStringAt(t, doc, payload.Path{payload.Key("escaped")})
	if token.Value != "same value" {
		t.Fatalf("decoded value mismatch: got_len=%d", len(token.Value))
	}
	out, changed, err = doc.Replace(context.Background(), []payload.Replacement{{Token: token, Value: token.Value}})
	if err != nil || changed {
		t.Fatalf("same-value Replace = changed %v, err %v", changed, err)
	}
	if !bytes.Equal(out, body) || !sameBacking(out, body) {
		t.Fatal("same-value replacement normalized bytes instead of retaining input")
	}
	wireEscape := []byte(`same` + string('\\') + `u0020value`)
	if !bytes.Contains(out, wireEscape) {
		t.Fatal("same-value replacement did not preserve original escape")
	}
}

func TestMultipleReplacementsAreOrderedTransactionally(t *testing.T) {
	body := []byte(`{"a":"one","nested":["two",{"x":"three"}],"keep":"four"}`)
	original := append([]byte(nil), body...)
	doc := mustScanObject(t, body, payload.ScanOptions{})
	a := mustStringAt(t, doc, payload.Path{payload.Key("a")})
	two := mustStringAt(t, doc, payload.Path{payload.Key("nested"), payload.Index(0)})
	three := mustStringAt(t, doc, payload.Path{payload.Key("nested"), payload.Index(1), payload.Key("x")})

	// Deliberately reverse document order; Replace sorts a private copy.
	replacements := []payload.Replacement{
		{Token: three, Value: "3<&>"},
		{Token: two, Value: "line\n2"},
		{Token: a, Value: `"1"`},
	}
	out, changed, err := doc.Replace(context.Background(), replacements)
	if err != nil || !changed {
		t.Fatalf("Replace = changed %v, err %v", changed, err)
	}
	const want = `{"a":"\"1\"","nested":["line\n2",{"x":"3<&>"}],"keep":"four"}`
	if string(out) != want {
		t.Fatalf("Replace mismatch: got_len=%d want_len=%d", len(out), len(want))
	}
	if !bytes.Equal(body, original) {
		t.Fatal("transaction mutated the source body")
	}
	if replacements[0].Token.Value != "three" || replacements[2].Token.Value != "one" {
		t.Fatal("Replace mutated or reordered caller replacements")
	}
}

func TestDuplicateKeysRemainDistinctTokens(t *testing.T) {
	body := []byte(`{"a":"first","a":"second","0":"object-zero","arr":["array-zero"]}`)
	doc := mustScanObject(t, body, payload.ScanOptions{})
	duplicates := doc.StringsAt(payload.Path{payload.Key("a")})
	if len(duplicates) != 2 || duplicates[0].Value != "first" || duplicates[1].Value != "second" {
		t.Fatalf("duplicate token mismatch: count=%d", len(duplicates))
	}
	if _, err := doc.StringAt(payload.Path{payload.Key("a")}); !errors.Is(err, payload.ErrPathAmbiguous) {
		t.Fatalf("StringAt duplicate error = %v", err)
	}
	if _, err := doc.StringAt(payload.Path{payload.Key("missing")}); !errors.Is(err, payload.ErrPathNotFound) {
		t.Fatalf("StringAt missing error = %v", err)
	}
	if len(doc.StringsAt(payload.Path{payload.Index(0)})) != 0 {
		t.Fatal("root numeric key was confused with an array index")
	}

	out, changed, err := doc.Replace(context.Background(), []payload.Replacement{
		{Token: duplicates[0], Value: "FIRST"},
		{Token: duplicates[1], Value: "SECOND"},
	})
	if err != nil || !changed {
		t.Fatalf("Replace duplicates = changed %v, err %v", changed, err)
	}
	const want = `{"a":"FIRST","a":"SECOND","0":"object-zero","arr":["array-zero"]}`
	if string(out) != want {
		t.Fatalf("Replace duplicates mismatch: got_len=%d want_len=%d", len(out), len(want))
	}
}

func TestOverlappingAndInvalidReplacementsAreRejected(t *testing.T) {
	body := []byte(`{"a":"one","b":"two"}`)
	original := append([]byte(nil), body...)
	doc := mustScanObject(t, body, payload.ScanOptions{})
	a := mustStringAt(t, doc, payload.Path{payload.Key("a")})

	out, changed, err := doc.Replace(context.Background(), []payload.Replacement{
		{Token: a, Value: "first"},
		{Token: a, Value: "second"},
	})
	if !errors.Is(err, payload.ErrOverlappingReplacements) || out != nil || changed {
		t.Fatalf("overlap = out_len %d, changed %v, err %v", len(out), changed, err)
	}
	if !bytes.Equal(body, original) {
		t.Fatal("failed transaction mutated input")
	}

	modified := a
	modified.Span.Start++
	if out, changed, err = doc.Replace(context.Background(), []payload.Replacement{{Token: modified, Value: "x"}}); !errors.Is(err, payload.ErrInvalidToken) || out != nil || changed {
		t.Fatalf("modified token = out_len %d, changed %v, err %v", len(out), changed, err)
	}

	other := mustScanObject(t, []byte(`{"a":"one"}`), payload.ScanOptions{})
	foreign := mustStringAt(t, other, payload.Path{payload.Key("a")})
	if _, _, err = doc.Replace(context.Background(), []payload.Replacement{{Token: foreign, Value: "x"}}); !errors.Is(err, payload.ErrInvalidToken) {
		t.Fatalf("foreign token error = %v", err)
	}
}

func TestScanLimits(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		body := []byte(`{"a":"b"}`)
		_, err := payload.Scan(context.Background(), body, payload.ScanOptions{Limits: payload.Limits{MaxBodyBytes: len(body) - 1}})
		if !errors.Is(err, payload.ErrBodyTooLarge) {
			t.Fatalf("error = %v", err)
		}
		if _, err = payload.Scan(context.Background(), body, payload.ScanOptions{Limits: payload.Limits{MaxBodyBytes: len(body)}}); err != nil {
			t.Fatalf("exact limit rejected: %v", err)
		}
	})

	t.Run("depth", func(t *testing.T) {
		_, err := payload.Scan(context.Background(), []byte(`[[["x"]]]`), payload.ScanOptions{Limits: payload.Limits{MaxDepth: 2}})
		if !errors.Is(err, payload.ErrDepthLimit) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("nodes", func(t *testing.T) {
		_, err := payload.Scan(context.Background(), []byte(`[0,1]`), payload.ScanOptions{Limits: payload.Limits{MaxNodes: 2}})
		if !errors.Is(err, payload.ErrNodeLimit) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("string value", func(t *testing.T) {
		_, err := payload.Scan(context.Background(), []byte(`{"a":"four"}`), payload.ScanOptions{Limits: payload.Limits{MaxStringBytes: 3}})
		if !errors.Is(err, payload.ErrStringTooLarge) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("object key", func(t *testing.T) {
		_, err := payload.Scan(context.Background(), []byte(`{"four":0}`), payload.ScanOptions{Limits: payload.Limits{MaxStringBytes: 3}})
		if !errors.Is(err, payload.ErrStringTooLarge) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("negative", func(t *testing.T) {
		_, err := payload.Scan(context.Background(), []byte(`null`), payload.ScanOptions{Limits: payload.Limits{MaxDepth: -1}})
		if !errors.Is(err, payload.ErrInvalidLimits) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestHardScanLimitsCannotBeRaised(t *testing.T) {
	defaults := payload.DefaultLimits()
	if defaults.MaxBodyBytes != 32<<20 || defaults.MaxDepth != 128 ||
		defaults.MaxNodes != 250_000 || defaults.MaxStructuralBytes != 128<<20 ||
		defaults.MaxStringBytes != 8<<20 || defaults.MaxReplacements != 100_000 ||
		defaults.MaxReplacementBytes != 32<<20 {
		t.Fatalf("unexpected hard defaults: %+v", defaults)
	}

	cases := []payload.Limits{
		{MaxBodyBytes: defaults.MaxBodyBytes + 1},
		{MaxDepth: defaults.MaxDepth + 1},
		{MaxNodes: defaults.MaxNodes + 1},
		{MaxStructuralBytes: defaults.MaxStructuralBytes + 1},
		{MaxStringBytes: defaults.MaxStringBytes + 1},
		{MaxReplacements: defaults.MaxReplacements + 1},
		{MaxReplacementBytes: defaults.MaxReplacementBytes + 1},
	}
	for _, limits := range cases {
		if _, err := limits.Normalized(); !errors.Is(err, payload.ErrInvalidLimits) {
			t.Errorf("Normalized(%+v) error = %v, want ErrInvalidLimits", limits, err)
		}
	}
}

func TestStructuralRetentionLimit(t *testing.T) {
	_, err := payload.ScanObject(
		context.Background(),
		[]byte(`{"a":"b"}`),
		payload.ScanOptions{Limits: payload.Limits{MaxStructuralBytes: 1_000}},
	)
	if !errors.Is(err, payload.ErrStructuralLimit) {
		t.Fatalf("error = %v, want ErrStructuralLimit", err)
	}
}

func wideDeepStringBody(depth, leaves int) []byte {
	var body strings.Builder
	body.Grow(depth*6 + leaves*4 + 1)
	for range depth {
		body.WriteString(`{"k":`)
	}
	body.WriteByte('[')
	for index := 0; index < leaves; index++ {
		if index != 0 {
			body.WriteByte(',')
		}
		body.WriteString(`"x"`)
	}
	body.WriteByte(']')
	for range depth {
		body.WriteByte('}')
	}
	return []byte(body.String())
}

func scanStringStats(t *testing.T, depth, leaves int) (stringsFound, retained int) {
	t.Helper()
	document := mustScanObject(t, wideDeepStringBody(depth, leaves), payload.ScanOptions{})
	if _, ok := document.StringMetadataAt(leaves - 1); !ok {
		t.Fatalf("last string metadata unavailable at depth %d with %d leaves", depth, leaves)
	}
	return document.StringCount(), document.StructuralBytes()
}

func TestScannerStringRetentionScalesWithNodesNotDepthProduct(t *testing.T) {
	const leaves = 4_000
	shallowCount, shallowRetained := scanStringStats(t, 8, leaves)
	deepCount, deepRetained := scanStringStats(t, 96, leaves)
	if shallowCount != leaves || deepCount != leaves {
		t.Fatalf("string counts = shallow %d, deep %d; want %d", shallowCount, deepCount, leaves)
	}
	if deepRetained > shallowRetained+1<<20 {
		t.Fatalf("deep scan retained %d bytes versus shallow %d", deepRetained, shallowRetained)
	}

	wideCount, wideRetained := scanStringStats(t, 96, 2*leaves)
	if wideCount != 2*leaves {
		t.Fatalf("wide string count = %d, want %d", wideCount, 2*leaves)
	}
	if wideRetained > deepRetained*5/2 {
		t.Fatalf("doubling string nodes grew retention from %d to %d", deepRetained, wideRetained)
	}
}

var scannerDocumentSink *payload.Document

func scannerAllocatedBytesPerScan(t *testing.T, depth, leaves int) int64 {
	t.Helper()
	body := wideDeepStringBody(depth, leaves)
	result := testing.Benchmark(func(benchmark *testing.B) {
		for range benchmark.N {
			document, err := payload.ScanObject(context.Background(), body, payload.ScanOptions{})
			if err != nil {
				benchmark.Fatal(err)
			}
			scannerDocumentSink = document
		}
	})
	return result.AllocedBytesPerOp()
}

func TestScannerStringAllocationDoesNotScaleByLeafDepth(t *testing.T) {
	const leaves = 1_000
	shallow := scannerAllocatedBytesPerScan(t, 8, leaves)
	deep := scannerAllocatedBytesPerScan(t, 96, leaves)
	wide := scannerAllocatedBytesPerScan(t, 96, 2*leaves)
	if deep > shallow*2 {
		t.Fatalf("deep scan allocated %d bytes versus shallow %d", deep, shallow)
	}
	if wide > deep*5/2 {
		t.Fatalf("doubling string nodes grew allocations from %d to %d", deep, wide)
	}
}

func TestReplacementLimits(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		body := []byte(`{"a":"x","b":"y"}`)
		doc := mustScanObject(t, body, payload.ScanOptions{Limits: payload.Limits{MaxReplacements: 1}})
		tokens := doc.Strings()
		out, changed, err := doc.Replace(context.Background(), []payload.Replacement{
			{Token: tokens[0], Value: "X"},
			{Token: tokens[1], Value: "Y"},
		})
		if !errors.Is(err, payload.ErrReplacementLimit) || out != nil || changed {
			t.Fatalf("Replace = out_len %d, changed %v, err %v", len(out), changed, err)
		}
	})

	t.Run("individual string", func(t *testing.T) {
		body := []byte(`{"a":"x"}`)
		doc := mustScanObject(t, body, payload.ScanOptions{Limits: payload.Limits{MaxStringBytes: 3}})
		token := mustStringAt(t, doc, payload.Path{payload.Key("a")})
		_, _, err := doc.Replace(context.Background(), []payload.Replacement{{Token: token, Value: "four"}})
		if !errors.Is(err, payload.ErrStringTooLarge) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("encoded bytes", func(t *testing.T) {
		body := []byte(`{"a":"x"}`)
		doc := mustScanObject(t, body, payload.ScanOptions{Limits: payload.Limits{MaxReplacementBytes: 4}})
		token := mustStringAt(t, doc, payload.Path{payload.Key("a")})
		_, _, err := doc.Replace(context.Background(), []payload.Replacement{{Token: token, Value: "abc"}})
		if !errors.Is(err, payload.ErrReplacementLimit) {
			t.Fatalf("error = %v", err)
		}
		out, changed, err := doc.Replace(context.Background(), []payload.Replacement{{Token: token, Value: "ab"}})
		if err != nil || !changed || string(out) != `{"a":"ab"}` {
			t.Fatalf("exact budget = out_len %d, changed %v, err %v", len(out), changed, err)
		}
	})
}

type cancelAfterChecks struct {
	done   chan struct{}
	checks int
	after  int
}

func newCancelAfterChecks(after int) *cancelAfterChecks {
	return &cancelAfterChecks{done: make(chan struct{}), after: after}
}

func (c *cancelAfterChecks) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelAfterChecks) Done() <-chan struct{} {
	c.checks++
	if c.checks == c.after {
		close(c.done)
	}
	return c.done
}
func (c *cancelAfterChecks) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}
func (c *cancelAfterChecks) Value(any) any { return nil }

func TestContextCancellation(t *testing.T) {
	t.Run("before scan", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := payload.Scan(ctx, []byte(`{"a":"b"}`), payload.ScanOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("during long string", func(t *testing.T) {
		body := []byte(`{"a":"` + strings.Repeat("x", 8*1024) + `"}`)
		ctx := newCancelAfterChecks(2)
		_, err := payload.Scan(ctx, body, payload.ScanOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v (checks %d)", err, ctx.checks)
		}
	})

	t.Run("before replacement", func(t *testing.T) {
		body := []byte(`{"a":"b"}`)
		doc := mustScanObject(t, body, payload.ScanOptions{})
		token := mustStringAt(t, doc, payload.Path{payload.Key("a")})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, changed, err := doc.Replace(ctx, []payload.Replacement{{Token: token, Value: "c"}})
		if !errors.Is(err, context.Canceled) || out != nil || changed {
			t.Fatalf("Replace = out_len %d, changed %v, err %v", len(out), changed, err)
		}
	})
}
