package payload_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

func FuzzScanNoPanic(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`null`),
		[]byte(`{"a":"b"}`),
		[]byte(`{"a":"\ud800","a":"second"}`),
		[]byte(`["x",{"nested":"<&>"},9007199254740993,1e+9]`),
		[]byte("{\n  \"escaped\": \"quote:\\\" slash:\\/ unicode:\\u263a\"\n}"),
		{0xff, 0x00, '{', '}'},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		limits := payload.Limits{
			MaxBodyBytes:        1 << 20,
			MaxDepth:            64,
			MaxNodes:            10_000,
			MaxStringBytes:      1 << 18,
			MaxReplacements:     32,
			MaxReplacementBytes: 1 << 18,
		}
		doc, err := payload.Scan(context.Background(), body, payload.ScanOptions{Limits: limits})
		if err != nil {
			return
		}
		if !json.Valid(body) {
			t.Fatalf("scanner accepted bytes encoding/json rejects: input_len=%d", len(body))
		}

		tokens := doc.Strings()
		replacements := make([]payload.Replacement, 0, len(tokens))
		for i, token := range tokens {
			if i >= limits.MaxReplacements {
				break
			}
			if i%2 == 0 {
				replacements = append(replacements, payload.Replacement{
					Token: token,
					Value: token.Value + "<&>",
				})
			}
		}
		out, changed, err := doc.Replace(context.Background(), replacements)
		if err != nil {
			// A generated valid input can be close enough to a configured string
			// budget that adding the suffix legitimately exceeds it.
			return
		}
		if !json.Valid(out) {
			t.Fatalf("replacement produced invalid JSON: output_len=%d", len(out))
		}
		if !changed {
			if !bytes.Equal(out, body) || !sameBacking(out, body) {
				t.Fatal("unchanged fuzz case did not return original backing bytes")
			}
		}
	})
}
