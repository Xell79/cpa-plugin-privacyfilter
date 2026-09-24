package privacyengine

import (
	"context"
	"testing"
)

func FuzzNoPanic(f *testing.F) {
	engine := customEngine(f, `
[[rules]]
id = "fuzz-capture"
regex = '''api[ _-]?key[=: ]*([A-Za-z0-9+/=_-]{4,})'''
keywords = ["api"]
`)
	for _, seed := range []string{
		"",
		"api keyABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"prefix token=abcDEF1234567890/xyzABC4567890== suffix",
		string([]byte{0xff, 0xfe, 'a', 'p', 'i', ' ', 'k', 'e', 'y'}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		_, _ = engine.Detect(context.Background(), input, RequestOptions{})
		_, _ = engine.Redact(context.Background(), input, RequestOptions{})
	})
}
