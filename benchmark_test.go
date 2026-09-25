package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

func BenchmarkSanitizeRequestSizes(b *testing.B) {
	plugin, err := buildPlugin(nil, b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	filter, ok := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok || filter == nil {
		b.Fatal("request interceptor is not privacyFilterPlugin")
	}

	for _, size := range []int{512 << 10, 1 << 20, 4 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			body := benchmarkRequestBody(size)
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				result, err := filter.sanitizeRequest(context.Background(), "openai", body)
				if err != nil {
					b.Fatal(err)
				}
				if !result.changed || result.findings != 1 {
					b.Fatalf("result changed=%t findings=%d targets=%d body_len=%d, want one redaction", result.changed, result.findings, result.targets, len(result.body))
				}
			}
		})
	}
}

func benchmarkRequestBody(size int) []byte {
	prefix := []byte(`{"model":"privacy-benchmark","messages":[{"role":"user","content":"`)
	suffix := []byte(` benchmark@user.example"}]}`)
	if size < len(prefix)+len(suffix) {
		size = len(prefix) + len(suffix)
	}
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte{'a'}, size-len(prefix)-len(suffix))...)
	body = append(body, suffix...)
	return body
}
