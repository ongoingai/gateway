package proxy

import (
	"bytes"
	"net/http"
	"strings"
)

func IsSSE(headers http.Header) bool {
	contentType := strings.ToLower(headers.Get("Content-Type"))
	return strings.Contains(contentType, "text/event-stream")
}

type StreamBuffer struct {
	maxBytes  int
	body      bytes.Buffer
	chunks    int
	truncated bool
}

func newStreamBuffer(maxBytes int) StreamBuffer {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return StreamBuffer{maxBytes: maxBytes}
}

// Add appends an immutable copy of each chunk so captured streaming traces
// preserve exact wire ordering without retaining caller-owned buffers.
func (b *StreamBuffer) Add(chunk []byte) {
	b.chunks++

	remaining := b.maxBytes - b.body.Len()
	if remaining <= 0 {
		if len(chunk) > 0 {
			b.truncated = true
		}
		return
	}
	if len(chunk) > remaining {
		b.truncated = true
		chunk = chunk[:remaining]
	}
	_, _ = b.body.Write(chunk)
}

func (b *StreamBuffer) Bytes() []byte {
	out := b.body.Bytes()
	copied := make([]byte, len(out))
	copy(copied, out)
	return copied
}

func (b *StreamBuffer) Count() int {
	return b.chunks
}

func (b *StreamBuffer) Truncated() bool {
	return b.truncated
}
