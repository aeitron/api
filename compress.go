package apigateway

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// DefaultMinCompressLength defines the minimum payload size in bytes to trigger on-the-fly compression.
	// Payloads smaller than 512 bytes are served uncompressed to avoid compression framing overhead.
	DefaultMinCompressLength = 512

	EncodingGzip     = "gzip"
	EncodingDeflate  = "deflate"
	EncodingIdentity = "identity"
)

// Compressible MIME prefixes and types
var compressibleContentTypes = []string{
	"application/json",
	"application/javascript",
	"text/javascript",
	"application/xml",
	"text/xml",
	"application/x-yaml",
	"text/yaml",
	"text/plain",
	"text/html",
	"text/css",
	"text/csv",
	"image/svg+xml",
}

// IsCompressibleContentType checks if the given Content-Type header is eligible for text compression.
func IsCompressibleContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	ct := strings.ToLower(contentType)
	// Strip optional parameters (e.g., "; charset=utf-8")
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	for _, prefix := range compressibleContentTypes {
		if strings.HasPrefix(ct, prefix) || ct == prefix {
			return true
		}
	}
	return false
}

// SelectEncoding inspects the client's Accept-Encoding header and chooses the optimal supported algorithm.
func SelectEncoding(acceptEncoding string) string {
	ae := strings.ToLower(acceptEncoding)
	if ae == "" || ae == "identity" {
		return ""
	}

	// Prioritize gzip (universal, RFC 1952), then deflate (RFC 1951)
	if strings.Contains(ae, "gzip") || strings.Contains(ae, "*") {
		return EncodingGzip
	}
	if strings.Contains(ae, "deflate") {
		return EncodingDeflate
	}
	return ""
}

var (
	gzipWriterPool = sync.Pool{
		New: func() any {
			// Level 6 (DefaultCompression) balances CPU vs compression ratio
			w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			return w
		},
	}
	deflateWriterPool = sync.Pool{
		New: func() any {
			w, _ := flate.NewWriter(io.Discard, flate.DefaultCompression)
			return w
		},
	}
)

// CompressGzip compresses a byte slice using pooled gzip writers with zero memory leaks.
func CompressGzip(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzipWriterPool.Get().(*gzip.Writer)
	gw.Reset(&buf)
	_, err := gw.Write(src)
	if err != nil {
		gzipWriterPool.Put(gw)
		return nil, err
	}
	if err := gw.Close(); err != nil {
		gzipWriterPool.Put(gw)
		return nil, err
	}
	gzipWriterPool.Put(gw)
	return buf.Bytes(), nil
}

// CompressDeflate compresses a byte slice using pooled flate writers.
func CompressDeflate(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	dw := deflateWriterPool.Get().(*flate.Writer)
	dw.Reset(&buf)
	_, err := dw.Write(src)
	if err != nil {
		deflateWriterPool.Put(dw)
		return nil, err
	}
	if err := dw.Close(); err != nil {
		deflateWriterPool.Put(dw)
		return nil, err
	}
	deflateWriterPool.Put(dw)
	return buf.Bytes(), nil
}

type countWriter struct {
	w     io.Writer
	count *atomic.Int64
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.count.Add(int64(n))
	return n, err
}

// CompressingResponseWriter transparently negotiates and streams compressed responses.
type CompressingResponseWriter struct {
	http.ResponseWriter
	acceptEncoding string
	minSize        int
	statusCode     int

	buf           bytes.Buffer
	countWriter   *countWriter
	gzipWriter    *gzip.Writer
	flateWriter   *flate.Writer
	encoding      string
	started       bool
	headerWritten bool

	uncompressedBytes atomic.Int64
	compressedBytes   atomic.Int64
}

// NewCompressingResponseWriter wraps an http.ResponseWriter with on-the-fly streaming compression.
func NewCompressingResponseWriter(w http.ResponseWriter, r *http.Request, minSize int) *CompressingResponseWriter {
	if minSize <= 0 {
		minSize = DefaultMinCompressLength
	}
	return &CompressingResponseWriter{
		ResponseWriter: w,
		acceptEncoding: r.Header.Get("Accept-Encoding"),
		minSize:        minSize,
		statusCode:     http.StatusOK,
	}
}

func (cw *CompressingResponseWriter) WriteHeader(code int) {
	if cw.headerWritten {
		return
	}
	cw.statusCode = code
	if cw.ResponseWriter.Header().Get("Content-Encoding") != "" {
		cw.started = true
		cw.ResponseWriter.WriteHeader(code)
		cw.headerWritten = true
	}
}

func (cw *CompressingResponseWriter) shouldCompress() bool {
	if cw.statusCode == http.StatusNoContent || cw.statusCode == http.StatusNotModified {
		return false
	}

	header := cw.ResponseWriter.Header()
	if header.Get("Content-Encoding") != "" {
		return false // already compressed by upstream or pre-compressed cache hit
	}

	ctype := header.Get("Content-Type")
	if ctype == "" && cw.buf.Len() > 0 {
		ctype = http.DetectContentType(cw.buf.Bytes())
	}
	if !IsCompressibleContentType(ctype) {
		return false
	}

	return SelectEncoding(cw.acceptEncoding) != ""
}

func (cw *CompressingResponseWriter) startCompression() error {
	cw.started = true
	header := cw.ResponseWriter.Header()

	if !cw.shouldCompress() {
		return fmt.Errorf("response not eligible for compression")
	}

	enc := SelectEncoding(cw.acceptEncoding)
	cw.encoding = enc

	addVaryHeader(cw.ResponseWriter, "Accept-Encoding")
	header.Set("Content-Encoding", enc)
	header.Del("Content-Length")

	// Convert strong ETag to weak ETag (RFC 9110 Section 8.8.1)
	if etag := header.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
		header.Set("ETag", "W/"+etag)
	}

	if !cw.headerWritten {
		cw.ResponseWriter.WriteHeader(cw.statusCode)
		cw.headerWritten = true
	}

	cw.countWriter = &countWriter{w: cw.ResponseWriter, count: &cw.compressedBytes}
	if enc == EncodingGzip {
		gw := gzipWriterPool.Get().(*gzip.Writer)
		gw.Reset(cw.countWriter)
		cw.gzipWriter = gw
		if cw.buf.Len() > 0 {
			_, err := gw.Write(cw.buf.Bytes())
			cw.buf.Reset()
			return err
		}
	} else if enc == EncodingDeflate {
		dw := deflateWriterPool.Get().(*flate.Writer)
		dw.Reset(cw.countWriter)
		cw.flateWriter = dw
		if cw.buf.Len() > 0 {
			_, err := dw.Write(cw.buf.Bytes())
			cw.buf.Reset()
			return err
		}
	}

	return nil
}

func (cw *CompressingResponseWriter) Write(b []byte) (int, error) {
	cw.uncompressedBytes.Add(int64(len(b)))

	// If streaming compressor is already active
	if cw.gzipWriter != nil {
		return cw.gzipWriter.Write(b)
	}
	if cw.flateWriter != nil {
		return cw.flateWriter.Write(b)
	}

	// If response is already encoded (e.g. pre-compressed cache hit or upstream compressed)
	if cw.ResponseWriter.Header().Get("Content-Encoding") != "" {
		cw.started = true
		if !cw.headerWritten {
			cw.ResponseWriter.WriteHeader(cw.statusCode)
			cw.headerWritten = true
		}
		return cw.ResponseWriter.Write(b)
	}

	// If already determined not compressible
	if cw.started {
		if !cw.headerWritten {
			cw.ResponseWriter.WriteHeader(cw.statusCode)
			cw.headerWritten = true
		}
		return cw.ResponseWriter.Write(b)
	}

	// Buffer until minSize is reached
	cw.buf.Write(b)
	if cw.buf.Len() >= cw.minSize {
		if err := cw.startCompression(); err != nil {
			// Not compressible, flush uncompressed
			cw.started = true
			if !cw.headerWritten {
				cw.ResponseWriter.WriteHeader(cw.statusCode)
				cw.headerWritten = true
			}
			_, _ = cw.ResponseWriter.Write(cw.buf.Bytes())
			cw.buf.Reset()
		}
	}

	return len(b), nil
}

// Close finalizes and flushes any active compression streams.
func (cw *CompressingResponseWriter) Close() error {
	if cw.gzipWriter != nil {
		err := cw.gzipWriter.Close()
		gzipWriterPool.Put(cw.gzipWriter)
		cw.gzipWriter = nil
		return err
	}
	if cw.flateWriter != nil {
		err := cw.flateWriter.Close()
		deflateWriterPool.Put(cw.flateWriter)
		cw.flateWriter = nil
		return err
	}

	// If compression never started (total response < minSize or not compressible)
	if !cw.started {
		cw.started = true
		if !cw.headerWritten {
			cw.ResponseWriter.WriteHeader(cw.statusCode)
			cw.headerWritten = true
		}
		if cw.buf.Len() > 0 {
			_, err := cw.ResponseWriter.Write(cw.buf.Bytes())
			cw.buf.Reset()
			return err
		}
	}

	return nil
}

func (cw *CompressingResponseWriter) Flush() {
	if !cw.started {
		if !cw.shouldCompress() {
			cw.started = true
			if !cw.headerWritten {
				cw.ResponseWriter.WriteHeader(cw.statusCode)
				cw.headerWritten = true
			}
			if cw.buf.Len() > 0 {
				_, _ = cw.ResponseWriter.Write(cw.buf.Bytes())
				cw.buf.Reset()
			}
		} else if cw.buf.Len() > 0 {
			if err := cw.startCompression(); err != nil {
				cw.started = true
				if !cw.headerWritten {
					cw.ResponseWriter.WriteHeader(cw.statusCode)
					cw.headerWritten = true
				}
				_, _ = cw.ResponseWriter.Write(cw.buf.Bytes())
				cw.buf.Reset()
			}
		}
	}
	if cw.gzipWriter != nil {
		_ = cw.gzipWriter.Flush()
	}
	if cw.flateWriter != nil {
		_ = cw.flateWriter.Flush()
	}
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (cw *CompressingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := cw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijacker not supported")
}

// Encoding returns the applied content encoding (e.g. "gzip", "deflate", or "").
func (cw *CompressingResponseWriter) Encoding() string {
	return cw.encoding
}

// UncompressedBytes returns the total uncompressed bytes received.
func (cw *CompressingResponseWriter) UncompressedBytes() int64 {
	return cw.uncompressedBytes.Load()
}

// CompressedBytes returns the total compressed bytes written to wire.
func (cw *CompressingResponseWriter) CompressedBytes() int64 {
	return cw.compressedBytes.Load()
}

// StatusCode returns the HTTP response status code recorded by the wrapper.
func (cw *CompressingResponseWriter) StatusCode() int {
	return cw.statusCode
}
