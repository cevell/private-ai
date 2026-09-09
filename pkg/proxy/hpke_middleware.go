package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cevell/private-ai/pkg/crypto"
	wirev1 "github.com/cevell/private-ai/pkg/proto/v1"
	"github.com/cevell/private-ai/pkg/system"
)

// HPKEContext encapsulates the encryption state and client session for an incoming request.
type HPKEContext struct {
	Session    *crypto.HPKESession
	IsProtobuf bool
	ProtoReq   *wirev1.EncryptedInferenceRequest
}

// UnwrapHPKERequest inspects rawBody and contentType. It strictly enforces binary HPKE encryption.
// Supports both Protobuf outer envelopes (application/x-protobuf) and binary envelopes (application/octet-stream).
// Optional expectedBindingHash verifies cryptographic attestation binding.
// ZERO fallback to unencrypted plaintext is permitted.
func UnwrapHPKERequest(hpkePrivKey [32]byte, rawBody []byte, contentType string, expectedBindingHash ...[]byte) ([]byte, *HPKEContext, error) {
	ct := strings.ToLower(contentType)
	if !strings.Contains(ct, "application/octet-stream") &&
		!strings.Contains(ct, "application/x-cevell-hpke") &&
		!strings.Contains(ct, "application/x-protobuf") {
		return nil, nil, fmt.Errorf("invalid Content-Type %q: inference endpoints strictly require application/x-protobuf or application/octet-stream", contentType)
	}

	var bindingHash []byte
	if len(expectedBindingHash) > 0 {
		bindingHash = expectedBindingHash[0]
	}

	// 1. If explicitly application/x-protobuf, unwrap as Protobuf
	if strings.Contains(ct, "application/x-protobuf") {
		plaintext, session, protoReq, err := crypto.UnwrapProtoHPKERequest(hpkePrivKey, rawBody, bindingHash)
		if err != nil {
			return nil, nil, fmt.Errorf("unwrapping protobuf HPKE request: %w", err)
		}
		return plaintext, &HPKEContext{
			Session:    session,
			IsProtobuf: true,
			ProtoReq:   protoReq,
		}, nil
	}

	// 2. For application/octet-stream or application/x-cevell-hpke:
	// First check if payload is a protobuf EncryptedInferenceRequest
	plaintext, session, protoReq, err := crypto.UnwrapProtoHPKERequest(hpkePrivKey, rawBody, bindingHash)
	if err == nil {
		return plaintext, &HPKEContext{
			Session:    session,
			IsProtobuf: true,
			ProtoReq:   protoReq,
		}, nil
	}

	// Fall back to raw binary HPKE envelope
	plaintext, session, err = crypto.UnwrapBinaryHPKERequest(hpkePrivKey, rawBody)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrapping binary HPKE request: %w", err)
	}

	return plaintext, &HPKEContext{
		Session:    session,
		IsProtobuf: false,
	}, nil
}

// hpkeResponseWriter wraps http.ResponseWriter to encrypt responses back to the client using
// monotonic binary AEAD frames or Protobuf frames over HTTP chunked streaming.
type hpkeResponseWriter struct {
	w             http.ResponseWriter
	session       *crypto.HPKESession
	flusher       http.Flusher
	statusCode    int
	headerWritten bool
	isStreaming   bool
	isProtobuf    bool
	nonSSEBuf     bytes.Buffer
	sseBuf        bytes.Buffer
	onActivity    func()
}

// newHPKEResponseWriter creates a response writer that emits binary AEAD frames or Protobuf frames.
func newHPKEResponseWriter(w http.ResponseWriter, session *crypto.HPKESession, isProtobuf ...bool) *hpkeResponseWriter {
	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	protoMode := false
	if len(isProtobuf) > 0 {
		protoMode = isProtobuf[0]
	}
	return &hpkeResponseWriter{
		w:          w,
		session:    session,
		flusher:    flusher,
		statusCode: http.StatusOK,
		isProtobuf: protoMode,
	}
}

func (rw *hpkeResponseWriter) Header() http.Header {
	return rw.w.Header()
}

func (rw *hpkeResponseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	if rw.headerWritten {
		return
	}

	upstreamCT := strings.ToLower(rw.w.Header().Get("Content-Type"))
	if strings.Contains(upstreamCT, "text/event-stream") || rw.isStreaming {
		rw.isStreaming = true
	}

	// Enforce wire Content-Type
	if rw.isProtobuf {
		rw.w.Header().Set("Content-Type", "application/x-protobuf")
	} else {
		rw.w.Header().Set("Content-Type", "application/octet-stream")
	}

	if rw.isStreaming {
		rw.w.Header().Del("Content-Length")
		rw.w.WriteHeader(statusCode)
		rw.headerWritten = true
		if rw.flusher != nil {
			rw.flusher.Flush()
		}
	}
	// For non-streaming, defer WriteHeader until Finish() so Content-Length of frame can be set.
}

const (
	maxSSEBufferSize = 1024 * 1024 // 1MB buffer ceiling to prevent memory exhaustion
)

func (rw *hpkeResponseWriter) Write(p []byte) (int, error) {
	if rw.session == nil {
		return 0, fmt.Errorf("hpkeResponseWriter: missing encryption session")
	}

	if rw.onActivity != nil {
		rw.onActivity()
	}

	if !rw.headerWritten {
		upstreamCT := strings.ToLower(rw.w.Header().Get("Content-Type"))
		if strings.Contains(upstreamCT, "text/event-stream") {
			rw.isStreaming = true
			rw.WriteHeader(rw.statusCode)
		}
	}

	if rw.isStreaming {
		rw.sseBuf.Write(p)
		rw.processSSEBuffer(false)
		return len(p), nil
	}

	// Buffer non-streaming body for single-pass frame encryption without arbitrary size limit
	return rw.nonSSEBuf.Write(p)
}

func (rw *hpkeResponseWriter) Flush() {
	if rw.session != nil && rw.isStreaming {
		rw.processSSEBuffer(false)
	}
	if rw.flusher != nil {
		rw.flusher.Flush()
	}
}

// processSSEBuffer extracts complete SSE events, encrypts them into binary AEAD frames, and writes them.
func (rw *hpkeResponseWriter) processSSEBuffer(drainAll bool) {
	for {
		bufBytes := rw.sseBuf.Bytes()
		if len(bufBytes) == 0 {
			break
		}

		crlfIdx := bytes.Index(bufBytes, []byte("\r\n\r\n"))
		lfIdx := bytes.Index(bufBytes, []byte("\n\n"))

		delimIdx := -1
		delimLen := 0

		if crlfIdx != -1 && (lfIdx == -1 || crlfIdx < lfIdx) {
			delimIdx = crlfIdx
			delimLen = 4
		} else if lfIdx != -1 {
			delimIdx = lfIdx
			delimLen = 2
		}

		if delimIdx == -1 {
			if drainAll && len(bufBytes) > 0 {
				rw.writeEncryptedSSEBlock(bufBytes)
				rw.sseBuf.Reset()
			} else if rw.sseBuf.Len() > maxSSEBufferSize {
				system.LogError("[HPKE] SSE buffer exceeded %d bytes without delimiter; forcing chunk flush", maxSSEBufferSize)
				rw.writeEncryptedSSEBlock(bufBytes)
				rw.sseBuf.Reset()
			}
			break
		}

		eventBlock := bufBytes[:delimIdx]
		rw.sseBuf.Next(delimIdx + delimLen)
		rw.writeEncryptedSSEBlock(eventBlock)
	}

	if rw.flusher != nil {
		rw.flusher.Flush()
	}
}

func (rw *hpkeResponseWriter) writeEncryptedSSEBlock(block []byte) {
	normalized := strings.ReplaceAll(string(block), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	var dataLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")))
		}
	}

	if len(dataLines) == 0 {
		return
	}

	payload := strings.Join(dataLines, "\n")
	if payload == "" {
		return
	}

	if rw.isProtobuf {
		if payload == "[DONE]" {
			frame, err := rw.session.EncryptProtoFrame(wirev1.FrameType_FRAME_TYPE_STREAM_END, []byte("[DONE]"))
			if err != nil {
				system.LogError("[HPKE] Failed to encrypt stream end proto frame: %v", err)
				return
			}
			_, _ = rw.w.Write(frame)
		} else {
			frame, err := rw.session.EncryptProtoFrame(wirev1.FrameType_FRAME_TYPE_TOKEN_DELTA, []byte(payload))
			if err != nil {
				system.LogError("[HPKE] Failed to encrypt token delta proto frame: %v", err)
				return
			}
			_, _ = rw.w.Write(frame)
		}
	} else {
		if payload == "[DONE]" {
			frame, err := rw.session.EncryptFrame(crypto.FrameTypeStreamEnd, []byte("[DONE]"))
			if err != nil {
				system.LogError("[HPKE] Failed to encrypt stream end frame: %v", err)
				return
			}
			_, _ = rw.w.Write(frame)
		} else {
			frame, err := rw.session.EncryptFrame(crypto.FrameTypeTokenDelta, []byte(payload))
			if err != nil {
				system.LogError("[HPKE] Failed to encrypt token delta frame: %v", err)
				return
			}
			_, _ = rw.w.Write(frame)
		}
	}
}

// Finish completes the response, encrypting buffered non-streaming data into binary AEAD frames or Protobuf frames.
func (rw *hpkeResponseWriter) Finish() {
	if rw.session == nil {
		return
	}
	defer rw.session.Zeroize()

	if rw.isStreaming {
		rw.processSSEBuffer(true)
		return
	}

	rawBody := rw.nonSSEBuf.Bytes()
	if len(rawBody) == 0 {
		if rw.isProtobuf {
			rw.w.Header().Set("Content-Type", "application/x-protobuf")
		} else {
			rw.w.Header().Set("Content-Type", "application/octet-stream")
		}
		rw.w.WriteHeader(rw.statusCode)
		return
	}

	if rw.isProtobuf {
		frameType := wirev1.FrameType_FRAME_TYPE_COMPLETION
		if rw.statusCode >= 400 {
			frameType = wirev1.FrameType_FRAME_TYPE_ERROR
		}

		frame, err := rw.session.EncryptProtoFrame(frameType, rawBody)
		if err != nil {
			system.LogError("[HPKE] Failed to encrypt non-streaming proto frame: %v", err)
			rw.w.Header().Set("Content-Type", "application/x-protobuf")
			rw.w.WriteHeader(http.StatusInternalServerError)
			return
		}

		endFrame, err := rw.session.EncryptProtoFrame(wirev1.FrameType_FRAME_TYPE_STREAM_END, []byte("[DONE]"))
		if err != nil {
			system.LogError("[HPKE] Failed to encrypt end proto frame: %v", err)
			return
		}

		totalPayload := append(frame, endFrame...)
		rw.w.Header().Set("Content-Type", "application/x-protobuf")
		rw.w.Header().Set("Content-Length", strconv.Itoa(len(totalPayload)))
		rw.w.WriteHeader(rw.statusCode)
		_, _ = rw.w.Write(totalPayload)
	} else {
		frameType := crypto.FrameTypeCompletion
		if rw.statusCode >= 400 {
			frameType = crypto.FrameTypeError
		}

		frame, err := rw.session.EncryptFrame(frameType, rawBody)
		if err != nil {
			system.LogError("[HPKE] Failed to encrypt non-streaming frame: %v", err)
			rw.w.Header().Set("Content-Type", "application/octet-stream")
			rw.w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Also emit end-of-stream frame to terminate the binary frame stream
		endFrame, err := rw.session.EncryptFrame(crypto.FrameTypeStreamEnd, []byte("[DONE]"))
		if err != nil {
			system.LogError("[HPKE] Failed to encrypt end frame: %v", err)
			return
		}

		totalPayload := append(frame, endFrame...)
		rw.w.Header().Set("Content-Type", "application/octet-stream")
		rw.w.Header().Set("Content-Length", strconv.Itoa(len(totalPayload)))
		rw.w.WriteHeader(rw.statusCode)
		_, _ = rw.w.Write(totalPayload)
	}

	if rw.flusher != nil {
		rw.flusher.Flush()
	}
}
