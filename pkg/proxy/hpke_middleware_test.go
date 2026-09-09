package proxy

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/cevell/private-ai/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestSession() *crypto.HPKESession {
	var respKey [32]byte
	var respIV [12]byte
	copy(respKey[:], []byte("01234567890123456789012345678901"))
	copy(respIV[:], []byte("012345678901"))
	return &crypto.HPKESession{
		ResponseKey: respKey,
		ResponseIV:  respIV,
	}
}

func TestHPKEResponseWriter_SSE_Delimiters(t *testing.T) {
	t.Run("Standard LF delimiter", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serverSession := createTestSession()
		clientSession := createTestSession()
		rw := newHPKEResponseWriter(rec, serverSession)

		rec.Header().Set("Content-Type", "text/event-stream")
		_, err := rw.Write([]byte("data: {\"token\":\"hello\"}\n\ndata: [DONE]\n\n"))
		require.NoError(t, err)
		rw.Finish()

		// Verify serverSession keys were securely zeroized
		assert.Equal(t, [32]byte{}, serverSession.ResponseKey)

		// Read binary frames written to recorder
		body := rec.Body.Bytes()
		require.True(t, len(body) > 0)

		// First frame: TokenDelta decrypted by client
		fType, seq, payload, err := clientSession.DecryptFrame(body[:crypto.BinaryFrameHeaderLen+17+crypto.GCMTagLen])
		require.NoError(t, err)
		assert.Equal(t, crypto.FrameTypeTokenDelta, fType)
		assert.Equal(t, uint32(0), seq)
		assert.Equal(t, "{\"token\":\"hello\"}", string(payload))
	})

	t.Run("CRLF delimiter", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serverSession := createTestSession()
		clientSession := createTestSession()
		rw := newHPKEResponseWriter(rec, serverSession)

		rec.Header().Set("Content-Type", "text/event-stream")
		_, err := rw.Write([]byte("data: {\"token\":\"world\"}\r\n\r\ndata: [DONE]\r\n\r\n"))
		require.NoError(t, err)
		rw.Finish()

		assert.Equal(t, [32]byte{}, serverSession.ResponseKey)

		body := rec.Body.Bytes()
		require.True(t, len(body) > 0)

		// First frame: TokenDelta decrypted by client
		fType, seq, payload, err := clientSession.DecryptFrame(body[:crypto.BinaryFrameHeaderLen+17+crypto.GCMTagLen])
		require.NoError(t, err)
		assert.Equal(t, crypto.FrameTypeTokenDelta, fType)
		assert.Equal(t, uint32(0), seq)
		assert.Equal(t, "{\"token\":\"world\"}", string(payload))
	})

	t.Run("Mixed LF and CRLF delimiters", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serverSession := createTestSession()
		clientSession := createTestSession()
		rw := newHPKEResponseWriter(rec, serverSession)

		rec.Header().Set("Content-Type", "text/event-stream")
		_, err := rw.Write([]byte("data: chunk1\r\n\r\ndata: chunk2\n\n"))
		require.NoError(t, err)
		rw.Finish()

		assert.Equal(t, [32]byte{}, serverSession.ResponseKey)

		body := rec.Body.Bytes()
		frame1Len := crypto.BinaryFrameHeaderLen + 6 + crypto.GCMTagLen
		fType1, _, payload1, err := clientSession.DecryptFrame(body[:frame1Len])
		require.NoError(t, err)
		assert.Equal(t, crypto.FrameTypeTokenDelta, fType1)
		assert.Equal(t, "chunk1", string(payload1))

		fType2, _, payload2, err := clientSession.DecryptFrame(body[frame1Len : frame1Len+frame1Len])
		require.NoError(t, err)
		assert.Equal(t, crypto.FrameTypeTokenDelta, fType2)
		assert.Equal(t, "chunk2", string(payload2))
	})

	t.Run("Multi-line data SSE event block joined with newline (PRX-04)", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serverSession := createTestSession()
		clientSession := createTestSession()
		rw := newHPKEResponseWriter(rec, serverSession)

		rec.Header().Set("Content-Type", "text/event-stream")
		sseInput := "data: {\"line\":1}\ndata: {\"line\":2}\n\ndata: [DONE]\n\n"
		_, err := rw.Write([]byte(sseInput))
		require.NoError(t, err)
		rw.Finish()

		body := rec.Body.Bytes()
		require.True(t, len(body) > 0)

		expectedPayload := "{\"line\":1}\n{\"line\":2}"
		frameLen := crypto.BinaryFrameHeaderLen + len(expectedPayload) + crypto.GCMTagLen
		fType, seq, payload, err := clientSession.DecryptFrame(body[:frameLen])
		require.NoError(t, err)
		assert.Equal(t, crypto.FrameTypeTokenDelta, fType)
		assert.Equal(t, uint32(0), seq)
		assert.Equal(t, expectedPayload, string(payload))

		endFrame := body[frameLen:]
		endType, endSeq, endPayload, err := clientSession.DecryptFrame(endFrame)
		require.NoError(t, err)
		assert.Equal(t, crypto.FrameTypeStreamEnd, endType)
		assert.Equal(t, uint32(1), endSeq)
		assert.Equal(t, "[DONE]", string(endPayload))
	})
}

func TestHPKEResponseWriter_SSE_BufferLimit(t *testing.T) {
	rec := httptest.NewRecorder()
	session := createTestSession()
	rw := newHPKEResponseWriter(rec, session)

	rec.Header().Set("Content-Type", "text/event-stream")

	// Write slightly more than maxSSEBufferSize (1MB) without any delimiter
	hugeChunk := bytes.Repeat([]byte("a"), maxSSEBufferSize+10)
	_, err := rw.Write(hugeChunk)
	require.NoError(t, err)

	// Verify that buffer did not grow unboundedly and was flushed/reset
	assert.True(t, rw.sseBuf.Len() < maxSSEBufferSize)
}

func TestHPKEResponseWriter_NonSSE_LargePayload(t *testing.T) {
	rec := httptest.NewRecorder()
	session := createTestSession()
	rw := newHPKEResponseWriter(rec, session)

	rec.Header().Set("Content-Type", "application/json")

	// Verify large non-streaming bodies (e.g. 33MB > previous 32MB cap) buffer without error
	largeChunk := make([]byte, 33*1024*1024)
	n, err := rw.Write(largeChunk)
	require.NoError(t, err)
	assert.Equal(t, len(largeChunk), n)
}
