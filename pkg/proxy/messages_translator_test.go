package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cevell/private-ai/pkg/auth"
	"github.com/cevell/private-ai/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertMessagesToOpenAI(t *testing.T) {
	req := []byte(`{"model":"claude-3-7-sonnet","messages":[{"role":"user","content":"hi"}]}`)
	openAIBytes, stream, model, err := ConvertMessagesToOpenAI(req)
	require.NoError(t, err)
	assert.False(t, stream)
	assert.Equal(t, "claude-3-7-sonnet", model)
	assert.Contains(t, string(openAIBytes), `"content":"hi"`)
}

func TestConvertAnthropicToOpenAI(t *testing.T) {
	anthropicReq := []byte(`{
		"model": "claude-3-7-sonnet-20250219",
		"system": "You are a helpful assistant.",
		"max_tokens": 1000,
		"thinking": {
			"type": "enabled",
			"budget_tokens": 2000
		},
		"tools": [
			{
				"name": "get_weather",
				"description": "Fetch current weather",
				"input_schema": {
					"type": "object",
					"properties": {
						"city": {"type": "string"}
					},
					"required": ["city"]
				}
			}
		],
		"tool_choice": {"type": "auto"},
		"messages": [
			{"role": "user", "content": "What is the weather in Tokyo?"},
			{
				"role": "assistant",
				"content": [
					{"type": "text", "text": "Let me check for you."},
					{
						"type": "tool_use",
						"id": "toolu_01",
						"name": "get_weather",
						"input": {"city": "Tokyo"}
					}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "tool_result",
						"tool_use_id": "toolu_01",
						"content": "{\"temp\": 22}"
					}
				]
			}
		],
		"stream": true
	}`)

	openAIBytes, stream, model, err := ConvertAnthropicToOpenAI(anthropicReq)
	require.NoError(t, err)
	assert.True(t, stream)
	assert.Equal(t, "claude-3-7-sonnet-20250219", model)

	var converted map[string]any
	err = json.Unmarshal(openAIBytes, &converted)
	require.NoError(t, err)

	// Verify model and max tokens
	assert.Equal(t, "claude-3-7-sonnet-20250219", converted["model"])
	assert.Equal(t, float64(3000), converted["max_completion_tokens"])

	// Verify messages: system prompt inserted as first message
	msgs, ok := converted["messages"].([]any)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(msgs), 4)

	sysMsg := msgs[0].(map[string]any)
	assert.Equal(t, "system", sysMsg["role"])
	assert.Equal(t, "You are a helpful assistant.", sysMsg["content"])

	userMsg := msgs[1].(map[string]any)
	assert.Equal(t, "user", userMsg["role"])
	assert.Equal(t, "What is the weather in Tokyo?", userMsg["content"])

	// Assistant message with tool_calls
	asstMsg := msgs[2].(map[string]any)
	assert.Equal(t, "assistant", asstMsg["role"])
	assert.Equal(t, "Let me check for you.", asstMsg["content"])
	toolCalls, ok := asstMsg["tool_calls"].([]any)
	require.True(t, ok)
	require.Len(t, toolCalls, 1)
	tc := toolCalls[0].(map[string]any)
	assert.Equal(t, "toolu_01", tc["id"])
	fn := tc["function"].(map[string]any)
	assert.Equal(t, "get_weather", fn["name"])
	assert.Contains(t, fn["arguments"], "Tokyo")

	// Tool result message
	toolResultMsg := msgs[3].(map[string]any)
	assert.Equal(t, "tool", toolResultMsg["role"])
	assert.Equal(t, "toolu_01", toolResultMsg["tool_call_id"])
	assert.Contains(t, toolResultMsg["content"], "22")

	// Verify tools schema
	tools, ok := converted["tools"].([]any)
	require.True(t, ok)
	require.Len(t, tools, 1)
	firstTool := tools[0].(map[string]any)
	assert.Equal(t, "function", firstTool["type"])
	toolFn := firstTool["function"].(map[string]any)
	assert.Equal(t, "get_weather", toolFn["name"])
	assert.Equal(t, "Fetch current weather", toolFn["description"])

	// Verify tool_choice
	assert.Equal(t, "auto", converted["tool_choice"])
}

func TestConvertOpenAIToAnthropicResponse(t *testing.T) {
	// 1. Response with reasoning_content and tool_calls
	openAIResp := []byte(`{
		"id": "chatcmpl-test123",
		"model": "deepseek-r1",
		"choices": [
			{
				"index": 0,
				"finish_reason": "tool_calls",
				"message": {
					"role": "assistant",
					"reasoning_content": "User wants temperature in Paris. I should call get_temperature.",
					"content": "Checking Paris temperature.",
					"tool_calls": [
						{
							"id": "call_paris_1",
							"type": "function",
							"function": {
								"name": "get_temperature",
								"arguments": "{\"city\":\"Paris\"}"
							}
						}
					]
				}
			}
		],
		"usage": {
			"prompt_tokens": 15,
			"completion_tokens": 40
		}
	}`)

	anthropicBytes, err := ConvertOpenAIToAnthropicResponse(openAIResp, "deepseek-r1")
	require.NoError(t, err)

	var aResp AnthropicResponse
	err = json.Unmarshal(anthropicBytes, &aResp)
	require.NoError(t, err)

	assert.Equal(t, "chatcmpl-test123", aResp.ID)
	assert.Equal(t, "message", aResp.Type)
	assert.Equal(t, "assistant", aResp.Role)
	require.NotNil(t, aResp.StopReason)
	assert.Equal(t, "tool_use", *aResp.StopReason)
	assert.Equal(t, 15, aResp.Usage.InputTokens)
	assert.Equal(t, 40, aResp.Usage.OutputTokens)

	// Content blocks must contain: thinking, text, and tool_use
	require.Len(t, aResp.Content, 3)

	thinkingBlock := aResp.Content[0]
	assert.Equal(t, "thinking", thinkingBlock["type"])
	assert.Contains(t, thinkingBlock["thinking"], "User wants temperature in Paris")

	textBlock := aResp.Content[1]
	assert.Equal(t, "text", textBlock["type"])
	assert.Equal(t, "Checking Paris temperature.", textBlock["text"])

	toolBlock := aResp.Content[2]
	assert.Equal(t, "tool_use", toolBlock["type"])
	assert.Equal(t, "call_paris_1", toolBlock["id"])
	assert.Equal(t, "get_temperature", toolBlock["name"])
	inputMap := toolBlock["input"].(map[string]any)
	assert.Equal(t, "Paris", inputMap["city"])
}

func TestConvertOpenAIToAnthropicResponse_ThinkTagFallback(t *testing.T) {
	// Response where model emitted raw <think>...</think> in content
	openAIResp := []byte(`{
		"id": "chatcmpl-tagfallback",
		"model": "deepseek-r1",
		"choices": [
			{
				"index": 0,
				"finish_reason": "stop",
				"message": {
					"role": "assistant",
					"content": "<think>\nThinking through this math problem:\n2 + 2 = 4\n</think>\nThe answer is 4."
				}
			}
		]
	}`)

	anthropicBytes, err := ConvertOpenAIToAnthropicResponse(openAIResp, "deepseek-r1")
	require.NoError(t, err)

	var aResp AnthropicResponse
	err = json.Unmarshal(anthropicBytes, &aResp)
	require.NoError(t, err)

	require.NotNil(t, aResp.StopReason)
	assert.Equal(t, "end_turn", *aResp.StopReason)
	require.Len(t, aResp.Content, 2)

	assert.Equal(t, "thinking", aResp.Content[0]["type"])
	assert.Contains(t, aResp.Content[0]["thinking"], "2 + 2 = 4")

	assert.Equal(t, "text", aResp.Content[1]["type"])
	assert.Equal(t, "The answer is 4.", aResp.Content[1]["text"])
}

func TestAnthropicStreamTranslator(t *testing.T) {
	translator := NewAnthropicStreamTranslator("deepseek-r1")

	// 1. First chunk with reasoning
	c1 := []byte(`{"choices":[{"delta":{"reasoning_content":"Step 1..."}}]}`)
	events1 := translator.ProcessOpenAIChunk(c1)
	require.NotEmpty(t, events1)
	joined1 := strings.Join(events1, "")
	assert.Contains(t, joined1, "event: message_start")
	assert.Contains(t, joined1, "event: content_block_start")
	assert.Contains(t, joined1, "thinking")
	assert.Contains(t, joined1, "event: content_block_delta")
	assert.Contains(t, joined1, "thinking_delta")
	assert.Contains(t, joined1, "Step 1...")

	// 2. Second chunk switching to text
	c2 := []byte(`{"choices":[{"delta":{"content":"Hello world"}}]}`)
	events2 := translator.ProcessOpenAIChunk(c2)
	require.NotEmpty(t, events2)
	joined2 := strings.Join(events2, "")
	assert.Contains(t, joined2, "event: content_block_stop") // Closes thinking block
	assert.Contains(t, joined2, "event: content_block_start") // Starts text block
	assert.Contains(t, joined2, "event: content_block_delta")
	assert.Contains(t, joined2, "text_delta")
	assert.Contains(t, joined2, "Hello world")

	// 3. Terminal chunk
	cDone := []byte(`[DONE]`)
	eventsDone := translator.ProcessOpenAIChunk(cDone)
	require.NotEmpty(t, eventsDone)
	joinedDone := strings.Join(eventsDone, "")
	assert.Contains(t, joinedDone, "event: content_block_stop") // Closes text block
	assert.Contains(t, joinedDone, "event: message_delta")
	assert.Contains(t, joinedDone, "event: message_stop")

	// 4. Subsequent DONE chunk should be ignored (idempotent termination)
	eventsDoneAgain := translator.ProcessOpenAIChunk(cDone)
	assert.Empty(t, eventsDoneAgain)
	assert.True(t, translator.IsDone())
}

func TestExtractThinkingFromContent(t *testing.T) {
	// Standard case
	content := "<think>pondering logic</think>Result is ready."
	thinking, clean := ExtractThinkingFromContent(content)
	assert.Equal(t, "pondering logic", thinking)
	assert.Equal(t, "Result is ready.", clean)

	// No thinking tags
	contentNoThink := "Just plain output."
	thinking2, clean2 := ExtractThinkingFromContent(contentNoThink)
	assert.Equal(t, "", thinking2)
	assert.Equal(t, "Just plain output.", clean2)

	// Unterminated tag
	contentUnterm := "Beginning <think>still reasoning"
	thinking3, clean3 := ExtractThinkingFromContent(contentUnterm)
	assert.Equal(t, "still reasoning", thinking3)
	assert.Equal(t, "Beginning", clean3)
}

func TestAnthropicProxyServerE2E_Unary(t *testing.T) {
	upstreamResponse := `{
		"id": "chatcmpl-anthropic-unary",
		"object": "chat.completion",
		"created": 1726000000,
		"model": "deepseek-ai/DeepSeek-R1",
		"choices": [{
			"index": 0,
			"message": {
				"role": "assistant",
				"reasoning_content": "Internal thought process",
				"content": "42 is the answer."
			},
			"finish_reason": "stop"
		}],
		"usage": {
			"prompt_tokens": 15,
			"completion_tokens": 25,
			"total_tokens": 40
		}
	}`

	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify upstream receives translated OpenAI request
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, _ := io.ReadAll(r.Body)
		var openAIReq map[string]any
		err := json.Unmarshal(body, &openAIReq)
		assert.NoError(t, err)
		assert.Equal(t, "claude-3-7-sonnet-20250219", openAIReq["model"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	// 1. Client generates ephemeral X25519 keypair and creates binary HPKE request directed to /v1/messages
	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	anthropicPayload := []byte(`{
		"model": "claude-3-7-sonnet-20250219",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "What is the meaning of life?"}],
		"thinking": {"type": "enabled", "budget_tokens": 1000}
	}`)
	wireBytes, clientSession, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, anthropicPayload)
	require.NoError(t, err)

	// 2. Gateway/Client signs wire ciphertext body with Ed25519
	nowTs := time.Now().Unix()
	sig := auth.SignPayload(clientPriv, "POST", "/v1/messages", "req-anthropic-1", nowTs, "nonce-ant-1", wireBytes)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(wireBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-ant-1", "req-anthropic-1"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// 3. Assert response is HTTP 200 with encrypted octet-stream
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))

	// 4. Client parses binary frames
	frames, err := parseBinaryFrames(rec.Body.Bytes())
	require.NoError(t, err)
	require.Len(t, frames, 2) // FrameTypeCompletion + FrameTypeStreamEnd

	// 5. Client decrypts completion frame
	fType1, seq1, payload1, err := clientSession.DecryptFrame(frames[0])
	require.NoError(t, err)
	assert.Equal(t, crypto.FrameTypeCompletion, fType1)
	assert.Equal(t, uint32(0), seq1)

	// 6. Verify decrypted payload is valid Anthropic Response schema
	var antResp AnthropicResponse
	err = json.Unmarshal(payload1, &antResp)
	require.NoError(t, err)
	assert.Equal(t, "message", antResp.Type)
	assert.Equal(t, "assistant", antResp.Role)
	assert.Equal(t, "deepseek-ai/DeepSeek-R1", antResp.Model)
	require.NotNil(t, antResp.StopReason)
	assert.Equal(t, "end_turn", *antResp.StopReason)

	// Verify both thinking block and text block exist
	require.Len(t, antResp.Content, 2)
	thinkingBlock := antResp.Content[0]
	assert.Equal(t, "thinking", thinkingBlock["type"])
	assert.Equal(t, "Internal thought process", thinkingBlock["thinking"])

	textBlock := antResp.Content[1]
	assert.Equal(t, "text", textBlock["type"])
	assert.Equal(t, "42 is the answer.", textBlock["text"])

	// 7. Verify stream end frame
	fType2, seq2, payload2, err := clientSession.DecryptFrame(frames[1])
	require.NoError(t, err)
	assert.Equal(t, crypto.FrameTypeStreamEnd, fType2)
	assert.Equal(t, uint32(1), seq2)
	assert.Equal(t, "[DONE]", string(payload2))
}

func TestAnthropicProxyServerE2E_Streaming(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		// 1. Thinking delta chunk from vLLM
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-stream\",\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking step 1\"}}]}\n\n"))
		flusher.Flush()

		// 2. Text delta chunk from vLLM
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-stream\",\"choices\":[{\"delta\":{\"content\":\"Final result\"}}]}\n\n"))
		flusher.Flush()

		// 3. Upstream stream completion
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	anthropicPayload := []byte(`{
		"model": "claude-3-7-sonnet-20250219",
		"max_tokens": 512,
		"messages": [{"role": "user", "content": "Compute result"}],
		"thinking": {"type": "enabled", "budget_tokens": 1000},
		"stream": true
	}`)
	wireBytes, clientSession, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, anthropicPayload)
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	sig := auth.SignPayload(clientPriv, "POST", "/v1/messages", "req-anthropic-stream", nowTs, "nonce-ant-s", wireBytes)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(wireBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-ant-s", "req-anthropic-stream"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))

	frames, err := parseBinaryFrames(rec.Body.Bytes())
	require.NoError(t, err)
	require.NotEmpty(t, frames)

	// Decrypt all frames and concatenate all event payloads
	var allDecryptedEvents string
	var foundStreamEnd bool
	for _, frame := range frames {
		fType, _, payload, err := clientSession.DecryptFrame(frame)
		require.NoError(t, err)
		if fType == crypto.FrameTypeStreamEnd {
			foundStreamEnd = true
			assert.Equal(t, "[DONE]", string(payload))
		} else if fType == crypto.FrameTypeTokenDelta {
			allDecryptedEvents += string(payload)
		}
	}

	assert.True(t, foundStreamEnd, "Must receive terminal stream end frame")
	assert.Contains(t, allDecryptedEvents, "event: message_start")
	assert.Contains(t, allDecryptedEvents, "event: content_block_start")
	assert.Contains(t, allDecryptedEvents, "thinking_delta")
	assert.Contains(t, allDecryptedEvents, "thinking step 1")
	assert.Contains(t, allDecryptedEvents, "text_delta")
	assert.Contains(t, allDecryptedEvents, "Final result")
	assert.Equal(t, 1, strings.Count(allDecryptedEvents, "event: message_stop"), "Must receive exactly one message_stop event")
	assert.Equal(t, 1, strings.Count(allDecryptedEvents, "event: message_delta"), "Must receive exactly one message_delta event")
}

