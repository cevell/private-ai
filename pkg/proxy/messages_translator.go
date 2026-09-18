package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AnthropicRequest represents an incoming request using the Anthropic Messages API.
type AnthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []AnthropicMessage `json:"messages"`
	System      any                `json:"system,omitempty"` // string or []AnthropicContentBlock
	MaxTokens   int                `json:"max_tokens,omitempty"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	TopK        *int               `json:"top_k,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	Thinking    *AnthropicThinking `json:"thinking,omitempty"`
	Tools       []AnthropicTool    `json:"tools,omitempty"`
	ToolChoice  any                `json:"tool_choice,omitempty"`
	Metadata    map[string]any     `json:"metadata,omitempty"`
}

// AnthropicThinking represents thinking / extended reasoning budget configuration.
type AnthropicThinking struct {
	Type         string `json:"type"` // "enabled" or "disabled"
	BudgetTokens int    `json:"budget_tokens,omitempty"`
}

// AnthropicTool represents tool definitions in Anthropic format.
type AnthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

// AnthropicMessage represents an individual message in Anthropic format.
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []AnthropicContentBlock
}

// AnthropicContentBlock represents a polymorphic content block in Anthropic format.
type AnthropicContentBlock struct {
	Type      string         `json:"type"` // "text", "thinking", "tool_use", "tool_result", "image"
	Text      string         `json:"text,omitempty"`
	Thinking  string         `json:"thinking,omitempty"`
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Input     map[string]any `json:"input,omitempty"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	Content   any            `json:"content,omitempty"`
}

// AnthropicResponse represents a non-streaming Anthropic Messages API response.
type AnthropicResponse struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"` // "message"
	Role         string           `json:"role"` // "assistant"
	Content      []map[string]any `json:"content"`
	Model        string           `json:"model"`
	StopReason   *string          `json:"stop_reason"`
	StopSequence *string          `json:"stop_sequence"`
	Usage        AnthropicUsage   `json:"usage"`
}

// AnthropicUsage tracks token consumption in Anthropic format.
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ExtractThinkingFromContent parses raw <think>...</think> XML blocks if present.
func ExtractThinkingFromContent(content string) (string, string) {
	startIdx := strings.Index(content, "<think>")
	if startIdx == -1 {
		return "", content
	}

	endIdx := strings.Index(content, "</think>")
	if endIdx == -1 {
		// Unterminated thinking tag: treat text after <think> as thinking
		thinking := strings.TrimSpace(content[startIdx+len("<think>"):])
		clean := strings.TrimSpace(content[:startIdx])
		return thinking, clean
	}

	thinking := strings.TrimSpace(content[startIdx+len("<think>") : endIdx])
	clean := strings.TrimSpace(content[:startIdx] + content[endIdx+len("</think>"):])
	return thinking, clean
}

// ConvertMessagesToOpenAI translates a Messages API request into an OpenAI Chat Completions request.
func ConvertMessagesToOpenAI(messagesBody []byte) ([]byte, bool, string, error) {
	return ConvertAnthropicToOpenAI(messagesBody)
}

// ConvertAnthropicToOpenAI translates an Anthropic Messages API request into an OpenAI Chat Completions request.
func ConvertAnthropicToOpenAI(anthropicBody []byte) ([]byte, bool, string, error) {
	var req AnthropicRequest
	if err := json.Unmarshal(anthropicBody, &req); err != nil {
		return nil, false, "", fmt.Errorf("parsing Anthropic request JSON: %w", err)
	}

	openAIReq := map[string]any{
		"model":  req.Model,
		"stream": req.Stream,
	}

	if req.Temperature != nil {
		openAIReq["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		openAIReq["top_p"] = *req.TopP
	}
	if req.TopK != nil {
		openAIReq["top_k"] = *req.TopK
	}

	maxTokens := req.MaxTokens
	if req.Thinking != nil && req.Thinking.Type == "enabled" {
		if req.Thinking.BudgetTokens > 0 {
			openAIReq["max_completion_tokens"] = req.Thinking.BudgetTokens + maxTokens
		}
	} else if maxTokens > 0 {
		openAIReq["max_tokens"] = maxTokens
	}

	var openAIMessages []map[string]any

	// 1. Process System prompt if present
	if req.System != nil {
		systemText := ""
		switch s := req.System.(type) {
		case string:
			systemText = s
		case []any:
			var parts []string
			for _, item := range s {
				if m, ok := item.(map[string]any); ok {
					if txt, ok := m["text"].(string); ok {
						parts = append(parts, txt)
					}
				}
			}
			systemText = strings.Join(parts, "\n\n")
		}
		if systemText != "" {
			openAIMessages = append(openAIMessages, map[string]any{
				"role":    "system",
				"content": systemText,
			})
		}
	}

	// 2. Process conversation Messages
	for _, msg := range req.Messages {
		role := msg.Role
		switch c := msg.Content.(type) {
		case string:
			openAIMessages = append(openAIMessages, map[string]any{
				"role":    role,
				"content": c,
			})
		case []any:
			var textParts []string
			var toolCalls []map[string]any

			for _, item := range c {
				block, ok := item.(map[string]any)
				if !ok {
					continue
				}
				bType, _ := block["type"].(string)
				switch bType {
				case "text":
					if txt, ok := block["text"].(string); ok {
						textParts = append(textParts, txt)
					}
				case "tool_use":
					id, _ := block["id"].(string)
					name, _ := block["name"].(string)
					inputMap, _ := block["input"].(map[string]any)
					inputBytes, _ := json.Marshal(inputMap)
					toolCalls = append(toolCalls, map[string]any{
						"id":   id,
						"type": "function",
						"function": map[string]any{
							"name":      name,
							"arguments": string(inputBytes),
						},
					})
				case "tool_result":
					toolUseID, _ := block["tool_use_id"].(string)
					var resContent string
					switch res := block["content"].(type) {
					case string:
						resContent = res
					default:
						rb, _ := json.Marshal(res)
						resContent = string(rb)
					}
					openAIMessages = append(openAIMessages, map[string]any{
						"role":         "tool",
						"tool_call_id": toolUseID,
						"content":      resContent,
					})
				}
			}

			if len(toolCalls) > 0 {
				asstMsg := map[string]any{
					"role":       "assistant",
					"tool_calls": toolCalls,
				}
				if len(textParts) > 0 {
					asstMsg["content"] = strings.Join(textParts, "\n\n")
				}
				openAIMessages = append(openAIMessages, asstMsg)
			} else if len(textParts) > 0 {
				openAIMessages = append(openAIMessages, map[string]any{
					"role":    role,
					"content": strings.Join(textParts, "\n\n"),
				})
			}
		}
	}

	openAIReq["messages"] = openAIMessages

	// 3. Process Tools
	if len(req.Tools) > 0 {
		var openAITools []map[string]any
		for _, t := range req.Tools {
			openAITools = append(openAITools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  t.InputSchema,
				},
			})
		}
		openAIReq["tools"] = openAITools

		if req.ToolChoice != nil {
			switch tc := req.ToolChoice.(type) {
			case string:
				openAIReq["tool_choice"] = tc
			case map[string]any:
				tcType, _ := tc["type"].(string)
				switch tcType {
				case "auto":
					openAIReq["tool_choice"] = "auto"
				case "any":
					openAIReq["tool_choice"] = "required"
				case "tool":
					if name, ok := tc["name"].(string); ok {
						openAIReq["tool_choice"] = map[string]any{
							"type": "function",
							"function": map[string]any{
								"name": name,
							},
						}
					}
				}
			}
		}
	}

	outBytes, err := json.Marshal(openAIReq)
	if err != nil {
		return nil, false, "", fmt.Errorf("serializing converted OpenAI request: %w", err)
	}

	return outBytes, req.Stream, req.Model, nil
}

// ConvertOpenAIToAnthropicResponse translates a non-streaming OpenAI chat completion response to Anthropic message JSON.
func ConvertOpenAIToAnthropicResponse(openAIResp []byte, requestedModel string) ([]byte, error) {
	var resp map[string]any
	if err := json.Unmarshal(openAIResp, &resp); err != nil {
		return nil, fmt.Errorf("parsing OpenAI completion JSON: %w", err)
	}

	msgID, _ := resp["id"].(string)
	if msgID == "" {
		msgID = fmt.Sprintf("msg_%d", time.Now().UnixNano())
	}
	model, _ := resp["model"].(string)
	if model == "" {
		model = requestedModel
	}

	var contentBlocks []map[string]any
	var stopReason *string

	if choices, ok := resp["choices"].([]any); ok && len(choices) > 0 {
		if firstChoice, ok := choices[0].(map[string]any); ok {
			finishReason, _ := firstChoice["finish_reason"].(string)
			switch finishReason {
			case "tool_calls":
				sr := "tool_use"
				stopReason = &sr
			case "stop":
				sr := "end_turn"
				stopReason = &sr
			case "length":
				sr := "max_tokens"
				stopReason = &sr
			default:
				if finishReason != "" {
					stopReason = &finishReason
				}
			}

			if msg, ok := firstChoice["message"].(map[string]any); ok {
				// 1. Thinking / reasoning content
				reasoning, _ := msg["reasoning_content"].(string)
				rawContent, _ := msg["content"].(string)

				if reasoning == "" && rawContent != "" {
					parsedThinking, clean := ExtractThinkingFromContent(rawContent)
					if parsedThinking != "" {
						reasoning = parsedThinking
						rawContent = clean
					}
				}

				if reasoning != "" {
					contentBlocks = append(contentBlocks, map[string]any{
						"type":     "thinking",
						"thinking": reasoning,
					})
				}

				if rawContent != "" {
					contentBlocks = append(contentBlocks, map[string]any{
						"type": "text",
						"text": rawContent,
					})
				}

				// 2. Tool calls
				if tcs, ok := msg["tool_calls"].([]any); ok {
					for _, tcItem := range tcs {
						tc, ok := tcItem.(map[string]any)
						if !ok {
							continue
						}
						tcID, _ := tc["id"].(string)
						if fn, ok := tc["function"].(map[string]any); ok {
							fnName, _ := fn["name"].(string)
							fnArgsStr, _ := fn["arguments"].(string)
							var inputMap map[string]any
							if err := json.Unmarshal([]byte(fnArgsStr), &inputMap); err != nil {
								inputMap = map[string]any{"raw": fnArgsStr}
							}
							contentBlocks = append(contentBlocks, map[string]any{
								"type":  "tool_use",
								"id":    tcID,
								"name":  fnName,
								"input": inputMap,
							})
						}
					}
				}
			}
		}
	}

	usage := AnthropicUsage{}
	if u, ok := resp["usage"].(map[string]any); ok {
		if pt, ok := u["prompt_tokens"].(float64); ok {
			usage.InputTokens = int(pt)
		}
		if ct, ok := u["completion_tokens"].(float64); ok {
			usage.OutputTokens = int(ct)
		}
	}

	anthropicMsg := AnthropicResponse{
		ID:         msgID,
		Type:       "message",
		Role:       "assistant",
		Content:    contentBlocks,
		Model:      model,
		StopReason: stopReason,
		Usage:      usage,
	}

	return json.Marshal(anthropicMsg)
}

// AnthropicStreamTranslator manages the state machine for translating an OpenAI SSE stream to Anthropic SSE events.
type AnthropicStreamTranslator struct {
	mu             sync.Mutex
	model          string
	msgID          string
	messageStarted bool
	currentBlock   string // "thinking", "text", "tool_use", or ""
	blockIndex     int
	inThinkTag     bool
	thinkBuf       bytes.Buffer
	outputTokens   int
	inputTokens    int
	doneEmitted    bool
}

// NewAnthropicStreamTranslator initializes an SSE stream adapter.
func NewAnthropicStreamTranslator(model string) *AnthropicStreamTranslator {
	return &AnthropicStreamTranslator{
		model: model,
		msgID: fmt.Sprintf("msg_%d", time.Now().UnixNano()),
	}
}

// IsDone returns true if terminal stream events ([DONE]) have already been emitted.
func (ast *AnthropicStreamTranslator) IsDone() bool {
	ast.mu.Lock()
	defer ast.mu.Unlock()
	return ast.doneEmitted
}

// ProcessOpenAIChunk parses a single OpenAI SSE line (e.g. data: {"choices": ...}) and produces corresponding Anthropic SSE lines.
func (ast *AnthropicStreamTranslator) ProcessOpenAIChunk(openAIPayload []byte) []string {
	ast.mu.Lock()
	defer ast.mu.Unlock()

	trimmed := strings.TrimSpace(string(openAIPayload))
	if trimmed == "" || trimmed == "[DONE]" {
		if trimmed == "[DONE]" {
			if ast.doneEmitted {
				return nil
			}
			ast.doneEmitted = true
			var events []string
			if ast.currentBlock != "" {
				events = append(events, fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", ast.blockIndex))
				ast.currentBlock = ""
			}
			events = append(events, fmt.Sprintf("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":%d}}\n\n", ast.outputTokens))
			events = append(events, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
			return events
		}
		return nil
	}

	var chunk map[string]any
	if err := json.Unmarshal([]byte(trimmed), &chunk); err != nil {
		return nil
	}

	var events []string

	// 1. Emit message_start once at the start of the stream
	if !ast.messageStarted {
		ast.messageStarted = true
		startData := map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id":            ast.msgID,
				"type":          "message",
				"role":          "assistant",
				"content":       []any{},
				"model":         ast.model,
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage": map[string]any{
					"input_tokens":  ast.inputTokens,
					"output_tokens": 1,
				},
			},
		}
		sb, _ := json.Marshal(startData)
		events = append(events, fmt.Sprintf("event: message_start\ndata: %s\n\n", string(sb)))
	}

	choices, ok := chunk["choices"].([]any)
	if !ok || len(choices) == 0 {
		return events
	}
	firstChoice, ok := choices[0].(map[string]any)
	if !ok {
		return events
	}

	delta, ok := firstChoice["delta"].(map[string]any)
	if !ok {
		return events
	}

	// 2. Process Reasoning / Thinking Delta
	reasoningDelta, _ := delta["reasoning_content"].(string)
	contentDelta, _ := delta["content"].(string)

	// Fallback extraction for raw <think>...</think> in contentDelta
	if reasoningDelta == "" && contentDelta != "" {
		if strings.Contains(contentDelta, "<think>") {
			ast.inThinkTag = true
			contentDelta = strings.Replace(contentDelta, "<think>", "", 1)
		}
		if ast.inThinkTag {
			if strings.Contains(contentDelta, "</think>") {
				parts := strings.SplitN(contentDelta, "</think>", 2)
				reasoningDelta = parts[0]
				contentDelta = parts[1]
				ast.inThinkTag = false
			} else {
				reasoningDelta = contentDelta
				contentDelta = ""
			}
		}
	}

	if reasoningDelta != "" {
		ast.outputTokens++
		if ast.currentBlock != "thinking" {
			if ast.currentBlock != "" {
				events = append(events, fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", ast.blockIndex))
				ast.blockIndex++
			}
			ast.currentBlock = "thinking"
			startBlock := map[string]any{
				"type":  "content_block_start",
				"index": ast.blockIndex,
				"content_block": map[string]any{
					"type":     "thinking",
					"thinking": "",
				},
			}
			sb, _ := json.Marshal(startBlock)
			events = append(events, fmt.Sprintf("event: content_block_start\ndata: %s\n\n", string(sb)))
		}

		deltaBlock := map[string]any{
			"type":  "content_block_delta",
			"index": ast.blockIndex,
			"delta": map[string]any{
				"type":     "thinking_delta",
				"thinking": reasoningDelta,
			},
		}
		sb, _ := json.Marshal(deltaBlock)
		events = append(events, fmt.Sprintf("event: content_block_delta\ndata: %s\n\n", string(sb)))
	}

	// 3. Process Normal Text Delta
	if contentDelta != "" {
		ast.outputTokens++
		if ast.currentBlock != "text" {
			if ast.currentBlock != "" {
				events = append(events, fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", ast.blockIndex))
				ast.blockIndex++
			}
			ast.currentBlock = "text"
			startBlock := map[string]any{
				"type":  "content_block_start",
				"index": ast.blockIndex,
				"content_block": map[string]any{
					"type": "text",
					"text": "",
				},
			}
			sb, _ := json.Marshal(startBlock)
			events = append(events, fmt.Sprintf("event: content_block_start\ndata: %s\n\n", string(sb)))
		}

		deltaBlock := map[string]any{
			"type":  "content_block_delta",
			"index": ast.blockIndex,
			"delta": map[string]any{
				"type": "text_delta",
				"text": contentDelta,
			},
		}
		sb, _ := json.Marshal(deltaBlock)
		events = append(events, fmt.Sprintf("event: content_block_delta\ndata: %s\n\n", string(sb)))
	}

	// 4. Process Tool Call Delta
	if tcs, ok := delta["tool_calls"].([]any); ok && len(tcs) > 0 {
		ast.outputTokens++
		for _, tcItem := range tcs {
			tc, ok := tcItem.(map[string]any)
			if !ok {
				continue
			}
			tcID, _ := tc["id"].(string)
			if fn, ok := tc["function"].(map[string]any); ok {
				fnName, _ := fn["name"].(string)
				fnArgs, _ := fn["arguments"].(string)

				if ast.currentBlock != "tool_use" {
					if ast.currentBlock != "" {
						events = append(events, fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", ast.blockIndex))
						ast.blockIndex++
					}
					ast.currentBlock = "tool_use"
					startBlock := map[string]any{
						"type":  "content_block_start",
						"index": ast.blockIndex,
						"content_block": map[string]any{
							"type":  "tool_use",
							"id":    tcID,
							"name":  fnName,
							"input": map[string]any{},
						},
					}
					sb, _ := json.Marshal(startBlock)
					events = append(events, fmt.Sprintf("event: content_block_start\ndata: %s\n\n", string(sb)))
				}

				if fnArgs != "" {
					deltaBlock := map[string]any{
						"type":  "content_block_delta",
						"index": ast.blockIndex,
						"delta": map[string]any{
							"type":         "input_json_delta",
							"partial_json": fnArgs,
						},
					}
					sb, _ := json.Marshal(deltaBlock)
					events = append(events, fmt.Sprintf("event: content_block_delta\ndata: %s\n\n", string(sb)))
				}
			}
		}
	}

	return events
}

// messagesResponseWriter adapts reverseProxy responses into Messages API format before HPKE encryption.
type messagesResponseWriter struct {
	hpkeWriter    *hpkeResponseWriter
	model         string
	isStreaming   bool
	headerWritten bool
	translator    *AnthropicStreamTranslator
	buf           bytes.Buffer
	sseBuf        bytes.Buffer
	statusCode    int
}

// anthropicResponseWriter is an alias for backwards compatibility.
type anthropicResponseWriter = messagesResponseWriter

func newMessagesResponseWriter(hpkeWriter *hpkeResponseWriter, model string) *messagesResponseWriter {
	return &messagesResponseWriter{
		hpkeWriter: hpkeWriter,
		model:      model,
		translator: NewAnthropicStreamTranslator(model),
		statusCode: http.StatusOK,
	}
}

func newAnthropicResponseWriter(hpkeWriter *hpkeResponseWriter, model string) *messagesResponseWriter {
	return newMessagesResponseWriter(hpkeWriter, model)
}

func (arw *anthropicResponseWriter) Header() http.Header {
	return arw.hpkeWriter.Header()
}

func (arw *anthropicResponseWriter) WriteHeader(statusCode int) {
	arw.statusCode = statusCode
	if arw.headerWritten {
		return
	}
	upstreamCT := strings.ToLower(arw.hpkeWriter.Header().Get("Content-Type"))
	if strings.Contains(upstreamCT, "text/event-stream") {
		arw.isStreaming = true
		arw.hpkeWriter.WriteHeader(statusCode)
		arw.headerWritten = true
	}
}

func (arw *anthropicResponseWriter) Write(p []byte) (int, error) {
	if !arw.headerWritten {
		upstreamCT := strings.ToLower(arw.hpkeWriter.Header().Get("Content-Type"))
		if strings.Contains(upstreamCT, "text/event-stream") {
			arw.isStreaming = true
			arw.hpkeWriter.WriteHeader(arw.statusCode)
			arw.headerWritten = true
		}
	}

	if arw.isStreaming {
		arw.sseBuf.Write(p)
		arw.processSSE()
		return len(p), nil
	}

	return arw.buf.Write(p)
}

func (arw *anthropicResponseWriter) Flush() {
	if arw.isStreaming {
		arw.processSSE()
		arw.hpkeWriter.Flush()
	}
}

func (arw *anthropicResponseWriter) processSSE() {
	for {
		bufBytes := arw.sseBuf.Bytes()
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
			break
		}

		eventBlock := bufBytes[:delimIdx]
		arw.sseBuf.Next(delimIdx + delimLen)

		normalized := strings.ReplaceAll(string(eventBlock), "\r\n", "\n")
		lines := strings.Split(normalized, "\n")
		var dataLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "data:") {
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")))
			}
		}

		if len(dataLines) > 0 {
			payload := strings.Join(dataLines, "\n")
			anthropicEvents := arw.translator.ProcessOpenAIChunk([]byte(payload))
			for _, evt := range anthropicEvents {
				_, _ = arw.hpkeWriter.Write([]byte(evt))
			}
			if payload == "[DONE]" && len(anthropicEvents) > 0 {
				_, _ = arw.hpkeWriter.Write([]byte("data: [DONE]\n\n"))
			}
		}
	}
}

func (arw *anthropicResponseWriter) Finish() {
	if arw.isStreaming {
		arw.processSSE()
		if arw.sseBuf.Len() > 0 {
			normalized := strings.ReplaceAll(arw.sseBuf.String(), "\r\n", "\n")
			lines := strings.Split(normalized, "\n")
			var dataLines []string
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "data:") {
					dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")))
				}
			}
			if len(dataLines) > 0 {
				payload := strings.Join(dataLines, "\n")
				events := arw.translator.ProcessOpenAIChunk([]byte(payload))
				for _, evt := range events {
					_, _ = arw.hpkeWriter.Write([]byte(evt))
				}
				if payload == "[DONE]" && len(events) > 0 {
					_, _ = arw.hpkeWriter.Write([]byte("data: [DONE]\n\n"))
				}
			}
			arw.sseBuf.Reset()
		}
		doneEvents := arw.translator.ProcessOpenAIChunk([]byte("[DONE]"))
		for _, evt := range doneEvents {
			_, _ = arw.hpkeWriter.Write([]byte(evt))
		}
		if len(doneEvents) > 0 {
			_, _ = arw.hpkeWriter.Write([]byte("data: [DONE]\n\n"))
		}
		return
	}

	rawBody := arw.buf.Bytes()
	if len(rawBody) == 0 {
		return
	}

	converted, err := ConvertOpenAIToAnthropicResponse(rawBody, arw.model)
	if err != nil {
		_, _ = arw.hpkeWriter.Write(rawBody)
		return
	}

	_, _ = arw.hpkeWriter.Write(converted)
}

