# Specification: Enhanced Error Handling and Request Validation (SSE Heartbeat)

## Overview
This track aims to improve the robustness of the ComfyUI OpenAI API Proxy by implementing strict request validation, detailed error mapping, and a streaming "heartbeat" mechanism to prevent timeouts during long-running generations.

## Objectives
1.  **Request Validation:** Implement comprehensive validation for `/v1/images/generations` and `/v1/images/edits` endpoints.
2.  **Error Mapping:** Map ComfyUI backend errors (timeouts, execution failures, connection issues) to standard OpenAI JSON error responses.
3.  **Streaming Heartbeat:** Implement Server-Sent Events (SSE) support for image generation requests to send progress updates, keeping the connection alive and preventing 504 Gateway Timeouts.

## Functional Requirements

### 1. Request Validation
- **Image Generation:** Validate `model` existence, `prompt` length, `size` format (WxH), and `n` (batch size) limits.
- **Image Edits:** Validate `image` base64 format, `mask` (if provided), and ensuring compatibility with the target workflow.
- **Rejection:** Return HTTP 400 Bad Request with a clear, descriptive error message for any invalid input.

### 2. Error Handling
- **Backend Failures:** Catch connection errors to ComfyUI (e.g., connection refused) and return HTTP 502 Bad Gateway.
- **Execution Errors:** Catch ComfyUI workflow errors (e.g., out of memory, missing node) and return HTTP 500 Internal Server Error with the specific error detail.
- **Timeouts:** If the job exceeds the configured global timeout (and streaming is NOT used), return HTTP 504 Gateway Timeout.

### 3. Streaming Heartbeat (SSE)
- **Activation:** The client triggers streaming mode via a custom header (e.g., `X-Stream: true`) or standard OpenAI streaming parameter if applicable.
- **Format:** Use `text/event-stream` Content-Type.
- **Events:**
    -   `ping`: Sent periodically (e.g., every 5-10s) to keep the connection alive.
    -   `progress`: Optional event sending current generation percentage (if available from ComfyUI).
    -   `result`: The final base64 image data or JSON response.
    -   `error`: If the generation fails mid-stream.
- **Compatibility:** Verify compatibility with LiteLLM's streaming response handling.

## Non-Functional Requirements
- **Performance:** Validation logic must add negligible latency (< 5ms).
- **Concurrency:** Streaming connections must be managed efficiently to not exhaust server resources (using Tokio/Axum streaming).

## Out of Scope
- Modifying the underlying ComfyUI backend code.
- Implementing "Async/Polling" API patterns (HTTP 202).
