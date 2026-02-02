# Implementation Plan: Enhanced Error Handling and Request Validation (SSE Heartbeat)

## Phase 1: Request Validation
- [ ] Task: Implement validation logic for Image Generation requests
    - [ ] Write unit tests for generation request validation (validating size, prompt, batch size)
    - [ ] Implement `validate_generation_request` function in `proxy.rs`
- [ ] Task: Implement validation logic for Image Edit (img2img) requests
    - [ ] Write unit tests for edit request validation (base64 image format, required fields)
    - [ ] Implement `validate_edit_request` function in `proxy.rs`
- [ ] Task: Integrate validation into HTTP handlers
    - [ ] Update `/v1/images/generations` and `/v1/images/edits` handlers to use validation functions
    - [ ] Ensure HTTP 400 is returned for invalid requests
- [ ] Task: Conductor - User Manual Verification 'Phase 1: Request Validation' (Protocol in workflow.md)

## Phase 2: Error Mapping and Transformation
- [ ] Task: Define OpenAI-compatible error response structures
    - [ ] Create `OpenAIError` and `ErrorResponse` structs in a new `error.rs` or `proxy.rs`
- [ ] Task: Map ComfyUI backend errors to OpenAI format
    - [ ] Write tests for translating backend connection errors (502) and execution errors (500)
    - [ ] Update `comfyui.rs` to return structured errors instead of generic ones
- [ ] Task: Update error handling in `proxy.rs`
    - [ ] Ensure all handler errors are converted to `OpenAIError` JSON responses
- [ ] Task: Conductor - User Manual Verification 'Phase 2: Error Mapping and Transformation' (Protocol in workflow.md)

## Phase 3: Streaming Heartbeat (SSE)
- [ ] Task: Implement SSE response structure
    - [ ] Define `SseEvent` enum (Ping, Progress, Result, Error)
- [ ] Task: Implement heartbeat loop in `proxy.rs`
    - [ ] Write unit tests for the heartbeat generator (ensuring pings are sent)
    - [ ] Create an async stream that yields `ping` events while waiting for the ComfyUI job
- [ ] Task: Integrate WebSocket progress into SSE stream
    - [ ] Update `ws.rs` or `comfyui.rs` to pipe progress updates from ComfyUI to the SSE stream
- [ ] Task: Finalize SSE image delivery
    - [ ] Ensure the final image is sent as a `result` event and the stream is closed correctly
- [ ] Task: Conductor - User Manual Verification 'Phase 3: Streaming Heartbeat (SSE)' (Protocol in workflow.md)
