//! ComfyUI backend communication and request/response handling
//!
//! This module handles the translation between OpenAI API format and ComfyUI format,
//! manages image generation requests, and retrieves generated images from the backend.

use crate::ws::WebSocketManager;
use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method},
    response::Response as AxumResponse,
};
use base64::{Engine as _, engine::general_purpose};
use log::{debug, error, info, warn};
use rand::Rng;
use reqwest::{Client, multipart};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tokio::time::timeout;

/// Metadata for an image file from ComfyUI output
///
/// Used to construct the query string for retrieving images from the backend
#[derive(Debug, Clone, Serialize)]
struct ImageFile {
    /// Image filename in the ComfyUI output directory
    filename: String,
    /// Subdirectory within the output folder
    subfolder: String,
    /// Image type (e.g., "output", "temp")
    #[serde(rename = "type")]
    type_field: String,
}

/// Loads ComfyUI workflow (workflow) JSON files from a directory
///
/// Workflows are definitions that describe the image generation process.
/// Each workflow is a JSON file that can be referenced by model name in API requests.
pub struct WorkflowsLoader;

impl WorkflowsLoader {
    /// Loads all .json files from the specified folder
    ///
    /// Scans the directory and loads all JSON files, using the filename (without extension)
    /// as the key. This allows clients to reference workflows by name in their requests.
    ///
    /// # Arguments
    /// * `folder_path` - Path to directory containing workflow JSON files
    ///
    /// # Returns
    /// - HashMap with workflow name -> JSON content
    /// - Error if directory doesn't exist, is invalid, or JSON parsing fails
    ///
    /// # Example
    /// ```no_run
    /// let workflows = WorkflowsLoader::load_from_folder("./workflows")?;
    /// // Access workflow with: workflows.get("animagine-xl-4")
    /// ```
    pub fn load_from_folder(folder_path: &str) -> Result<HashMap<String, Value>, String> {
        let path = Path::new(folder_path);

        // Validate that the folder exists
        if !path.exists() {
            return Err(format!("Workflows folder does not exist: {}", folder_path));
        }

        // Validate that the path is a directory
        if !path.is_dir() {
            return Err(format!(
                "Workflows path is not a directory: {}",
                folder_path
            ));
        }

        let mut workflows = HashMap::new();

        // Read all entries in the directory
        let entries =
            fs::read_dir(path).map_err(|e| format!("Failed to read workflows directory: {}", e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let file_path = entry.path();

            // Only process JSON files
            if file_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
            {
                // Extract filename without extension (used as workflow name)
                let filename = file_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .ok_or_else(|| format!("Failed to get filename for: {:?}", file_path))?
                    .to_string();

                // Read the JSON file contents
                let file_content = fs::read_to_string(&file_path).map_err(|e| {
                    format!("Failed to read JSON file {}: {}", file_path.display(), e)
                })?;

                // Parse the JSON
                let json_value: Value = serde_json::from_str(&file_content).map_err(|e| {
                    format!("Failed to parse JSON from {}: {}", file_path.display(), e)
                })?;

                info!("✅ Loaded workflow: {}", filename);
                workflows.insert(filename, json_value);
            }
        }

        info!("📦 Successfully loaded {} workflow(s)", workflows.len());
        Ok(workflows)
    }
}

use crate::proxy::{ProxyError, ProxyState, handle_request_error, handle_timeout_error};

/// Handles OpenAI API image generation requests and proxies them to ComfyUI
///
/// This is the main entry point for image generation requests from clients.
/// It:
/// 1. Reads the OpenAI format request
/// 2. Translates it to ComfyUI format
/// 3. Sends it to the backend
/// 4. Waits for job completion via WebSocket
/// 5. Retrieves and encodes generated images
/// 6. Returns them in OpenAI API format
pub async fn generations_response(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<AxumResponse, ProxyError> {
    process_generation_request(State(state), Query(params), headers, body, false).await
}

/// Handles OpenAI-compatible img2img requests (POST /v1/images/edits)
pub async fn img2img_response(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<AxumResponse, ProxyError> {
    process_generation_request(State(state), Query(params), headers, body, true).await
}

/// Internal helper that powers both text-to-image and image-to-image flows.
async fn process_generation_request(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
    require_image: bool,
) -> Result<AxumResponse, ProxyError> {
    // Construct the backend ComfyUI URL for prompt submission
    let target_base: String = format!("{}:{}", state.backend_url, state.backend_port);
    let method = Method::POST;
    let target_url: String = format!("http://{}/prompt", target_base);

    debug!("🎯 Proxying {} / -> {}", method, target_url);

    // Build query string from parameters (rarely used but preserved for compatibility)
    let query_string = if params.is_empty() {
        String::new()
    } else {
        let mut query = String::with_capacity(256);
        query.push('?');
        for (i, (k, v)) in params.iter().enumerate() {
            if i > 0 {
                query.push('&');
            }
            query.push_str(k);
            query.push('=');
            query.push_str(v);
        }
        query
    };
    let full_url = format!("{}{}", target_url, query_string);

    // Read the request body up to the configured maximum size
    debug!("📥 Reading request body...");
    let body_bytes = match axum::body::to_bytes(body, state.max_payload_size_mb * 1024 * 1024).await
    {
        Ok(bytes) => {
            debug!("✅ Body read successfully: {} bytes", bytes.len());
            bytes
        }
        Err(e) => {
            error!("❌ Failed to read body: {}", e);
            return Err(ProxyError::Internal(format!(
                "Failed to read request body: {}",
                e
            )));
        }
    };

    let openai_request: Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ProxyError::Json(format!("Failed to parse JSON: {}", e)))?;

    let mut base_image_name: Option<String> = None;

    if require_image {
        let image_field = openai_request
            .get("image")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProxyError::Json("Failed to get image from JSON".to_string()))?;

        let image_bytes = decode_base64_image(image_field)?;
        let uploaded_name =
            upload_image_to_backend(&image_bytes, &target_base, &headers, &state.client).await?;

        base_image_name = Some(uploaded_name);
    }

    // Transform OpenAI API request format to ComfyUI format
    let processed_body = if !body_bytes.is_empty() {
        debug!("🔧 Generating comfyui request body...");
        match create_json_payload(
            openai_request,
            state.workflows.clone(),
            state.backend_client_id.clone(),
            base_image_name.as_deref(),
        )
        .await
        {
            Ok(modified) => {
                debug!("✅ Body modified successfully");
                modified
            }
            Err(e) => {
                warn!("❌ Failed to modify body: {:?}", e);
                return Err(e);
            }
        }
    } else {
        body_bytes
    };

    // Prepare HTTP headers for the backend request
    debug!("📋 Preparing headers...");
    let mut upstream_headers = reqwest::header::HeaderMap::new();

    // Set content-type for JSON payload
    if !processed_body.is_empty() {
        upstream_headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
    }

    // Forward authorization headers if present
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_value) = reqwest::header::HeaderValue::from_bytes(auth.as_bytes()) {
            upstream_headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }
    }

    // Log headers for debugging
    debug!("📋 Headers to send:");
    for (name, value) in upstream_headers.iter() {
        debug!("   {}: {}", name, value.to_str().unwrap_or("[unprintable]"));
    }
    debug!("🚀 Making upstream request...");
    debug!("   URL: {}", full_url);
    debug!("   Method: {}", method);
    debug!("   Body size: {} bytes", processed_body.len());

    // Build the request to the backend
    let request_builder = state
        .client
        .request(method.clone(), &full_url)
        .headers(upstream_headers)
        .body(processed_body);

    debug!("⏳ Sending request to backend...");

    // Send request with timeout protection
    let request_future = request_builder.send();
    let timeout_duration = Duration::from_secs(state.timeout);

    debug!(
        "⏰ Starting request with {} second timeout...",
        timeout_duration.as_secs()
    );

    // Execute request with timeout
    let upstream_response = match tokio::time::timeout(timeout_duration, request_future).await {
        Ok(Ok(response)) => {
            debug!(
                "✅ Got response from backend: {} - Headers: {:?}",
                response.status(),
                response.headers()
            );
            response
        }
        Ok(Err(e)) => {
            return Err(handle_request_error(e, &full_url));
        }
        Err(_) => {
            return Err(handle_timeout_error(&full_url, timeout_duration));
        }
    };

    // Detect response type (streaming responses are not yet supported)
    let _is_streaming = upstream_response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.contains("text/event-stream")
                || v.contains("application/x-ndjson")
                || v.contains("text/plain")
        })
        .unwrap_or(false);

    // Handle the response from ComfyUI
    handle_regular_response(
        upstream_response,
        target_base,
        headers,
        state.use_ws,
        &state.client,
        &state.ws_manager,
    )
    .await
}

/// Transforms an OpenAI API request into a ComfyUI prompt request
///
/// This function performs the critical translation layer between the OpenAI image
/// generation API format and ComfyUI's workflow format.
///
/// Mapping:
/// - `model` -> workflow name (used to look up workflow JSON)
/// - `prompt` -> positive prompt text for image generation
/// - `negative_prompt` -> negative prompt for image generation
/// - `seed` -> seed for image generation
/// - `size` -> image dimensions (e.g., "1024x1024" -> width/height)
/// - `n` -> batch_size (number of images to generate)
///
///
/// # Arguments
/// * `body` - Parsed OpenAI API request payload
/// * `workflows` - Map of available ComfyUI workflows definitions
/// * `client_id` - Client ID for WebSocket tracking
/// * `base_image` - Optional filename for uploaded input image (img2img)
///
/// # Returns
/// - Serialized ComfyUI prompt JSON ready for backend submission
/// - ProxyError if validation or transformation fails
async fn create_json_payload(
    body: Value,
    workflows: Arc<HashMap<String, Value>>,
    client_id: String,
    base_image: Option<&str>,
) -> Result<Bytes, ProxyError> {
    if body.is_null() {
        return Err(ProxyError::Json("Request body is empty".to_string()));
    }
    let mut rng = rand::rng();

    let json: Value = body;

    // Initialize ComfyUI request structure with placeholder values
    let mut workflow_use = serde_json::json!({
        "prompt": "",
        "client_id": ""
    });

    // Process the OpenAI request
    if let Some(openai_request) = json.as_object() {
        // Extract and validate the model/workflow name
        if let Some(model_name) = openai_request.get("model").and_then(|v| v.as_str()) {
            if let Some(workflow) = workflows.get(model_name) {
                debug!("📦 Retrieved workflow '{}'", model_name);
                // Use the selected workflow as the base prompt
                workflow_use["prompt"] = workflow.clone();
            } else {
                return Err(ProxyError::Json(format!(
                    "Workflow '{}' not found",
                    model_name
                )));
            }
        } else {
            return Err(ProxyError::Json(format!(
                "Failed to get model name from JSON"
            )));
        }

        // Modify the prompt with request-specific parameters
        if let Some(obj) = workflow_use.as_object_mut() {
            // Set the client ID for WebSocket tracking
            obj.insert("client_id".to_string(), Value::String(client_id.clone()));

            // Modify workflow nodes to inject parameters from OpenAI request
            if let Some(workflow_prompt) = workflow_use
                .get_mut("prompt")
                .and_then(|v| v.as_object_mut())
            {
                for (node_key, node_data) in workflow_prompt {
                    // Match on node class to handle ComfyLiterals primitives explicitly
                    if let Some(class_type) = node_data["class_type"].as_str() {
                        match class_type {
                            // Integer primitive nodes (ComfyLiterals 'Int')
                            "Int" => {
                                // Prefer to identify the primitive by the node's _meta.title if present
                                let title_lower = node_data.get("_meta").and_then(|m| m.get("title")).and_then(|t| t.as_str()).map(|s| s.to_lowercase());
                                let key_lower = node_key.to_lowercase();
                                if let Some(inputs_obj) = node_data.get_mut("inputs").and_then(|v| v.as_object_mut()) {

                                    // Helper to set the first numeric-like field in the inputs object
                                    let mut set_first_numeric = |val: String| {
                                        for (_k, v) in inputs_obj.iter_mut() {
                                            if v.is_number() || v.is_string() {
                                                *v = Value::String(val.clone());
                                                return;
                                            }
                                        }
                                    };

                                    // Seed
                                    if title_lower.as_deref() == Some("seed") || key_lower == "seed" {
                                        let seed_value = openai_request.get("seed").and_then(|v| v.as_i64()).map(|s| s as i64).unwrap_or_else(|| rng.random_range(0..1_000_000) as i64);
                                        debug!("✏️ Injecting seed into Int node '{}': {}", node_key, seed_value);
                                        set_first_numeric(seed_value.to_string());
                                    }

                                    // Width / Height
                                    else if title_lower.as_deref() == Some("width") || title_lower.as_deref() == Some("height") || key_lower == "width" || key_lower == "height" {
                                        if let Some(size_data) = openai_request.get("size").and_then(|v| v.as_str()) {
                                            if let Some((w, h)) = parse_size(size_data) {
                                                let inject_value = if title_lower.as_deref() == Some("width") || key_lower == "width" { w } else { h };
                                                debug!("✏️ Injecting {} into Int node '{}'", inject_value, node_key);
                                                set_first_numeric(inject_value.to_string());
                                            } else {
                                                warn!("⚠️ Invalid size format for {}", node_key);
                                            }
                                        }
                                    }

                                    // Batch size / copies
                                    else if title_lower.as_deref() == Some("batch_size") || key_lower == "batch_size" || key_lower == "copies" {
                                        if let Some(copies_num_data) = openai_request.get("n").and_then(|v| v.as_i64()) {
                                            debug!("✏️ Injecting copies into Int node '{}': {}", node_key, copies_num_data);
                                            set_first_numeric(copies_num_data.to_string());
                                        }
                                    }
                                }
                            }

                            // String primitive nodes (ComfyLiterals 'String' or String-literal types)
                            ct if ct.to_lowercase().contains("string") => {
                                // Prefer title for semantic meaning (e.g., "Positive Prompt", "Negative Prompt")
                                let title_lower = node_data.get("_meta").and_then(|m| m.get("title")).and_then(|t| t.as_str()).map(|s| s.to_lowercase());
                                let key_lower = node_key.to_lowercase();

                                if let Some(inputs_obj) = node_data.get_mut("inputs").and_then(|v| v.as_object_mut()) {
                                    let is_prompt_like = title_lower.as_deref().map(|t| t.contains("prompt") || t.contains("positive") || t.contains("negative")).unwrap_or(false) || key_lower.contains("prompt") || key_lower.contains("text");

                                    if is_prompt_like {
                                        // Decide positive vs negative by title or node name
                                        let is_negative = title_lower.as_deref().map(|t| t.contains("neg") || t.contains("negative")).unwrap_or(false) || key_lower.contains("neg");

                                        if is_negative {
                                            if let Some(neg_prompt_input) = openai_request.get("negative_prompt").and_then(|v| v.as_str()) {
                                                debug!("✏️ Injecting negative prompt into String node '{}': {}", node_key, neg_prompt_input);
                                                for (_k, v) in inputs_obj.iter_mut() {
                                                    if v.is_string() {
                                                        *v = Value::String(neg_prompt_input.to_string());
                                                        break;
                                                    }
                                                }
                                            }
                                        } else {
                                            if let Some(prompt_input) = openai_request.get("prompt").and_then(|v| v.as_str()) {
                                                debug!("✏️ Injecting prompt into String node '{}': {}", node_key, prompt_input);
                                                for (_k, v) in inputs_obj.iter_mut() {
                                                    if v.is_string() {
                                                        *v = Value::String(prompt_input.to_string());
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Keep handling of LoadImage nodes for image uploads
                            "LoadImage" => {
                                if let Some(inputs_data) = node_data["inputs"].as_object_mut() {
                                    if let Some(image_name) = base_image {
                                        debug!("✏️ Using uploaded image (LoadImage): {}", image_name);
                                        inputs_data.insert("image".to_string(), Value::String(image_name.to_string()));
                                    } else {
                                        debug!("No base image provided, using workflow default");
                                    }
                                }
                            }

                            // For other node types, preserve existing CLIPTextEncode logic below
                            _ => {}
                        }
                    }

                    // Still handle CLIPTextEncode specially to detect positive/negative prompt nodes
                    if let Some(class_type) = node_data["class_type"].as_str() {
                        if class_type == "CLIPTextEncode" {
                            if let Some(meta_data) = node_data["_meta"].as_object() {
                                if let Some(title) = meta_data["title"].as_str() {
                                    if title == "Positive Prompt" {
                                        if let Some(inputs_data) = node_data["inputs"].as_object_mut() {
                                            if let Some(prompt_input) = openai_request.get("prompt").and_then(|v| v.as_str()) {
                                                debug!("✏️ Requested prompt: {}", prompt_input);
                                                inputs_data.insert("text".to_string(), Value::String(prompt_input.to_string()));
                                            } else {
                                                return Err(ProxyError::Json(format!("Failed to get prompt from JSON")));
                                            }
                                        }
                                    } else if title == "Negative Prompt" {
                                        if let Some(inputs_data) = node_data["inputs"].as_object_mut() {
                                            if let Some(neg_prompt_input) = openai_request.get("negative_prompt").and_then(|v| v.as_str()) {
                                                debug!("✏️ Requested negative prompt: {}", neg_prompt_input);
                                                inputs_data.insert("text".to_string(), Value::String(neg_prompt_input.to_string()));
                                            } else {
                                                debug!("No negative_prompt in JSON, using workflow default");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        debug!("🔧 Generated JSON payload");
    } else {
        return Err(ProxyError::Json(
            "Request body must be a JSON object".to_string(),
        ));
    }

    // Serialize the modified ComfyUI prompt to JSON bytes
    let modified_json = serde_json::to_vec(&workflow_use)
        .map_err(|e| ProxyError::Json(format!("Failed to serialize JSON: {}", e)))?;

    Ok(Bytes::from(modified_json))
}

/// Decodes a base64-encoded image string, accepting optional data URLs.
fn decode_base64_image(image_field: &str) -> Result<Vec<u8>, ProxyError> {
    let data = if let Some(idx) = image_field.find(',') {
        &image_field[idx + 1..]
    } else {
        image_field
    };

    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| ProxyError::Json(format!("Failed to decode base64 image: {}", e)))
}

/// Uploads an input image to the ComfyUI backend so workflows can reference it.
async fn upload_image_to_backend(
    image_bytes: &[u8],
    target_base: &str,
    headers: &HeaderMap,
    client: &Client,
) -> Result<String, ProxyError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let file_name = format!("openai-img-{}.png", timestamp);
    let upload_url = format!("http://{}/upload/image", target_base);

    let mut upload_headers = reqwest::header::HeaderMap::new();
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_value) = reqwest::header::HeaderValue::from_bytes(auth.as_bytes()) {
            upload_headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }
    }

    let form = multipart::Form::new().part(
        "image",
        multipart::Part::bytes(image_bytes.to_vec())
            .file_name(file_name.clone())
            .mime_str("image/png")
            .map_err(|e| ProxyError::Json(format!("Failed to build upload payload: {}", e)))?,
    );

    debug!("⏫ Uploading base image to backend as {}", file_name);

    let response = client
        .post(&upload_url)
        .headers(upload_headers)
        .multipart(form)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(ProxyError::Upstream(format!(
            "Image upload failed with status {}",
            response.status()
        )));
    }

    let uploaded_name = response
        .json::<Value>()
        .await
        .ok()
        .and_then(|json| {
            json.get("name")
                .or_else(|| json.get("filename"))
                .or_else(|| json.get("file"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or(file_name);

    Ok(uploaded_name)
}

/// Handles the response from ComfyUI backend
///
/// This function:
/// 1. Extracts the prompt_id from the backend response
/// 2. Waits for job completion via WebSocket
/// 3. Retrieves generated images from the backend
/// 4. Encodes images as base64
/// 5. Returns response in OpenAI API format
async fn handle_regular_response(
    upstream_response: reqwest::Response,
    target_base: String,
    _headers: HeaderMap,
    use_ws: bool,
    client: &Client,
    ws_manager: &Option<Arc<WebSocketManager>>,
) -> Result<AxumResponse, ProxyError> {
    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();

    debug!("📄 Handling regular response with status: {}", status);

    // Read response body from backend
    let body_bytes = upstream_response
        .bytes()
        .await
        .map_err(|e| ProxyError::Upstream(format!("Failed to read response body: {}", e)))?;

    debug!("📥 Response body: {} bytes", body_bytes.len());

    // Parse backend response as JSON
    let json: Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ProxyError::Json(format!("Failed to parse JSON: {}", e)))?;

    debug!("📝 Received response: {}", json.to_string());

    // Extract the prompt_id which identifies this job in ComfyUI
    let prompt_id = json.get("prompt_id").and_then(|v| v.as_str());
    if let Some(pid) = prompt_id {
        debug!(
            "📝 Found prompt_id in response: {}. Waiting for job completion...",
            pid
        );

        // // Block until the job completes via WebSocket
        if use_ws {
            if let Some(manager) = ws_manager {
                match timeout(
                    Duration::from_secs(600),
                    manager.wait_for_job_completion(pid),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!("⚠️ Failed to wait for job completion: {}", e),
                    Err(_) => warn!("⚠️ Job completion wait timed out after 600 seconds"),
                }
            } else {
                warn!("⚠️ WebSocket manager is not initialized but use_ws is true");
            }
        } else {
            loop {
                // Fetch generated images from ComfyUI backend and prepare response
                let is_done =
                    check_queue(target_base.clone(), Some(pid), headers.clone(), client).await?;

                if is_done {
                    debug!("⚡ Job {} completed (not found in queue)", pid);
                    break;
                }

                tokio::time::sleep(Duration::from_millis(2000)).await;
            }
        }
    }

    // Fetch generated images from ComfyUI backend and prepare response
    let image_response_json =
        retrieve_image_from_history(target_base, prompt_id, headers.clone(), client).await?;

    // Serialize the image response JSON to bytes
    let output_json = serde_json::to_vec(&image_response_json)
        .map_err(|e| ProxyError::Json(format!("Failed to serialize JSON: {}", e)))?;
    let output_body_bytes = Bytes::from(output_json);
    debug!(
        "✏️ JSON regular response: {} bytes",
        output_body_bytes.len()
    );

    // Copy and update response headers
    let mut response_headers = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_str(name.as_str()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            if name.as_str() == "content-length" {
                // Update content-length to match the final response size
                if let Ok(value) =
                    HeaderValue::from_str(format!("{}", output_body_bytes.len()).as_str())
                {
                    response_headers.insert(name, value);
                }
            } else {
                response_headers.insert(name, value);
            }
        }
    }

    // Build the final HTTP response
    let mut response = AxumResponse::builder().status(status.as_u16());

    for (name, value) in response_headers.iter() {
        response = response.header(name, value);
    }

    debug!("✅ Regular response built successfully");

    response
        .body(Body::from(output_body_bytes))
        .map_err(|e| ProxyError::Internal(format!("Failed to build regular response: {}", e)))
}

/// Retrieves generated images from ComfyUI backend
///
/// This function:
/// 1. Queries the ComfyUI history endpoint for the given prompt_id
/// 2. Extracts image metadata from the job outputs
/// 3. Downloads each image from the view endpoint
/// 4. Base64 encodes the images
/// 5. Formats the response in OpenAI API standards
///
/// # Arguments
/// * `target_base` - ComfyUI backend address (host:port)
/// * `prompt_id` - The job ID to retrieve results for
/// * `headers` - Original request headers (may contain auth)
/// * `client` - HTTP client for backend communication
///
/// # Returns
/// - JSON response in OpenAI image generation format with base64 encoded images
/// - ProxyError if history lookup or image retrieval fails
async fn retrieve_image_from_history(
    target_base: String,
    prompt_id: Option<&str>,
    headers: HeaderMap,
    client: &Client,
) -> Result<Value, ProxyError> {
    // Validate that we have a prompt_id
    let prompt_id = match prompt_id {
        Some(id) => id,
        None => {
            error!("⚠️ No prompt_id received!");
            return Err(ProxyError::Upstream(format!("No prompt_id received.",)));
        }
    };

    // Construct URL to ComfyUI history endpoint
    let history_url: String = format!("http://{}/history/{}", target_base, prompt_id);

    debug!("🔍 Checking history at {} for {}", target_base, prompt_id);

    // Prepare headers for backend requests
    let mut upstream_headers = reqwest::header::HeaderMap::new();

    // Forward authorization headers if present
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_value) = reqwest::header::HeaderValue::from_bytes(auth.as_bytes()) {
            upstream_headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }
    }

    // Log headers for debugging
    debug!("📋 Headers to send (if any):");
    for (name, value) in upstream_headers.iter() {
        debug!("   {}: {}", name, value.to_str().unwrap_or("[unprintable]"));
    }

    // Build request to history endpoint
    let request_builder = client
        .request(Method::GET, &history_url)
        .headers(upstream_headers.clone());

    debug!("⏳ Sending history request to backend...");

    // Query history with timeout protection
    let request_future = request_builder.send();
    let timeout_duration = Duration::from_secs(5);

    let upstream_response = match tokio::time::timeout(timeout_duration, request_future).await {
        Ok(Ok(response)) => {
            debug!(
                "✅ Got response from history backend: {} - Headers: {:?}",
                response.status(),
                response.headers()
            );
            response
        }
        Ok(Err(e)) => {
            return Err(handle_request_error(e, &history_url));
        }
        Err(_) => {
            return Err(handle_timeout_error(&history_url, timeout_duration));
        }
    };

    // Parse history response
    let response_body = upstream_response.bytes().await.map_err(|e| {
        ProxyError::Upstream(format!("Failed to read history response body: {}", e))
    })?;
    let history_json: Value = serde_json::from_slice(&response_body)
        .map_err(|e| ProxyError::Json(format!("Failed to parse history JSON: {}", e)))?;

    // Extract image metadata from job outputs
    let mut image_files: Vec<ImageFile> = Vec::new();
    if let Some(prompt_hist) = history_json.get(prompt_id).and_then(|v| v.as_object()) {
        if let Some(out_nodes) = prompt_hist.get("outputs").and_then(|v| v.as_object()) {
            // Iterate through output nodes looking for generated images
            for (_node_id, out_node_data) in out_nodes {
                if let Some(all_images_data) =
                    out_node_data.get("images").and_then(|v| v.as_array())
                {
                    // Process each image in the node output
                    for image_data in all_images_data {
                        if let Some(type_field) = image_data["type"].as_str() {
                            // Only include output images (not temporary/preview)
                            if type_field == "output" {
                                if let Some(filename) = image_data["filename"].as_str() {
                                    if let Some(subfolder) = image_data["subfolder"].as_str() {
                                        debug!(
                                            "🔍 Found: filename: {}, subfolder: {}",
                                            filename, subfolder
                                        );
                                        image_files.push(ImageFile {
                                            filename: filename.to_string(),
                                            subfolder: subfolder.to_string(),
                                            type_field: type_field.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        error!("⚠️ No prompt_id history found");
        return Err(ProxyError::Upstream(
            format!("No prompt_id history found.",),
        ));
    }

    debug!("📦 Collected {} image files", image_files.len());
    let mut response_data: Vec<serde_json::Value> = Vec::new();

    // Download and encode each generated image
    for image_file_data in image_files {
        // Construct query parameters for the view endpoint
        let view_query = serde_urlencoded::to_string(&image_file_data).map_err(|e| {
            ProxyError::Json(format!("Failed to serialize image data query: {}", e))
        })?;

        let view_url: String = format!("http://{}/view?{}", target_base, view_query);

        // Build request to image view endpoint
        let request_builder = client
            .request(Method::GET, &view_url)
            .headers(upstream_headers.clone());

        debug!("⏳ Sending view request to backend: {}", view_query);

        // Download image with timeout
        let request_future = request_builder.send();
        let timeout_duration = Duration::from_secs(5);

        let view_response = match tokio::time::timeout(timeout_duration, request_future).await {
            Ok(Ok(response)) => {
                debug!(
                    "✅ Got response from view backend: {} - Headers: {:?}",
                    response.status(),
                    response.headers()
                );
                response
            }
            Ok(Err(e)) => {
                return Err(handle_request_error(e, &view_url));
            }
            Err(_) => {
                return Err(handle_timeout_error(&view_url, timeout_duration));
            }
        };

        // Read image bytes and encode as base64
        let image_bytes = view_response.bytes().await?;
        debug!("📋 Read {} image bytes", image_bytes.len());
        let b64_image = general_purpose::STANDARD.encode(image_bytes);
        response_data.push(serde_json::json!({
            "b64_json": b64_image
        }));
    }

    // Create OpenAI API format response with timestamp
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProxyError::Internal("Failed to get current time".to_string()))?
        .as_secs() as i64;

    Ok(serde_json::json!({
        "data": response_data,
        "created": created
    }))
}

/// Checks a job state from ComfyUI backend
///
/// This function:
/// 1. Queries the ComfyUI queue endpoint for the given prompt_id
/// 2. Looks for the given job ID in both queues (pending y running)
/// 3. Returns true if not found
///
/// # Arguments
/// * `target_base` - ComfyUI backend address (host:port)
/// * `prompt_id` - The job ID to retrieve results for
/// * `headers` - Original request headers (may contain auth)
/// * `client` - HTTP client for backend communication
///
/// # Returns
/// - True if the given job id is not in the queues and hence finished
/// - ProxyError if history lookup or image retrieval fails
async fn check_queue(
    target_base: String,
    prompt_id: Option<&str>,
    headers: HeaderMap,
    client: &Client,
) -> Result<bool, ProxyError> {
    // Validate that we have a prompt_id
    let prompt_id = match prompt_id {
        Some(id) => id,
        None => {
            error!("⚠️ No prompt_id received!");
            return Err(ProxyError::Upstream(format!("No prompt_id received.",)));
        }
    };

    // Construct URL to ComfyUI history endpoint
    let history_url: String = format!("http://{}/queue", target_base);

    debug!("🔍 Checking queue at {}", target_base);

    // Prepare headers for backend requests
    let mut upstream_headers = reqwest::header::HeaderMap::new();

    // Forward authorization headers if present
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_value) = reqwest::header::HeaderValue::from_bytes(auth.as_bytes()) {
            upstream_headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }
    }

    // Log headers for debugging
    debug!("📋 Headers to send (if any):");
    for (name, value) in upstream_headers.iter() {
        debug!("   {}: {}", name, value.to_str().unwrap_or("[unprintable]"));
    }

    // Build request to history endpoint
    let request_builder = client
        .request(Method::GET, &history_url)
        .headers(upstream_headers.clone());

    debug!("⏳ Sending queue request to backend...");

    // Query history with timeout protection
    let request_future = request_builder.send();
    let timeout_duration = Duration::from_secs(5);

    let upstream_response = match tokio::time::timeout(timeout_duration, request_future).await {
        Ok(Ok(response)) => {
            debug!(
                "✅ Got response from queue backend: {} - Headers: {:?}",
                response.status(),
                response.headers()
            );
            response
        }
        Ok(Err(e)) => {
            return Err(handle_request_error(e, &history_url));
        }
        Err(_) => {
            return Err(handle_timeout_error(&history_url, timeout_duration));
        }
    };

    // Parse history response
    let response_body = upstream_response
        .bytes()
        .await
        .map_err(|e| ProxyError::Upstream(format!("Failed to read queu response body: {}", e)))?;
    let queu_json: Value = serde_json::from_slice(&response_body)
        .map_err(|e| ProxyError::Json(format!("Failed to queu history JSON: {}", e)))?;

    // Check running
    if let Some(queue_running) = queu_json.get("queue_running").and_then(|v| v.as_array()) {
        for queue_elem in queue_running.iter() {
            if queue_elem[1] == prompt_id {
                return Ok(false);
            }
        }
    }
    // Check pending
    if let Some(queue_pending) = queu_json.get("queue_pending").and_then(|v| v.as_array()) {
        for queue_elem in queue_pending.iter() {
            if queue_elem[1] == prompt_id {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
/// Parse an OpenAI-style size string (e.g., "1024x1024") into width and height.
fn parse_size(size_data: &str) -> Option<(i32, i32)> {
    let lower = size_data.to_lowercase();
    let mut parts = lower.split('x').filter_map(|p| p.parse::<i32>().ok());

    match (parts.next(), parts.next()) {
        (Some(width), Some(height)) if width > 0 && height > 0 => Some((width, height)),
        _ => None,
    }
}
