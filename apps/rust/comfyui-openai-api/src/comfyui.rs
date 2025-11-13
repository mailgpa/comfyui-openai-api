use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method},
    response::{Response as AxumResponse},
};
use log::{debug, error, warn, info};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use crate::ws::WebSocketManager;
use base64::{engine::general_purpose, Engine as _};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
struct ImageFile {
    filename: String,
    subfolder: String,
    #[serde(rename = "type")]
    type_field: String,
}

/// Loads all JSON files from a directory and returns them as a map
/// where the key is the filename without extension and the value is the parsed JSON
pub struct PipelinesLoader;

impl PipelinesLoader {
    /// Load all .json files from the specified folder path
    /// Returns a HashMap with filename (without extension) -> JSON content
    pub fn load_from_folder(folder_path: &str) -> Result<HashMap<String, Value>, String> {
        let path = Path::new(folder_path);
        
        // Check if the folder exists
        if !path.exists() {
            return Err(format!("Pipelines folder does not exist: {}", folder_path));
        }
        
        if !path.is_dir() {
            return Err(format!("Pipelines path is not a directory: {}", folder_path));
        }
        
        let mut pipelines = HashMap::new();
        
        // Read all entries in the directory
        let entries = fs::read_dir(path)
            .map_err(|e| format!("Failed to read pipelines directory: {}", e))?;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let file_path = entry.path();
            
            // Only process JSON files
            if file_path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
            {
                // Get the filename without extension
                let filename = file_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .ok_or_else(|| {
                        format!("Failed to get filename for: {:?}", file_path)
                    })?
                    .to_string();
                
                // Read and parse the JSON file
                let file_content = fs::read_to_string(&file_path)
                    .map_err(|e| {
                        format!("Failed to read JSON file {}: {}", file_path.display(), e)
                    })?;
                
                let json_value: Value = serde_json::from_str(&file_content)
                    .map_err(|e| {
                        format!("Failed to parse JSON from {}: {}", file_path.display(), e)
                    })?;
                
                info!("✅ Loaded pipeline: {}", filename);
                pipelines.insert(filename, json_value);
            }
        }
        
        info!("📦 Successfully loaded {} pipeline(s)", pipelines.len());
        Ok(pipelines)
    }
}

use crate::proxy::{ProxyState, ProxyError, handle_request_error, handle_timeout_error};


pub async fn generations_response(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<AxumResponse, ProxyError> {

    // Set the backend target endpoint
    let target_base: String = format!("{}:{}", state.backend_url, state.backend_port);
    let method = Method::POST;
    // Append the target path
    let target_url: String = format!("http://{}/prompt", target_base);

    debug!("🎯 Proxying {} / -> {}", method, target_url);

    // Build query string, if any, after the backend path (not really tested)
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

    // Read body of the request, up to the given number of MBs
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

    // There is some body here, construct the comfyui request
    let processed_body = if !body_bytes.is_empty() {
        debug!("🔧 Generating comfyui request body...");
        match create_json_payload(
            body_bytes,
            state.pipelines.clone(),
            state.backend_client_id.clone(),
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

    // Prepare headers
    debug!("📋 Preparing headers...");
    let mut upstream_headers = reqwest::header::HeaderMap::new();

    // Only add content-type if we have a body
    if !processed_body.is_empty() {
        upstream_headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
    }

    // Add authorization header if present in original request
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_value) = reqwest::header::HeaderValue::from_bytes(auth.as_bytes()) {
            upstream_headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }
    }

    // Debug: Print all headers being sent
    debug!("📋 Headers to send:");
    for (name, value) in upstream_headers.iter() {
        debug!("   {}: {}", name, value.to_str().unwrap_or("[unprintable]"));
    }
    debug!("🚀 Making upstream request...");
    debug!("   URL: {}", full_url);
    debug!("   Method: {}", method);
    debug!("   Body size: {} bytes", processed_body.len());

    // Build request
    let request_builder = state
        // set client
        .client
        // add method and endpoint
        .request(method.clone(), &full_url)
        // add headers
        .headers(upstream_headers)
        // add body
        .body(processed_body);

    debug!("⏳ Sending request to backend...");
    debug!("🔍 About to call request_builder.send()...");

    // Add a timeout wrapper to catch hanging requests
    let request_future = request_builder.send();
    let timeout_duration = Duration::from_secs(state.timeout);

    debug!(
        "⏰ Starting request with {} second timeout...",
        timeout_duration.as_secs()
    );

    // Await the request future
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

    // Check if it is a streaming request
    let is_streaming = upstream_response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.contains("text/event-stream")
                || v.contains("application/x-ndjson")
                || v.contains("text/plain")
        })
        .unwrap_or(false);

    println!(
        "📦 Response type: {}",
        if is_streaming { "streaming" } else { "regular" }
    );


    // Handle a regular response
    handle_regular_response(
        upstream_response,
        target_base, 
        headers,
        &state.client,
        &state.ws_manager,
    )
    .await
}



/// Modifies the json payload of a openAI image request to adapt it to ComfyUI
async fn create_json_payload(
    body: Bytes,
    pipelines: Arc<HashMap<String, Value>>,
    client_id: String,
) -> Result<Bytes, ProxyError> {
    // just in case empty body check
    if body.is_empty() {
        return Ok(body);
    }

    // Read all the body as a json, it should be a json
    let mut json: Value = serde_json::from_slice(&body)
        .map_err(|e| ProxyError::Json(format!("Failed to parse JSON: {}", e)))?;

    let mut pipeline_use = serde_json::json!({
            "prompt": "",
            "client_id": ""
        });

    // if we can get a json hashmap, go ahead
    if let Some(openai_request) = json.as_object() {

        

        if let Some(model_name) = openai_request.get("model").and_then(|v| v.as_str()) {
            if let Some(pipeline) = pipelines.get(model_name) {
                debug!("📦 Retrieved pipeline '{}'", model_name);
                pipeline_use["prompt"] = pipeline.clone();
            } else {
                return Err(ProxyError::Json(format!("Pipeline '{}' not found", model_name)));
            }
        } else {
            return Err(ProxyError::Json(format!("Failed to get model name from JSON")));
        }


        
        if let Some(obj) = pipeline_use.as_object_mut() {
            // Modify client id
            obj.insert(
                "client_id".to_string(),
                Value::String(client_id.clone()),
            );

            // modify prompt
            if let Some(pipeline_prompt) = pipeline_use.get_mut("prompt").and_then(|v| v.as_object_mut()){

                for (_node_id, node_data) in pipeline_prompt {
                    if let Some(class_type) = node_data["class_type"].as_str() {
                        match class_type {
                            "EmptyLatentImage" | "EmptySD3LatentImage" => {
                                // Look to modify size and copies
                                if let Some(inputs_data_size) = node_data["inputs"].as_object_mut() {

                                    // Size
                                    if let Some(size_data) = openai_request.get("size").and_then(|v| v.as_str()) {
                                        debug!("✏️ Requested image size: {}", size_data);
                                        // Split and parse
                                        let size_data_split: Vec<i32> = size_data.split('x')
                                            .map(|p| p.parse().unwrap())
                                            .collect();

                                        inputs_data_size.insert(
                                            "width".to_string(),
                                            Value::String(size_data_split[0].to_string()),
                                        );
                                        inputs_data_size.insert(
                                            "height".to_string(),
                                            Value::String(size_data_split[1].to_string()),
                                        );
                                    } else {
                                        return Err(ProxyError::Json(format!("Failed to get size from JSON")));
                                    }

                                    // Copies
                                    if let Some(copies_num_data) = openai_request.get("n").and_then(|v| v.as_i64()) {
                                        debug!("✏️ Requested copies: {}", copies_num_data);
                                        inputs_data_size.insert(
                                            "batch_size".to_string(),
                                            Value::String(copies_num_data.to_string()),
                                        );

                                    } else {
                                        debug!("No \"c\" (copies) in JSON, default to 1");
                                    }


                                }   
                            }
                            "CLIPTextEncode" => {
                                // Look to modify prompts
                                if let Some(meta_data) = node_data["_meta"].as_object() {
                                    if let Some(title) = meta_data["title"].as_str() {
                                        if title == "Positive Prompt" { 
                                            // Modify here
                                            if let Some(inputs_data) = node_data["inputs"].as_object_mut() {

                                                if let Some(prompt_input) = openai_request.get("prompt").and_then(|v| v.as_str()) {
                                                    debug!("✏️ Requested prompt: {}", prompt_input);
                                                    inputs_data.insert(
                                                        "text".to_string(),
                                                        Value::String(prompt_input.to_string()),
                                                    );
                                                } else {
                                                    return Err(ProxyError::Json(format!("Failed to get prompt from JSON")));
                                                }
                                            }
                                        } else if title == "Negative Prompt" {
                                            // Modify here (if needed)
                                            if let Some(inputs_data) = node_data["inputs"].as_object_mut() {

                                                if let Some(neg_prompt_input) = openai_request.get("negative_prompt").and_then(|v| v.as_str()) {
                                                    debug!("✏️ Requested negative prompt: {}", neg_prompt_input);
                                                    inputs_data.insert(
                                                        "text".to_string(),
                                                        Value::String(neg_prompt_input.to_string()),
                                                    );
                                                } else {
                                                    debug!("No negative_prompt in JSON");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                continue
                            }
                        }
                            

                    }
                }
            }

        }

        
        

        debug!("🔧 Generated JSON payload");

    }

    let modified_json = serde_json::to_vec(&pipeline_use)
        .map_err(|e| ProxyError::Json(format!("Failed to serialize JSON: {}", e)))?;

    Ok(Bytes::from(modified_json))
}

/// Regular response handler, will receive the response and then send it back to
/// the proxied source
async fn handle_regular_response(
    upstream_response: reqwest::Response,
    target_base: String, 
    headers: HeaderMap,
    client: &Client,
    ws_manager: &Arc<WebSocketManager>,
) -> Result<AxumResponse, ProxyError> {
    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();

    debug!("📄 Handling regular response with status: {}", status);

    let body_bytes = upstream_response
        .bytes()
        .await
        .map_err(|e| ProxyError::Upstream(format!("Failed to read response body: {}", e)))?;

    debug!("📥 Response body: {} bytes", body_bytes.len());

    // Read all the body as a json, it should be a json
    let json: Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ProxyError::Json(format!("Failed to parse JSON: {}", e)))?;

    debug!(
            "📝 Received response: {}",
            json.to_string()
        );

    // Check for prompt_id in the response
    let prompt_id = json.get("prompt_id").and_then(|v| v.as_str());
    if let Some(pid) = prompt_id {
        debug!(
            "📝 Found prompt_id in response: {}. Waiting for job completion...",
            pid
        );

        // Wait for the job to complete via WebSocket
        if let Err(e) = ws_manager.wait_for_job_completion(pid).await {
            warn!("⚠️ Failed to wait for job completion: {}", e);
            // Continue anyway, don't fail the response
        }
    }

    // Call history to retrieve image location
    let image_response_json = retrieve_image_from_history(
        target_base,
        prompt_id,
        headers.clone(),
        client,
    )
    .await?;



    let output_json = serde_json::to_vec(&image_response_json)
        .map_err(|e| ProxyError::Json(format!("Failed to serialize JSON: {}", e)))?;
    let output_body_bytes = Bytes::from(output_json);
    debug!(
        "✏️ JSON regular response: {} bytes",
        output_body_bytes.len()
    );

    // Copy headers
    let mut response_headers = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_str(name.as_str()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            if name.as_str() == "content-length" {
                // Replace context len with valid value
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

    let mut response = AxumResponse::builder().status(status.as_u16());

    for (name, value) in response_headers.iter() {
        response = response.header(name, value);
    }

    debug!("✅ Regular response built successfully");

    response
        .body(Body::from(output_body_bytes))
        .map_err(|e| ProxyError::Internal(format!("Failed to build regular response: {}", e)))
}


async fn retrieve_image_from_history(
    target_base: String,
    prompt_id: Option<&str>,
    headers: HeaderMap,
    client: &Client,
) -> Result<Value, ProxyError> {

    // Handle case where prompt_id is None
    let prompt_id = match prompt_id {
        Some(id) => id,
        None => {
            error!("⚠️ No prompt_id received!");
            return Err(ProxyError::Upstream(format!(
                    "No prompt_id received.",
                )));
        }
    };

    // Append the target path
    let history_url: String = format!("http://{}/history/{}", target_base, prompt_id);

    debug!("🔍 Checking history at {} for {}", target_base, prompt_id);

    let mut upstream_headers = reqwest::header::HeaderMap::new();

    // Add authorization header if present in original request
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_value) = reqwest::header::HeaderValue::from_bytes(auth.as_bytes()) {
            upstream_headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }
    }

    // Debug: Print all headers being sent
    debug!("📋 Headers to send (if any):");
    for (name, value) in upstream_headers.iter() {
        debug!("   {}: {}", name, value.to_str().unwrap_or("[unprintable]"));
    }
    
    // Build request
    let request_builder = 
        // set client
        client
        // add method and endpoint
        .request(Method::GET, &history_url)
        // add headers
        .headers(upstream_headers.clone());

    debug!("⏳ Sending history request to backend...");
    
    // Add a timeout wrapper to catch hanging requests
    let request_future = request_builder.send();
    let timeout_duration = Duration::from_secs(5);

    // Await the request future
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


    // Get history data:
    let response_body = upstream_response
        .bytes()
        .await
        .map_err(|e| ProxyError::Upstream(format!("Failed to read history response body: {}", e)))?;
    let history_json: Value = serde_json::from_slice(&response_body)
        .map_err(|e| ProxyError::Json(format!("Failed to parse history JSON: {}", e)))?;
    // debug!("✅ Retrieved history: {}", history_json.to_string());


    // Look for job image name and path
    let mut image_files: Vec<ImageFile> = Vec::new();
    if let Some(prompt_hist) = history_json.get(prompt_id).and_then(|v| v.as_object()) {
        if let Some(out_nodes) = prompt_hist.get("outputs").and_then(|v| v.as_object())
        {
            for (node_id, out_node_data) in out_nodes {
                if let Some(all_images_data) = out_node_data.get("images").and_then(|v| v.as_array())
                {
                    for image_data in all_images_data {
                        if let Some(type_field) = image_data["type"].as_str() {
                            if type_field == "output" {
                                if let Some(filename) = image_data["filename"].as_str() {
                                    if let Some(subfolder) = image_data["subfolder"].as_str() {
                                        debug!("🔍 Found: filename: {}, subfolder: {}", filename, subfolder);
                                        image_files.push(ImageFile {
                                            filename: filename.to_string(),
                                            subfolder: subfolder.to_string(),
                                            type_field: type_field.to_string()
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
        return Err(ProxyError::Upstream(format!(
                "No prompt_id history found.",
            )));
    }

    debug!("📦 Collected {} image files", image_files.len());
    let mut response_data: Vec<serde_json::Value> = Vec::new();
    for image_file_data in image_files {

        let view_query = serde_urlencoded::to_string(&image_file_data).
            map_err(|e| ProxyError::Json(format!("Failed to serialize image data query: {}", e)))?;

        let view_url: String = format!("http://{}/view?{}", target_base, view_query);


        // Build request
        let request_builder = 
            // set client
            client
            // add method and endpoint
            .request(Method::GET, &view_url)
            // add headers
            .headers(upstream_headers.clone());

        debug!("⏳ Sending view request to backend: {}", view_query);
        
        // Add a timeout wrapper to catch hanging requests
        let request_future = request_builder.send();
        let timeout_duration = Duration::from_secs(5);

        // Await the request future
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

        
        let image_bytes = view_response.bytes().await?;
        debug!("📋 Read {} image bytes", image_bytes.len());
        let b64_image = general_purpose::STANDARD.encode(image_bytes);
        response_data.push(serde_json::json!({
            "b64_json": b64_image
        }));
    }


    // Create response with image files
    let created = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| ProxyError::Internal("Failed to get current time".to_string()))?
    .as_secs() as i64;

     Ok(serde_json::json!({
       "data": response_data,
       "created": created
   }))

}