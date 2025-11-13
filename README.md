![ever growing...](./assets/banner.png)

# ComfyUI OpenAI API Proxy

A high-performance reverse proxy that translates OpenAI image generation API calls into ComfyUI backend requests. This enables clients to use the standard OpenAI API while leveraging ComfyUI's powerful workflow engine for image generation.

## Overview

This proxy serves as a bridge between OpenAI API-compatible clients and ComfyUI. It:

- **Accepts** standard OpenAI image generation requests (`POST /v1/images/generations`)
- **Translates** OpenAI parameters to ComfyUI workflow format
- **Manages** job execution via persistent WebSocket connection
- **Retrieves** generated images from ComfyUI backend
- **Returns** responses in OpenAI API format (base64-encoded images)

## Architecture

### Components

- **HTTP Server** (Axum): Handles incoming OpenAI API requests with CORS support
- **HTTP Client** (Reqwest): Communicates with ComfyUI backend for workflow execution
- **WebSocket Manager**: Persistent connection to ComfyUI for job tracking
- **Workflow Loader**: Manages ComfyUI workflow definitions
- **Request Translator**: Converts OpenAI format to ComfyUI format

### Request Flow

```
Client Request (OpenAI format)
    ↓
[Proxy Server - HTTP Handler]
    ↓
[Request Translator]
    - Extract model name → lookup workflow
    - Extract prompt, size, batch count
    - Transform to ComfyUI prompt format
    ↓
[ComfyUI Backend - /prompt endpoint]
    Returns: { prompt_id: "..." }
    ↓
[WebSocket Manager - Job Tracking]
    Waits for: { type: "executing", data: { node: null } }
    ↓
[Image Retrieval]
    - Query /history/{prompt_id}
    - Download images from /view endpoint
    - Base64 encode images
    ↓
Client Response (OpenAI format)
    { data: [ { b64_json: "..." } ], created: ... }
```

## Getting Started

### Prerequisites

- Rust 1.70+ (for building)
- Docker and Docker Compose (for deployment)
- ComfyUI backend running on accessible network

### Installation

1. Clone the repository:
```bash
cd apps/rust/comfyui-openai-api
```

2. Create configuration file:
```bash
cp config/config.sample.yaml config/config.yaml
```

3. Edit `config/config.yaml` with your settings:
```yaml
log_level: debug
server:
  host: "0.0.0.0"
  port: 8080
comfyui_backend:
  host: "comfyui"
  port: 8188
  client_id: "openai-proxy-client"
  workflows_folder: "./workflows"
routing:
  timeout_seconds: 120
  max_payload_size_mb: 10
```

4. Place workflow JSON files in the `workflows` folder:
```bash
cp ../../workflows/*.json workflows/
```

### Running

#### Local Development

```bash
# Build
cargo build --release

# Run
./target/release/comfyui-openai-api
```

#### Docker

```bash
# Build image
docker build -t comfyui-openai-api .

# Run container
docker run -p 8080:8080 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/workflows:/app/workflows \
  comfyui-openai-api
```

#### Docker Compose

(coming soon, currently it only launches a ComfyUI backend for testing)

```bash
docker-compose up --build
```

## Configuration

### Environment Variables

- `CONFIG_PATH`: Path to YAML configuration file (default: `./config/config.yaml`)
- `RUST_LOG`: Logging level (debug, info, warn, error) - set by config file

### Configuration File (config.yaml)

```yaml
# Logging level
log_level: debug

# Proxy server configuration
server:
  host: "0.0.0.0"        # Bind address
  port: 8080             # Listen port

# ComfyUI backend connection
comfyui_backend:
  host: "localhost"      # ComfyUI host
  port: 8188             # ComfyUI port
  client_id: "proxy"     # Unique ID for WebSocket
  workflows_folder: "./workflows"  # Path to workflow JSONs

# Request routing settings
routing:
  timeout_seconds: 120   # Request timeout
  max_payload_size_mb: 10 # Max request body size
```

## API Usage

### Endpoint

```
POST /v1/images/generations
```

### Request Format

Compatible with OpenAI image generation API:

```json
{
  "model": "animagine-xl-4",
  "prompt": "1girl, cyberpunk style, astronaut suit, looking at viewer, smile, outdoors, neon city, \"PNYX\", night, v, masterpiece, high score, great score, absurdres",
  "size": "832x1216",
  "n": 1
}
```

### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `model` | string | Yes | Workflow name (filename without .json) |
| `prompt` | string | Yes | Positive prompt for image generation |
| `negative_prompt` | string | No | Negative prompt to avoid |
| `size` | string | Yes | Image dimensions: "1024x1024", "768x768", etc. |
| `n` | integer | No | Number of images to generate (default: 1) |

### Response Format

OpenAI-compatible response with base64-encoded images:

```json
{
  "data": [
    {
      "b64_json": "iVBORw0KGgoAAAANSUhEUgAAAAUA..."
    }
  ],
  "created": 1704067200
}
```

### Example Requests

#### cURL

```bash
curl -X POST http://localhost:8080/v1/images/generations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "animagine-xl-4",
    "prompt": "a cat wearing a hat",
    "size": "832x1216",
    "n": 1
  }'
```

#### Python (with OpenAI client)

```python
from openai import OpenAI

client = OpenAI(
    api_key="dummy-key",  # Not used by proxy
    base_url="http://localhost:8080/v1"
)

response = client.images.generate(
    model="animagine-xl-4",
    prompt="a cat wearing a hat",
    size="832x1216",
    n=1,
    response_format="b64_json"
)

print(response.data[0].b64_json)
```

## Workflow Management

### Creating Workflows

1. Create workflow in ComfyUI UI
2. Export as JSON
3. Place in `workflows/` folder
4. Reference by filename (without `.json`) in API calls, using the `model` field.

### Example Workflow

You will find example workflows in  `./workflows`. Please download the model's weights and place them in the correct folders before trying to use them!

### Node Replacement

The proxy automatically modifies specific nodes:

- **EmptyLatentImage / EmptySD3LatentImage**: Updates `width`, `height`, `batch_size`
- **CLIPTextEncode (Positive Prompt)**: Updates `text` with prompt
- **CLIPTextEncode (Negative Prompt)**: Updates `text` with negative_prompt

If you workflow needs other nodes to be modified, you can open an issue!

## Project Structure

```
./
├── apps/               # Project Apps
│   └── ...             # See below...
├── workflows/          # Example workflows
│   ├── animagine-xl-4.json  
│   ├── qwen_2-5_vl_7b.json  
│   └── ...
├── comfyui_docker/
│   ├── Dockerfile           # Container image definition for ComfyUI backend
│   ├── build.sh             # Build script for ComfyUI backend image
│   ├── .env.sample          # Sample file for backend enviroment variables needed
│   └── docker-compose.yaml  # Multi-container setup for backend (currently)
├── REEDME.md                # This readme!
```


Proxy app:

```
apps/rust/comfyui-openai-api/
├── src/
│   ├── main.rs          # Server setup and configuration
│   ├── config.rs        # Configuration management
│   ├── proxy.rs         # HTTP request routing
│   ├── comfyui.rs       # Backend communication and translation
│   └── ws.rs            # WebSocket job tracking
├── config/
│   └── config.sample.yaml  # Configuration template
├── Dockerfile           # Container image definition
└── build.sh             # Build script
```

## Module Documentation

### main.rs
Entry point and server initialization. Sets up the Axum HTTP server, initializes WebSocket connection, loads workflows, and configures middleware.

### config.rs
Configuration struct definitions and YAML file loading. Handles server, backend, and routing settings.

### proxy.rs
HTTP request routing and error handling. Routes `/v1/images/*` requests to appropriate handlers and converts errors to HTTP responses.

### comfyui.rs
Core translation logic. Converts OpenAI API requests to ComfyUI format, submits to backend, retrieves images, and formats responses.

### ws.rs
WebSocket management for job tracking. Maintains persistent connection to ComfyUI backend and monitors job completion via WebSocket messages.

## Performance Characteristics

- **Concurrency**: 8 worker threads (configurable) for handling concurrent requests
- **Connection Pooling**: Reusable HTTP client with connection pooling
- **Memory**: Circular buffer (100 jobs) for tracking completions prevents memory leaks
- **Timeouts**: Configurable request timeouts (default 120s) prevent hanging connections
- **Payload Size**: Configurable max request body size (default 10MB)

## Monitoring and Debugging

### Logging

Set `log_level` in configuration to control verbosity:
- `debug`: Detailed request/response information
- `info`: General operational information
- `warn`: Warnings and recoverable errors
- `error`: Error conditions only

## Contributing

Contributions are welcome. Please follow these guidelines:
- Add comments to all public functions and modules
- Update documentation for user-facing changes
- Test with various workflow configurations
- Report bugs with reproduction steps

