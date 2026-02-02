# Technology Stack

## Core Backend
- **Language:** Rust (Edition 2024) - Chosen for high performance, memory safety, and excellent concurrency support via the Tokio ecosystem.
- **Web Framework:** [Axum (v0.7)](https://github.com/tokio-rs/axum) - An ergonomic and modular web framework built on top of `tower`, `hyper`, and `tokio`.
- **Async Runtime:** [Tokio (v1.0)](https://tokio.rs/) - The industry-standard asynchronous runtime for Rust, providing the foundation for high-throughput network applications.

## Communication & Data
- **HTTP Client:** [Reqwest (v0.12)](https://github.com/seanmonstar/reqwest) - Used for communicating with the ComfyUI backend REST API.
- **Serialization/Deserialization:** [Serde](https://serde.rs/) (JSON & YAML) - For robust and efficient handling of configuration files and API payloads.
- **WebSocket:** [tokio-tungstenite (v0.21)](https://github.com/snapview/tokio-tungstenite) - Enables persistent, low-latency communication with ComfyUI for real-time job tracking.

## Infrastructure & Deployment
- **Containerization:** Docker - Ensures consistent environments across development and production.
- **Orchestration:** Docker Compose - Simplifies the management of the proxy alongside the ComfyUI backend and its GPU dependencies.
- **CI/CD Target:** Linux-based containers (Alpine/Debian) for minimal footprint.
