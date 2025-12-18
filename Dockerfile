# Build proxy binary
FROM rust:1.92-bookworm AS builder
WORKDIR /build
COPY apps/rust/comfyui-openai-api ./comfyui-openai-api
WORKDIR /build/comfyui-openai-api
RUN rustup update stable
RUN cargo build --release

# Runtime image with ComfyUI and proxy
FROM pytorch/pytorch:2.9.1-cuda12.8-cudnn9-devel

ENV CONFIG_PATH=/app/config/config.yaml
WORKDIR /app

# System dependencies for building and networking utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl ca-certificates pkg-config libssl-dev netcat-openbsd libgl1 && \
    rm -rf /var/lib/apt/lists/*

# Install ComfyUI via comfy-cli
RUN pip install --no-cache-dir comfy-cli opencv-python-headless PyWavelets matplotlib
RUN comfy-cli --skip-prompt install --nvidia

# Proxy binary and assets
RUN mkdir -p /app/bin /app/config /app/workflows
COPY --from=builder /build/comfyui-openai-api/target/release/comfyui-openai-api /app/bin/comfyui-openai-api
COPY workflows /app/workflows
COPY docker/config.yaml /app/config/config.yaml

# Entrypoint
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080 8188
ENTRYPOINT ["/app/entrypoint.sh"]
