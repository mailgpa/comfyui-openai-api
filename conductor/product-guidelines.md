# Product Guidelines

## Documentation & Prose Style
- **Tone:** Technical, direct, and concise. 
- **Focus:** Prioritize API accuracy, performance characteristics, and clear configuration examples.
- **Code Comments:** Use doc comments (`///`) for public modules and functions. Focus on the *why* and any specific performance implications or edge cases.

## Architectural Principles
- **Safety & Reliability:** Leverage Rust's type system and ownership model to ensure memory safety. Implement comprehensive error handling that translates backend failures into clear, standard OpenAI-compatible error responses.
- **Performance First:** Minimize unnecessary cloning and allocations. Use asynchronous patterns (Tokio/Axum) to handle high concurrency with minimal resource overhead.
- **Modular Translation:** Keep the workflow translation logic decoupled from the HTTP/WebSocket handling to allow for easy updates as ComfyUI nodes evolve.

## Visual & Project Identity
- **Consistency:** Maintain a professional and minimalist aesthetic in all project assets (e.g., banners, README formatting).
- **Naming:** Follow standard Rust naming conventions (`snake_case` for variables/functions, `PascalCase` for types).
