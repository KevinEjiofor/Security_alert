# ---- Build Stage ----
FROM rust:1.82 AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy all source files at once to avoid the patch issue
COPY . .

# Clean any existing builds and build fresh
RUN cargo clean && cargo build --release

# ---- Runtime Stage ----
FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y ca-certificates libssl1.1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/security_alert .

# Copy .env file if it exists (optional)
COPY .env* ./

# Create a non-root user for security
RUN useradd -m -u 1001 appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["./security_alert"]