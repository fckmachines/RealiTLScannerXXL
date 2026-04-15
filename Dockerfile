FROM rust:1.83-slim-bookworm AS build
WORKDIR /src

# Cache dependencies in their own layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src target/release/realitlscanner* target/release/deps/realitlscanner*

COPY src ./src
RUN cargo build --release && strip target/release/realitlscanner

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/realitlscanner /app/realitlscanner
COPY Country.mmdb /app/Country.mmdb
ENTRYPOINT ["/app/realitlscanner"]
