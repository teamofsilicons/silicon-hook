FROM rust:1.98.0-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --locked --release --bins

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin hook

COPY --from=builder /build/target/release/hook-api /usr/local/bin/hook-api
COPY --from=builder /build/target/release/hook-worker /usr/local/bin/hook-worker
COPY --from=builder /build/target/release/hook-migrate /usr/local/bin/hook-migrate

USER hook
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hook-api"]
