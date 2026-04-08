FROM rust:1.94-slim-trixie AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY src ./src

RUN cargo build --release --no-default-features --bin fips --bin fipsctl && \
    cp target/release/fips target/release/fipsctl /usr/local/bin/

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        netcat-openbsd \
        procps && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/fips /usr/local/bin/fipsctl /usr/local/bin/

WORKDIR /config

CMD ["fips", "--config", "/config/fips.yaml"]
