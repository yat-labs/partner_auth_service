# syntax=docker/dockerfile:1

FROM buildpack-deps:stretch as builder

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    \
    url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain nightly-2020-08-03; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;

RUN USER=root cargo new --bin app
WORKDIR /app
COPY ./Cargo.toml ./Cargo.toml
COPY ./rust-toolchain ./rust-toolchain
RUN cargo build --release && rm src/*.rs

ADD . ./

RUN cargo build --release

FROM debian:buster-slim
RUN apt-get update \
    && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*;



COPY --from=builder /app/target/release/yat-partner /usr/bin/yat-partner

CMD ["/usr/bin/yat-partner"]
