FROM rust:1.79 as builder

WORKDIR /
RUN cargo new --bin ctfnote-extra
WORKDIR /ctfnote-extra
COPY ./Cargo.toml ./Cargo.lock ./
RUN cargo build --release
RUN rm -r ./src

ADD . .
RUN rm ./target/release/deps/ctfnote_extra*
RUN cargo build --release

FROM debian:12.5-slim
# RUN pt-get update && apt-get install -y extra-runtime-dependencies && rm -rf /var/lib/apt/lists/*
COPY --from=builder /ctfnote-extra/target/release/ctfnote-extra /app/ctfnote-extra
WORKDIR /app
CMD ["./ctfnote-extra"]
