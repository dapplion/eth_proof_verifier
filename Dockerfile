FROM rust:1.99-slim-bookworm AS builder
WORKDIR /src
COPY . .
# Locked, as the release binaries are: the SP1 and ZisK pins are exact on purpose.
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/eth_proof_verifier /usr/local/bin/eth_proof_verifier
USER nobody
EXPOSE 8025
ENTRYPOINT ["eth_proof_verifier"]
# The binary listens on loopback by default, which a container cannot be reached on.
CMD ["--listen-address", "0.0.0.0:8025"]
