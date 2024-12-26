FROM rust:slim-bookworm AS builder

RUN update-ca-certificates

ENV USER=jitsi-openid
ENV UID=10001

RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "${UID}" \
  "${USER}"

RUN apt-get update \
  && apt-get install -y pkg-config libssl-dev

RUN cargo new --bin jitsi-openid

WORKDIR /jitsi-openid

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN cargo build --release \
  && rm src/*.rs target/release/deps/jitsi_openid*

COPY ./src ./src
RUN cargo build --release

FROM debian:bookworm-slim

ENV LISTEN_ADDR=0.0.0.0:3000
EXPOSE 3000

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /jitsi-openid

COPY --from=builder /jitsi-openid/target/release/jitsi-openid ./jitsi-openid

USER jitsi-openid:jitsi-openid

CMD ["/jitsi-openid/jitsi-openid"]
