FROM rust:alpine
RUN apk update && apk add \
    alpine-sdk \
    bash \
    iptables \
    linux-headers

WORKDIR /root

RUN mkdir /root/vpn
COPY Cargo.toml /root/vpn/
COPY src /root/vpn/src
RUN cargo install --path /root/vpn

COPY genkey.sh pubkey.sh /root/
COPY server-config.toml client-config.toml /root/
