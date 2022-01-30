FROM alpine
RUN apk update && apk add \
    alpine-sdk \
    bash \
    iptables \
    linux-headers \
    tshark \
    vim

WORKDIR /root
RUN echo 'set -o vi' >> .bashrc

# install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN mkdir /root/vpn
COPY Cargo.toml /root/vpn/
COPY src /root/vpn/src
RUN bash -c '/root/.cargo/bin/cargo install --path vpn'

COPY genkey.sh pubkey.sh /root/
COPY server-config.toml client-config.toml /root/
