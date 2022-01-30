#!/bin/sh

# Is stdout attached to TTY?
if [[ -t 1 ]]; then
    echo "Usage: $0 > private_key.der"
    exit 1
fi

openssl genpkey -algorithm ED25519 -outform DER
