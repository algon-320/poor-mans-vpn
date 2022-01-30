#!/bin/sh

# Is stdout attached to TTY?
if [[ -t 1 ]]; then
    echo "Usage: $0 < private_key.der > public_key.der"
    exit 1
fi

openssl pkey -inform DER -in - -pubout -outform DER -out - | tail -c 32
