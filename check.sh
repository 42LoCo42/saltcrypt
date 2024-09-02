#!/usr/bin/env bash
set -euo pipefail
export PATH="$PATH:$PWD"

trap 'rm -f key0 key1 key2 raw sum enc' EXIT

key0="$(saltcrypt genkey 2>&1 >key0)"
key1="$(saltcrypt genkey 2>&1 >key1)"
key2="$(saltcrypt genkey 2>&1 >key2)"

head -c 32 /dev/urandom >raw
sha256sum <raw >sum
saltcrypt encrypt raw "$key0" "$key1" >enc

saltcrypt decrypt enc key0 | sha256sum -c sum
saltcrypt decrypt enc key1 | sha256sum -c sum
saltcrypt decrypt enc key2 && exit 1

head -c 32 /dev/urandom >raw
sha256sum <raw >sum
saltcrypt encrypt raw "$key1" "$key2" >enc

saltcrypt decrypt enc key0 && exit 1
saltcrypt decrypt enc key1 | sha256sum -c sum
saltcrypt decrypt enc key2 | sha256sum -c sum
