#!/bin/bash
# Run Toric with system linker (patches nix glibc dependency)
BINARY="${1:-target/debug/toric}"
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 "$BINARY" 2>/dev/null
exec "$BINARY"
