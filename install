#!/bin/bash
set -e
cd "$(dirname "$0")"

patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 src-tauri/holochain-bin 2>/dev/null || true
npx @tauri-apps/cli build --debug

patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 target/debug/toric
patchelf --set-rpath /usr/lib/x86_64-linux-gnu target/debug/toric

rm -rf target/debug/bundle/deb/toric-unpacked
cd target/debug/bundle/deb
dpkg-deb -R Toric_0.1.0_amd64.deb toric-unpacked

# Patch the holochain binary inside the deb before repackaging
cp ../../../../src-tauri/holochain-bin toric-unpacked/usr/lib/Toric/holochain
chmod +x toric-unpacked/usr/lib/Toric/holochain
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 toric-unpacked/usr/lib/Toric/holochain
patchelf --set-rpath /usr/lib/x86_64-linux-gnu toric-unpacked/usr/lib/Toric/holochain

patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 toric-unpacked/usr/bin/toric
patchelf --set-rpath /usr/lib/x86_64-linux-gnu toric-unpacked/usr/bin/toric

dpkg-deb -b toric-unpacked Toric_0.1.0_amd64.deb
sudo dpkg -i Toric_0.1.0_amd64.deb
