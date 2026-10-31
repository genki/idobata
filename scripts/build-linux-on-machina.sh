#!/usr/bin/env bash
# 既存Machina/Colimaでビルドし、完了・ハッシュ照合後に成果物を受け取る。
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:-/tmp/idobata-linux-x86_64}
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
tar --exclude='*/target' -czf "$work/source.tgz" -C "$root" Cargo.toml Cargo.lock crates profiles schemas
source_sha=$(sha256sum "$work/source.tgz" | awk '{print $1}')
ssh -o BatchMode=yes machinaai 'mkdir -p /Users/machinaai/.cache/idobata-linux-source/out'
scp -q "$root/ops/linux-builder.Dockerfile" machinaai:/Users/machinaai/.cache/idobata-linux-source/Dockerfile
scp -q "$work/source.tgz" machinaai:/Users/machinaai/.cache/idobata-linux-source/source.tgz
ssh -o BatchMode=yes machinaai "set -e; cd /Users/machinaai/.cache/idobata-linux-source; test \"\$(shasum -a 256 source.tgz | awk '{print \$1}')\" = '$source_sha'; tar xzf source.tgz; export PATH=/Applications/Docker.app/Contents/Resources/bin:/opt/homebrew/bin:\$PATH; docker --context colima build -t idobata-linux-builder:v02 .; docker --context colima run --rm --cpus 4 --memory 8g -v \"\$PWD:/workspace\" -v idobata-linux-target-v02:/target -v majutsu-cargo-registry:/usr/local/cargo/registry -v majutsu-sccache:/sccache -w /workspace idobata-linux-builder:v02 bash -ec 'cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu -p idobata; cp /target/x86_64-unknown-linux-gnu/release/idobata out/idobata-linux-x86_64'"
expected=$(ssh -o BatchMode=yes machinaai 'shasum -a 256 /Users/machinaai/.cache/idobata-linux-source/out/idobata-linux-x86_64' | awk '{print $1}')
scp -q machinaai:/Users/machinaai/.cache/idobata-linux-source/out/idobata-linux-x86_64 "$work/binary"
actual=$(sha256sum "$work/binary" | awk '{print $1}')
[[ "$actual" == "$expected" ]]
chmod 755 "$work/binary"
"$work/binary" --version
install -m 755 "$work/binary" "$output"
printf 'source_sha256=%s\nbinary_sha256=%s\n' "$source_sha" "$actual"
