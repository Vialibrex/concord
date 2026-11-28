#!/bin/sh
# build.sh <goos> <goarch> <out-dir>
# Builds the Tailscale node library for one platform. omit-tags.txt leaves out tailscale features
# a node used as an outbound never runs, and go.mod pins the module versions mihomo uses. CC names
# the target's C compiler, which cgo needs for the c-shared runtime glue; GO names the go binary
# when it is not on PATH; GOARM, GOFLAGS and GOPROXY pass through.
set -eu
goos=$1 goarch=$2
case $goos in
  windows) name=concord_tsnet.dll ;;
  darwin|ios) name=libconcord_tsnet.dylib ;;
  *) name=libconcord_tsnet.so ;;
esac
go=${GO:-go}
command -v "$go" >/dev/null || { echo "build.sh: the Tailscale library needs a Go toolchain (go on PATH, or GO)" >&2; exit 1; }
mkdir -p "$3"
out=$(cd "$3" && pwd)
cd "$(dirname "$0")"
# The library's bytes, which a packaged Concord pins, depend on the compiler: go.mod's toolchain
# line names the one release builds use.
want=$(sed -n 's/^toolchain //p' go.mod)
have=$(GOTOOLCHAIN=local "$go" env GOVERSION)
[ "$have" = "$want" ] || { echo "build.sh: the Tailscale library is built with $want, not $have" >&2; exit 1; }
tags=$(tr '\n' ' ' < omit-tags.txt)
CGO_ENABLED=1 GOOS=$goos GOARCH=$goarch GOTOOLCHAIN=local "$go" build -buildmode=c-shared -trimpath \
  -buildvcs=false -tags "$tags" -ldflags "-s -w -buildid=" -o "$out/$name" .
rm -f "$out/${name%.*}.h"
echo "$out/$name"
