#!/usr/bin/env sh
set -eu

architecture="$(uname -m)"
case "$architecture" in
    x86_64) artifact_arch="amd64" ;;
    aarch64|arm64) artifact_arch="arm64" ;;
    *)
        echo "Unsupported architecture: $architecture" >&2
        exit 2
        ;;
esac

python3 -m PyInstaller --clean --noconfirm pgsecurecheck.spec

artifact="pgsecurecheck-linux-${artifact_arch}"
mv dist/pgsecurecheck "dist/${artifact}"
chmod 755 "dist/${artifact}"

"dist/${artifact}" checks >/dev/null
(
    cd dist
    sha256sum "$artifact" >SHA256SUMS
)

echo "Created dist/${artifact}"

