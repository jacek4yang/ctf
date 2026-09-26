#!/usr/bin/env bash
set -euo pipefail
asset=${1:?archive required}
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
[[ $(tar -tzf "$asset" | paste -sd ' ' -) == 'LICENSE README.md ctf' ]]
tar -xzf "$asset" -C "$root"
mkdir "$root/bin"
install -m755 "$root/ctf" "$root/bin/ctf"
"$root/bin/ctf" --version
bash tests/smoke.bash "$root/bin"
