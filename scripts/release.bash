#!/usr/bin/env bash
set -euo pipefail

version() {
    sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml
}

validate() {
    local tag=$1 expected
    expected="v$(version)"
    [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $tag == "$expected" ]] || {
        printf 'Tag %s must exactly match Cargo.toml (%s)\n' "$tag" "$expected" >&2
        return 1
    }
}

case ${1-} in
    version) version ;;
    validate) validate "${2-}" ;;
    package)
        tag=${2:?tag required}
        target=${3:?target required}
        output=${4:?output directory required}
        validate "$tag"
        case $target in x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;; *) exit 1 ;; esac
        [[ $(rustc -vV | sed -n 's/^host: //p') == "$target" ]] || { printf '%s\n' 'Native build target mismatch' >&2; exit 1; }
        binary="${CARGO_TARGET_DIR:-target}/release/ctf"
        [[ $("$binary" --version) == "ctf ${tag#v}" ]]
        stage=$(mktemp -d)
        trap 'rm -rf -- "$stage"' EXIT
        install -m755 "$binary" "$stage/ctf"
        strip "$stage/ctf"
        install -m644 README.md LICENSE "$stage/"
        mkdir -p "$output"
        asset="$output/ctf-$tag-$target.tar.gz"
        epoch=$(git log -1 --format=%ct)
        # Stable archive ordering, ownership and timestamps; never overwrite an artifact.
        set -C
        tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
            -C "$stage" -cf - LICENSE README.md ctf | gzip -n > "$asset"
        [[ $(tar -tzf "$asset" | paste -sd ' ' -) == 'LICENSE README.md ctf' ]]
        printf '%s\n' "$asset"
        ;;
    *) printf '%s\n' 'usage: release.bash version | validate TAG | package TAG TARGET OUTPUT' >&2; exit 2 ;;
esac
