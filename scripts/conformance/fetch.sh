#!/usr/bin/env bash
# Fetch and SHA-256-verify a pinned third-party conformance suite (N2.2, #66).
# Exits 2 on any missing entry, download failure, or SHA-256 mismatch.
set -euo pipefail

ROOT="$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")")"
LOCKFILE="${CONFORMANCE_LOCKFILE:-$ROOT/scripts/conformance/third_party.lock}"

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <suite> [dest_root]" >&2
    exit 2
fi

SUITE="$1"
DEST_ROOT="${2:-$ROOT/target/conformance}"

if [ ! -f "$LOCKFILE" ]; then
    echo "CONFORMANCE-FETCH ERROR: lockfile missing: $LOCKFILE" >&2
    exit 2
fi

VERSION=""
EXPECTED_SHA=""
URL=""
while read -r name ver sha url extra; do
    case "${name:-}" in
        ""|\#*) continue ;;
    esac
    if [ "$name" = "$SUITE" ]; then
        if [ -n "${extra:-}" ] || [ -z "${ver:-}" ] || [ -z "${sha:-}" ] || [ -z "${url:-}" ]; then
            echo "CONFORMANCE-FETCH ERROR: malformed lock entry for $SUITE" >&2
            exit 2
        fi
        VERSION="$ver"
        EXPECTED_SHA="$sha"
        URL="$url"
        break
    fi
done < "$LOCKFILE"

if [ -z "$VERSION" ]; then
    echo "CONFORMANCE-FETCH ERROR: suite '$SUITE' not found in $LOCKFILE" >&2
    exit 2
fi

if ! [[ "$EXPECTED_SHA" =~ ^[0-9a-f]{64}$ ]]; then
    echo "CONFORMANCE-FETCH ERROR: invalid sha256 in lockfile for $SUITE" >&2
    exit 2
fi

DOWNLOAD_DIR="$DEST_ROOT/downloads"
SRC_DIR="$DEST_ROOT/src/$SUITE"
case "$URL" in
    *.tar.bz2) EXT=".tar.bz2" ;;
    *.tar.xz)  EXT=".tar.xz" ;;
    *.tar.gz|*.tgz) EXT=".tar.gz" ;;
    *)
        echo "CONFORMANCE-FETCH ERROR: unsupported archive extension in URL: $URL" >&2
        exit 2
        ;;
esac
ARCHIVE="$DOWNLOAD_DIR/$SUITE-$VERSION$EXT"
STAMP="$SRC_DIR/.fetched-$EXPECTED_SHA"

mkdir -p "$DOWNLOAD_DIR"

verify_sha() {
    local file="$1"
    local actual
    actual="$(sha256sum "$file" | awk '{print $1}')"
    if [ "$actual" != "$EXPECTED_SHA" ]; then
        echo "CONFORMANCE-FETCH ERROR: sha256 mismatch for $SUITE" >&2
        echo "  expected: $EXPECTED_SHA" >&2
        echo "  actual:   $actual" >&2
        return 1
    fi
    return 0
}

if [ -f "$ARCHIVE" ]; then
    if ! verify_sha "$ARCHIVE"; then
        rm -f "$ARCHIVE"
        exit 2
    fi
else
    TMP_ARCHIVE="$ARCHIVE.tmp.$$"
    cleanup_tmp() {
        rm -f "${TMP_ARCHIVE:-}"
    }
    trap cleanup_tmp EXIT
    echo "Fetching $SUITE ($VERSION) from $URL..."
    if ! curl -fsSL --retry 3 --retry-delay 2 -o "$TMP_ARCHIVE" "$URL"; then
        echo "CONFORMANCE-FETCH ERROR: download failed for $SUITE" >&2
        exit 2
    fi
    if ! verify_sha "$TMP_ARCHIVE"; then
        exit 2
    fi
    mv -f "$TMP_ARCHIVE" "$ARCHIVE"
    trap - EXIT
fi

if [ ! -f "$STAMP" ]; then
    rm -rf "$SRC_DIR"
    mkdir -p "$SRC_DIR"
    tar -xf "$ARCHIVE" -C "$SRC_DIR" --strip-components=1
    printf '%s %s\n' "$VERSION" "$EXPECTED_SHA" > "$STAMP"
fi

echo "$SRC_DIR"
