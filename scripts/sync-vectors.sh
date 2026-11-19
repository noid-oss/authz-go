#!/usr/bin/env bash
# Copies vectors.json from the authz-spec repo into testdata/ and pins its sha256.
# Usage: scripts/sync-vectors.sh [path-to-authz-spec]   (default ../authz-spec)
# Never edit testdata/vectors.json by hand: change authz-spec, then re-run this.
set -euo pipefail
cd "$(dirname "$0")/.."
spec="${1:-../authz-spec}"
src="$spec/vectors.json"
[[ -f "$src" ]] || { echo "missing $src" >&2; exit 1; }
cp "$src" testdata/vectors.json
shasum -a 256 testdata/vectors.json | awk '{print $1}' > testdata/vectors.json.sha256
echo "synced $src -> testdata/vectors.json ($(cat testdata/vectors.json.sha256))"
