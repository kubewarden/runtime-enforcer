#!/usr/bin/env bash

set -euo pipefail

mode="${1:-diff}"

if [[ "$mode" != "diff" && "$mode" != "apply" ]]; then
  printf 'usage: %s [diff|apply]\n' "$0" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
tmp_manifest="$(mktemp "$repo_root/updatecli/.bpf-kernel-versions.local.XXXXXX.yaml")"

cleanup() {
  rm -f "$tmp_manifest"
}

trap cleanup EXIT

python3 - "$repo_root/updatecli/updatecli.d/bpf-kernel-versions.yaml" "$tmp_manifest" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
target = Path(sys.argv[2])

result = []
skip_block = False

for line in source.splitlines():
    if line.startswith("actions:") or line.startswith("scms:"):
        skip_block = True
        continue

    if skip_block:
        continue

    if line.strip() == "scmid: default":
        continue

    result.append(line)

target.write_text("\n".join(result) + "\n")
PY

docker run --rm \
  -v "$repo_root:/workspace" \
  -w /workspace \
  updatecli/updatecli:latest \
  pipeline "$mode" --config "${tmp_manifest#$repo_root/}"
