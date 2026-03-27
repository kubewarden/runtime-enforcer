#!/usr/bin/env bash

set -euo pipefail

minor="${1:?minor series required, e.g. 6.6}"
artifact_arch="${2:?artifact architecture required, e.g. amd64}"

base_url="https://kernel.ubuntu.com/mainline"

case "$artifact_arch" in
  amd64)
    required_patterns=(
      "linux-image-unsigned-${minor//./\\.}\\.[0-9]+-[^\"]*_amd64\\.deb"
      "linux-modules-${minor//./\\.}\\.[0-9]+-[^\"]*_amd64\\.deb"
    )
    ;;
  arm64)
    required_patterns=(
      "linux-image-unsigned-${minor//./\\.}\\.[0-9]+-[^\"]*_arm64\\.deb"
      "linux-modules-${minor//./\\.}\\.[0-9]+-[^\"]*_arm64\\.deb"
    )
    ;;
  *)
    printf 'unsupported artifact architecture: %s\n' "$artifact_arch" >&2
    exit 1
    ;;
esac

mapfile -t candidates < <(
  curl -fsSL "$base_url/" |
    perl -ne 'while (m{href="(v[0-9]+\.[0-9]+\.[0-9]+)/"}g) { print "$1\n" }' |
    grep -E "^v${minor//./\.}\.[0-9]+$" |
    sort -V -r
)

if [[ ${#candidates[@]} -eq 0 ]]; then
  printf 'no Ubuntu mainline versions found for %s\n' "$minor" >&2
  exit 1
fi

for version in "${candidates[@]}"; do
  listing="$(curl -fsSL "$base_url/$version/$artifact_arch/")"
  missing=0

  for pattern in "${required_patterns[@]}"; do
    if ! grep -Eq "$pattern" <<<"$listing"; then
      missing=1
      break
    fi
  done

  if [[ $missing -eq 0 ]]; then
    printf '%s\n' "$version"
    exit 0
  fi
done

printf 'no version in %s has the required %s artifacts\n' "$minor" "$artifact_arch" >&2
exit 1
