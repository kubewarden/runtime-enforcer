# Updatecli

This repository uses Updatecli policies from `updatecli/updatecli.d` and `updatecli/updatecli.release.d`.

## Manual testing

If `updatecli` is not installed locally, you can run it with Docker.

To validate the BPF kernel policy locally without GitHub credentials:

```sh
./updatecli/run-bpf-kernel-versions-local.sh diff
```

This helper script:

- runs `updatecli` via Docker
- strips the GitHub `scms` and `actions` blocks from `updatecli/updatecli.d/bpf-kernel-versions.yaml`
- keeps the real shell sources and file targets, so you can verify matching and replacements locally
- uses `updatecli/scripts/latest-ubuntu-mainline-kernel.sh` to skip versions that do not expose the required Ubuntu mainline artifacts for the configured architecture

To apply the changes to your working tree on purpose:

```sh
./updatecli/run-bpf-kernel-versions-local.sh apply
```
