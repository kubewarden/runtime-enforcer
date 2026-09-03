- [Setup Development Environments](#setup-development-environments)
  - [Pre-requisite](#pre-requisite)
  - [Steps](#steps)
  - [Optional](#optional)
    - [golangci-lint](#golangci-lint)
  - [Verified environment](#verified-environment)

# Setup Development Environments

Runtime enforcer supports Tilt to run development environment in your local.

## Pre-requisite

- On a supported Linux host to run a local kubernetes cluster, install a one node kubernetes cluster.
- Setup golang development environments.

## Steps

1. Clone the repository: `git clone https://github.com/kubewarden/runtime-enforcer.git`.
2. Install [kubectl](https://kubernetes.io/docs/reference/kubectl/) and [helm](https://helm.sh/).
3. Install [tilt](https://docs.tilt.dev/install.html).
4. Install [libbpf](https://github.com/libbpf/libbpf), so you can build ebpf programs at your local.
5. Create `tilt-settings.yaml` based on `tilt-settings.yaml.example`.
6. Run `tilt up`.  Related resources should be built and deployed.

You can use this command to list the policy proposals:

```sh
kubectl get workloadpolicyproposals.security.rancher.io -A
```

## Optional

### golangci-lint

You may want to install a pre-commit hook for golangci-lint, so you can fix linter issues at your local.

1. Install golangci-lint, e.g., `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0`
2. Install pre-commit hooks. You can also use tools like [husky](https://typicode.github.io/husky/) or [pre-commit](https://pre-commit.com/).

```sh
cat << EOF > .git/hooks/pre-commit
#!/bin/sh
golangci-lint-v2 run
EOF
chmod +x .git/hooks/pre-commit
```

If you are using [pre-commit](https://pre-commit.com/), you can run the following command to install the hooks we define in `.pre-commit-config.yaml`:

```sh
pre-commit install --install-hooks --hook-type pre-commit --overwrite
# if you want to disable the hook
pre-commit uninstall --hook-type pre-commit  
```

## Verified environment

- [Kind](https://kind.sigs.k8s.io/) v1.32.2
- Ubuntu 22.04.5 LTS with 6.8.0-52-generic kernel.

## Run bpfvalidator on our ebpf instrumentation

As a first thing, install bpfvalidator on you machine downloading it from <https://github.com/Andreagit97/bpfvalidator/releases>, or build it from source.

From the root of the repo

```sh
# generate a binary with bpf tests called `tester`
go test -c ./internal/bpf/... -o tester
# install bpfvalidator on you machine https://github.com/Andreagit97/bpfvalidator/releases
bpfvalidator --config ./bpfvalidator-amd64-config.yaml --cmd="./tester -test.v"
```
