- [Setup Development Environments](#setup-development-environments)
  - [Pre-requisite](#pre-requisite)
  - [Steps](#steps)
  - [Optional](#optional)
    - [golangci-lint](#golangci-lint)
  - [Verified environment](#verified-environment)

# Setup Development Environments

Runtime enforcement supports Tilt to run development environment in your local.

## Pre-requisite

- On a supported Linux host to run a local kubernetes cluster, install a one node kubernetes cluster.  Minikube is not supported.
- Setup golang development environments.

## Steps

1. Install [kubectl](https://kubernetes.io/docs/reference/kubectl/) and [helm](https://helm.sh/).
2. Install [tilt](https://docs.tilt.dev/install.html).
3. Create `tilt-settings.yaml` based on `tilt-settings.yaml.example`. You should use 
4. Run `tilt up`.  Related resources should be built and deployed.


You can use this command to list the policy proposals:

```sh
kubectl get workloadsecuritypolicyproposals.security.rancher.io -A
```

## Optional

### golangci-lint

You may want to install a pre-commit hook for golangci-lint, so you can fix linter issues at your local.
1. Install golangci-lint, e.g., `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0`
2. Install pre-commit hooks. You can also use tools like [husky](https://typicode.github.io/husky/) or [pre-commit](https://pre-commit.com/). 

```
cat << EOF > .git/hooks/pre-commit
#!/bin/sh
golangci-lint-v2 run
EOF
chmod +x .git/hooks/pre-commit
```

## Verified environment

- [Kind](https://kind.sigs.k8s.io/) v1.32.2
- Ubuntu 22.04.5 LTS with 6.8.0-52-generic kernel.
