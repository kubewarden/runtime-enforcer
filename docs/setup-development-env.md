# Setup Development Environments

Runtime enforcement supports Tilt to run development environment in your local.

## Pre-requisite

- On a supported Linux host to run a local kubernetes cluster, install a one node kubernetes cluster.  Minikube is not supported.
- Setup golang development environments.

## Steps

1. Install [tilt](https://docs.tilt.dev/install.html)
2. Create `tilt-settings.yaml` based on `tilt-settings.yaml.example`.
3. Run `tilt up`.  Related resources should be built and deployed.

## Verified environment

- [Kind](https://kind.sigs.k8s.io/) v1.32.2
- Ubuntu 22.04.5 LTS with 6.8.0-52-generic kernel.
