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

## Verified environment

- [Kind](https://kind.sigs.k8s.io/) v1.32.2
- Ubuntu 22.04.5 LTS with 6.8.0-52-generic kernel.
