# runtime-enforcement
A runtime enforcement solution for your Kubernetes cluster.

## Local development
Having installed on your machine:

- `kubectl`
- `helm`
- `kind` or `k3d` with a test cluster already created, leveraging a local registry

Create a `tilt-settings.yml` with the images' URI inside. Then, just issue this to get started:

```sh
tilt up
```

You can use this command to list the policy proposals:

```sh
kubectl get workloadsecuritypolicyproposals.security.rancher.io -A
```

Have a lot of fun!
