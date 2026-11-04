# Contributing

## Code conventions

Read our global [CONTRIBUTING
guidelines](https://github.com/kubewarden/community/blob/main/CONTRIBUTING.md)
and the [AI usage
policy](https://github.com/kubewarden/community/blob/main/AI_POLICY.md).

## Requirements

You need the following tools to build and run this project:

- **Docker**: for building and running containerized workloads.
- **Go**: required by all the components. The exact version is defined in `go.mod`.
- **clang, llvm, libbpf and libelf**: required to compile the eBPF programs in
  `bpf/`. eBPF programs run inside the Linux kernel. On Debian and Ubuntu,
  install the `clang`, `llvm`, `libbpf-dev`, `libelf-dev` and `build-essential`
  packages.
- **[protoc](https://grpc.io/docs/protoc-installation/)**: required to
  regenerate the gRPC code in `proto/`.
- **Make**: the build tool controlling various build tasks.
- **[Tilt](https://docs.tilt.dev/)**: a development tool for multi-service applications.
- **Kubernetes cluster**: a running Kubernetes cluster, used for development. [kind](https://kind.sigs.k8s.io/)
  or a similar solution.
- **[Helm](https://helm.sh/)**: required for deploying and testing charts. The
  chart tests need the
  [helm-unittest](https://github.com/helm-unittest/helm-unittest) plugin.
- **[pre-commit](https://pre-commit.com/)**: runs all the linters.

The following tools are optional:

- **Node.js**: required to run [commitlint](https://commitlint.js.org/) on
  your machine.
- **[bpfvalidator](https://github.com/Andreagit97/bpfvalidator)**: runs the
  eBPF tests against multiple kernel versions.

## Code Layout

The repository has the following layout:

- `api`: the Go types of the `WorkloadPolicy` and `WorkloadPolicyProposal`
  CRDs (custom resource definitions).
- `bpf`: the C source code of the eBPF programs.
- `charts`: contains the Helm chart for managing deployments.
- `cmd`: main entry points for the `agent`, `controller`, `debugger`,
  `kubectl-plugin` and `wpgen` executables.
- `docs`: developer-focused documentation, the generated CRD reference and the RFCs.
- `hack`: helper scripts and the Dockerfiles used by Tilt.
- `internal`: the private Go implementation packages used by the executables.
- `package`: the Dockerfiles of the released container images.
- `pkg/generated`: the generated Kubernetes clientset, informers and listers.
- `proto`: the gRPC API between the agent and the other components.
- `test/e2e`: end-to-end tests. A real Kubernetes cluster is created using Docker and Kind.
- `updatecli`: the automation that bumps dependencies and the Helm chart.

## Linting and Formatting

All the linters run through [pre-commit](https://pre-commit.com/). The
`.pre-commit-config.yaml` file defines them. CI runs the same hooks.

Install the hooks in your local clone:

```console
pre-commit install --install-hooks
```

Run all the linters on all the files:

```console
make generate-ebpf
pre-commit run --all-files
```

The `make generate-ebpf` step is required because the Go linter needs the
generated eBPF objects.

### Go

Format Go code:

```console
make fmt
```

Run `go vet`:

```console
make vet
```

Run the Go linter ([golangci-lint](https://golangci-lint.run/)):

```console
pre-commit run golangci-lint-full --all-files
```

### eBPF

Format the C code with `clang-format`:

```console
pre-commit run clang-format --all-files
```

Lint the C code with `clang-tidy`:

```console
pre-commit run clang-tidy --all-files
```

### Protobuf

Lint the `.proto` files with [protolint](https://github.com/yoheimuta/protolint):

```console
pre-commit run protolint --all-files
```

## Building

### Build All Components

Build the controller, the agent and the debugger:

```console
make controller
make agent
make debugger
```

Make writes the binaries to `bin/`.

### Build the kubectl plugin

Build the plugin for your platform:

```console
make kubectl-plugin
```

Build the plugin for all the supported platforms:

```console
make kubectl-plugin-cross
```

### Build wpgen

Build `wpgen` for your platform:

```console
make wpgen
```

Build `wpgen` for all the supported platforms. Make writes the binaries to
`bin/wpgen-dist/`:

```console
make wpgen-cross
```

### Build Container Images

Build Docker images for each component:

```console
make build-controller-image
make build-agent-image
make build-debugger-image
```

You can customize the repository and the tag using environment variables:

```console
make build-controller-image REPO=ghcr.io/your-username/runtime-enforcer TAG=dev
```

## Development

To run the controller, the agent and the debugger for development purposes, you
can use [Tilt](https://tilt.dev/).

### Settings

The `tilt-settings.yaml.example` acts as a template for the
`tilt-settings.yaml` file that you need to create in the root of this
repository. Copy the example file and edit it to match your environment. Git
ignores the `tilt-settings.yaml` file, so you cannot commit it by mistake.

The file accepts the following keys:

- `controller.image`: the name of the controller image. If you are using
  `ghcr.io` as your registry, you need to prefix the image name with your GitHub
  username.

- `agent.image`: the name of the agent image. If you are using `ghcr.io` as
  your registry, you need to prefix the image name with your GitHub username.

- `debugger.image`: the name of the debugger image. If you are using `ghcr.io`
  as your registry, you need to prefix the image name with your GitHub username.

- `clusters`: the list of Kubernetes contexts that Tilt can use. Tilt allows
  local clusters like kind by default. If you use a different cluster, add its
  context here.

Example:

```yaml
controller:
  image: ghcr.io/your-github-username/runtime-enforcer/controller
agent:
  image: ghcr.io/your-github-username/runtime-enforcer/agent
debugger:
  image: ghcr.io/your-github-username/runtime-enforcer/debugger
clusters:
  - my-cluster
```

### Running

The `Tiltfile` included in this repository takes care of the following:

- Installs cert-manager and the cert-manager-csi-driver.
- Creates the `runtime-enforcer` namespace.
- Installs the `runtime-enforcer` Helm chart from the `charts` folder, with the
  debugger enabled.
- Injects the development images into the running Pods.
- Rebuilds and reloads the controller, the agent and the debugger on every
  code change.

To run the project, run the following command against an empty cluster:

```console
tilt up
```

Use the web interface of Tilt to monitor the log streams of the different
components. If needed, trigger restarts by hand from the same interface.

The agent needs a node that runs containerd or CRI-O with NRI (Node Resource
Interface) enabled. See the [compatibility
page](https://docs.kubewarden.io/runtime-enforcer/latest/en/compatibility.html)
for the kernel and runtime requirements.

## Changes to CRDs and other generated code

After changing a CRD, a `.proto` file, an eBPF program, a kubectl plugin
command, a `wpgen` command or the Helm chart `values.yaml`, run the following
command:

```console
make generate
```

This will:

- Update all the generated Go code
- Update the CRDs and the RBAC rules shipped by our Helm chart
- Update the CRD reference in `docs/crds/CRD-docs-for-docs-repo.adoc`
- Update the eBPF objects in `internal/bpf`
- Update the gRPC code in `proto/`
- Update the clientset, informers and listers in `pkg/generated`
- Update the `values.schema.json` of the Helm chart
- Update the kubectl plugin reference in `docs/kubectl-plugin/cli-docs.adoc`
- Update the `wpgen` reference in `docs/wpgen/cli-docs.adoc`

CI runs `make generate` on each pull request. If the generated files are not up
to date, CI fails.

## Testing

### Running Tests

Run all unit tests:

```console
make test
```

The target downloads the envtest binaries into `bin/` on the first run.

Run the eBPF tests. They need root because they load eBPF programs into the
running kernel:

```console
make test-bpf
```

Run e2e tests:

```console
make test-e2e
```

The target builds the container images, creates a kind cluster, installs the
chart and runs the tests. The following environment variables change this
behavior:

- `E2E_USE_EXISTING_CLUSTER=true`: use the cluster of your current kubeconfig
  instead of creating a kind cluster. Make does not rebuild the images.
- `E2E_NO_REBUILD=true`: do not rebuild the container images.
- `E2E_DEPENDENCIES`: a comma-separated list of the dependencies that the tests
  install. The accepted values are `cert-manager` and `cert-manager-csi-driver`.
  Use `none` to install nothing. When the variable is not set, the tests install
  all the dependencies.

The tests write the logs of the cluster to `test/e2e/logs`.

### Helm Chart Tests

Run Helm chart unit tests:

```console
make helm-unittest
```

### Writing tests

Most of the Go unit tests use the standard `testing` package and
[testify](https://github.com/stretchr/testify).

The controller tests use the [Ginkgo](https://onsi.github.io/ginkgo/) and
[Gomega](https://onsi.github.io/gomega/) testing frameworks. The tests are in
the `internal/controller` and `internal/eventhandler` packages.

These tests run with [envtest](https://book.kubebuilder.io/reference/envtest).
envtest starts an instance of etcd and the Kubernetes API server, without
kubelet, controller-manager, or other components.

Some tests require a real Kubernetes cluster to run. These tests are in the
`test/e2e` folder and use the
[e2e-framework](https://github.com/kubernetes-sigs/e2e-framework).

The suite setup starts a cluster with [kind](https://kind.sigs.k8s.io/) and
runs the tests against it. When the tests finish, the suite deletes the
cluster.

The `e2e` tests are slower than the `envtest` tests. As a result, keep their
number to a minimum.

### Focusing on Specific Tests

You can focus on a specific Ginkgo spec by using a [Focused
Spec](https://onsi.github.io/ginkgo/#focused-specs).

Example:

```go
var _ = Describe("Controller test", func() {
    FIt("should do something", func() {
        // This spec will be the only one executed
    })
})
```

### Testing eBPF on multiple kernels

CI runs the eBPF tests against multiple kernel versions with
[bpfvalidator](https://github.com/Andreagit97/bpfvalidator). The tool boots
each kernel in a virtual machine and runs the test binary inside it. The
kernel list is in `bpfvalidator-amd64-config.yaml` and
`bpfvalidator-arm64-config.yaml`.

To run the same tests on your machine:

1. Install bpfvalidator from its [release
   page](https://github.com/Andreagit97/bpfvalidator/releases), or build it
   from source.
2. Generate the eBPF objects and build the test binary from the root of the repository:

   ```console
   make generate-ebpf
   go test -c ./internal/bpf/... -o tester
   ```

3. Run the tests against all the kernels of your architecture:

   ```console
   bpfvalidator --config "./bpfvalidator-$(go env GOARCH)-config.yaml" --cmd="./tester -test.v"
   ```

### Testing wpgen

`wpgen` reads container images and produces policies, tables and JSON. Its
tests are split in three layers, so that most of them run without images and
without the network.

**Unit tests on the rules.** The functions that compare a policy with the
executables of an image, such as `compare` and `matchContainers` in
`internal/wpgen`, take plain Go values and return plain Go values. Their tests
build these values by hand, or load them from the scan fixture described
below, and check the fields of the result. These tests do not render
anything.

**Golden files for the rendered output.** The tables, the JSON report and the
summaries are rendered from a result value. Their tests render a fixed result
and compare the output with a file in `internal/wpgen/testdata/*.golden`.
When you change the layout on purpose, rewrite the golden files and review
the diff:

```console
go test ./internal/wpgen -update
```

**Scan fixture of a real image.** The file
`internal/wpgen/testdata/golang-1.12-alpine-amd64.scan.json` holds the result
of `imagescan.Scan`, the function that `wpgen` uses to scan an image, for a
real image. The result has the executables of the image with their kind
(program, library, script or unknown), and the real path of each lookup path
that goes through a symbolic link. The image is
`ghcr.io/kubewarden/sbomscanner/test-assets/golang@sha256:1782cafde43390b032f960c0fad3def745fac18994ced169003cb56e9a93c028`,
the same digest-pinned image that
[sbomscanner](https://github.com/kubewarden/sbomscanner) uses for its
fixtures. The tests read this file instead of scanning the image, so they do
not need the network.

The lookup paths are the paths that the tests ask about, and they are stored
in the `lookup` field of the fixture. A test that asks about another path
fails with a message that tells you to add it. To add a path, add it to the
`lookup` field and regenerate the fixture.

The fixture also changes when the classification rules in
`internal/imagescan` change. To regenerate it, run:

```console
make generate-wpgen-fixtures
```

The target scans the pinned image with the production code and rewrites the
file. Review the diff: it shows which files of a real image moved from one
kind to another. Then rewrite the golden files with `-update`, because they
are rendered from the fixture. The target needs network access, so it is not
part of `make generate`.

**End-to-end tests.** A few tests run the `wpgen` commands through cobra, with
small images that `internal/imagescan/imagescantest` builds on the fly. They
test the wiring: flags, input files, exit codes, and which stream gets the
output. Keep their number low. Put new tests on the rules or on the layout in
the first two layers.

## Commit subjects

The commit messages must follow the [conventional commits
standard](https://www.conventionalcommits.org/en/v1.0.0/). For example:

- `type: free form subject`

Common `type` values include:

- `feat`: a commit that introduces a new feature
- `fix`: a commit that fixes an issue
- `perf`: a commit that improves performance
- `refactor`: a commit that refactors some code

Some examples:

- `feat: this is a new feature`
- `fix: this is fixing a reported bug`

You can also specify a component if this commit targets one component
specifically.

- `feat(agent): this adds a new event type`

CI runs [commitlint](https://commitlint.js.org/) on the commits of each pull
request. The rules are in `commitlint.config.js`. To run commitlint on your
machine:

```console
npm ci
npx commitlint --from main
```

## Releasing

The [release issue
template](.github/ISSUE_TEMPLATE/3-runtime-enforcer-release.yml) documents the
release process. Open a new issue from that template to track a release. The
[release workflow](.github/workflows/release.yml) starts when you push a
`v*.*.*` tag.

## Additional Resources

- **Developer Documentation**: The `docs/` folder contains the generated CRD
  reference (`crds/CRD-docs-for-docs-repo.adoc`), the kubectl plugin guide
  (`kubectl_plugin.adoc`), the kubectl plugin command reference
  (`kubectl-plugin/cli-docs.adoc`), the `wpgen` guide (`wpgen.adoc`) and the
  `wpgen` command reference (`wpgen/cli-docs.adoc`).
- **RFCs**: The `docs/rfc` folder holds design proposals and architectural
  decisions.
- **User Documentation**: The user documentation is at
  <https://docs.kubewarden.io/runtime-enforcer>.
