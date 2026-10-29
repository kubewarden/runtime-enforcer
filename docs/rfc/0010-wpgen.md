|              |                                                         |
| ------------ | ------------------------------------------------------- |
| Feature Name | `wpgen`: draft a `WorkloadPolicy` from container images |
| Start Date   | 2026-10-29                                              |
| Category     | Tooling / Policy authoring                              |
| RFC PR       | [fill this in after opening PR]                         |
| State        | **ACCEPTED**                                            |

# Summary

[summary]: #summary

This RFC proposes `wpgen`, a command-line tool that drafts a `WorkloadPolicy`
from a container image or from a Kubernetes workload file. The tool downloads
each image, finds the executable files inside it, and writes a `WorkloadPolicy`
that allows them. The tool can also compare an existing policy with the images
of a workload. The output is a starting point for a user. It does not replace
the learn phase.

`wpgen` is a new binary in this repository. It is not part of the kubectl
plugin.

# Motivation

[motivation]: #motivation

Today a `WorkloadPolicy` comes from two sources. The learn phase produces a
`WorkloadPolicyProposal` that the user promotes. Or the user writes the policy
by hand. The learn phase needs a cluster with runtime-enforcer installed and a
workload that runs with realistic traffic. Some users cannot meet these
conditions:

- The workload does not exist yet. A CI pipeline builds the manifest, and the
  team wants the policy in the same pull request.
- A vendor ships an application as a Helm chart and wants to ship a policy with
  it. The vendor cannot learn in the cluster of each customer.
- A security reviewer wants to know if a learned policy is still valid after an
  image update. The reviewer needs a list of the executables that the new image
  contains.

Writing a policy by hand is error-prone. The user must know the real path of
each executable, as the kernel reports it. For example, in a BusyBox image the
user runs `/bin/ls`, but the kernel reports `/bin/busybox`.

The expected outcome is a tool that:

- Runs on a workstation or in CI, without a cluster.
- Reads one image or all the images of a workload file.
- Writes a `WorkloadPolicy` that uses the same Go types as the controller.
- Compares an existing policy with the images and reports the differences.

The tool must not become a shortcut that skips the learn phase. An allow-list
that contains every executable of a large base image gives little protection.
The design includes guardrails for this risk.

## Examples / User Stories

[examples]: #examples

- As a developer, I want to generate a `WorkloadPolicy` from my Deployment
  manifest in CI, so that the policy ships with the application.
- As a platform operator, I want to generate a policy for a third-party image,
  so that I can run the workload in monitor mode from day one.
- As a security reviewer, I want to compare a learned policy with the current
  image, so that I can find paths that no longer exist.

### Draft a policy from a workload file

```console
$ wpgen workload ./deploy/nginx.yaml
apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: deployment-nginx
  namespace: web
spec:
  mode: monitor
  rulesByContainer:
    nginx:
      executables:
        allowed:
          - /docker-entrypoint.sh
          - /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
          - /usr/sbin/nginx
          - ...
```

On standard error the tool prints a summary:

```text
container "nginx" (image docker.io/library/nginx:1.27): 312 executables
WARNING: container "nginx" allows 312 executables. A learned policy is usually
much smaller. Review the list before you switch the policy to protect mode.
Add this label to the pod template of Deployment "nginx":
  runtimeenforcer.kubewarden.io/policy: deployment-nginx
```

### Draft a policy from a single image

The user has no workload file yet. The user knows the image and the name of
the container that will run it. The tool treats this image as the main
container of the future pod.

```console
$ wpgen image ghcr.io/example/api:2.3.0 --container-name api --name api --namespace prod
apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: api
  namespace: prod
spec:
  mode: monitor
  rulesByContainer:
    api:
      executables:
        allowed:
          - /usr/local/bin/api
          - /usr/local/bin/migrate
          - ...
```

On standard error the tool prints a summary:

```text
container "api" (image ghcr.io/example/api:2.3.0): 14 executables
Add this label to the pod template of the workload that runs this image:
  runtimeenforcer.kubewarden.io/policy: api
```

The three flags are optional. Without `--container-name` the key in
`rulesByContainer` is `main`. Without `--name` the policy name is the last
path element of the image repository, `api` in this example. Without
`--namespace` the policy goes to the `default` namespace. The user must make
sure that the container name in the policy matches the container name in the
pod. If the names differ, the rules do not apply to the container.

### Compare a policy with the images of a workload

The team learned a policy for the nginx Deployment some months ago. A pull
request now bumps the image from `nginx:1.25` to `nginx:1.27`. The reviewer
wants to know if the policy still matches the new image. The CI job runs
`wpgen check` with the policy file and the updated workload file.

```console
$ wpgen check ./policy.yaml --workload ./deploy/nginx.yaml
container "nginx": 2 allowed paths do not exist in the image
  /usr/sbin/nginx-debug
  /usr/local/bin/wait-for-it.sh
container "nginx": 310 executables in the image are not allowed (expected)
$ echo $?
1
```

The report has two parts. The first part lists the allowed paths that the
tool did not find in the image. In this example, `/usr/sbin/nginx-debug` is
gone from the new image, and `/usr/local/bin/wait-for-it.sh` comes from a
volume. The reviewer decides to remove the first path and to keep the second
one. The second part counts the executables of the image that the policy does
not allow. This count is high for a learned policy, and that is the expected
result. The tool prints it so that the reviewer can see how much of the image
the policy blocks.

The exit code is `1` because the first part is not empty. The CI job fails,
and the pull request cannot merge until the reviewer updates the policy or
accepts the difference.

The same check works for a single image:

```console
$ wpgen check ./policy.yaml --image ghcr.io/example/api:2.3.0 --container-name api
container "api": all 14 allowed paths exist in the image
container "api": 0 executables in the image are not allowed
$ echo $?
0
```

# Detailed design

[design]: #detailed-design

## Scope

`wpgen` is a policy drafting tool. It reads images and manifests. It never
connects to a Kubernetes cluster. It never changes a workload file.

The tool has three subcommands:

| Subcommand       | Input                            | Output                            |
| ---------------- | -------------------------------- | --------------------------------- |
| `wpgen image`    | One image reference              | One `WorkloadPolicy`              |
| `wpgen workload` | A file with Kubernetes workloads | One `WorkloadPolicy` per workload |
| `wpgen check`    | A policy file and the images     | A report and an exit code         |

## Command-line interface

```text
wpgen image IMAGE [--container-name NAME] [--name NAME] [--namespace NS] [flags]
wpgen workload FILE [flags]
wpgen check POLICY_FILE (--workload FILE | --image IMAGE [--container-name NAME])
```

Common flags:

| Flag               | Default        | Description                                                         |
| ------------------ | -------------- | ------------------------------------------------------------------- |
| `--mode`           | `monitor`      | Value of `spec.mode`. Accepts `monitor` or `protect`.               |
| `--platform`       | `linux/<host>` | Platform to select from a multi-platform image.                     |
| `--output`, `-o`   | `yaml`         | Output format. Accepts `yaml` or `json`.                            |
| `--warn-threshold` | `50`           | Print a warning when a container allows more executables than this. |

Flags of `wpgen image`:

| Flag               | Default                        | Description                          |
| ------------------ | ------------------------------ | ------------------------------------ |
| `--container-name` | `main`                         | Key used in `spec.rulesByContainer`. |
| `--name`           | Last path element of the image | Value of `metadata.name`.            |
| `--namespace`      | `default`                      | Value of `metadata.namespace`.       |

## Image sources

The tool accepts three kinds of image sources:

- A registry reference, for example `docker.io/library/nginx:1.27` or a
  reference with a digest.
- A path to a tar archive that `docker save` or `podman save` produced.
- A path to a directory in OCI image layout format.

The tool uses `github.com/google/go-containerregistry` to read all three
sources. This library is widely used, has no CGO dependency, and already
handles the layer format details that follow.

A multi-platform image is an index that points to one image per platform.
The tool selects the image that matches `--platform`. The default is `linux`
with the architecture of the host. If the index has more than one platform,
the tool prints a notice with the selected platform. The set of executables
can differ between platforms.

## How the tool finds executables

The tool must produce the same paths that the eBPF program records. The
program hooks `security_bprm_creds_for_exec` and reads the path of
`bprm->file` with `bpf_d_path_approx`. The kernel resolves symbolic links
before this hook runs. As a result, the recorded path is always the path of a
regular file. It is never the path of a symbolic link.

The tool does the following steps for each image:

1. Flatten the layers into one file tree. Each layer is a tar stream. A later
   layer can add, replace, or delete files of an earlier layer. A deletion is
   a whiteout entry (a file named `.wh.<name>`). The tool applies all layers
   in order and honors the whiteouts. `mutate.Extract` from
   go-containerregistry does this step.
2. Walk the flattened tree.
3. Keep each regular file that has at least one execute permission bit set
   (owner, group, or other).
4. Keep each hard link whose target is kept. A hard link is a second directory
   entry for the same file. The kernel reports the path that the process used.
   The tool keeps both paths because both are valid.
5. Skip symbolic links. The kernel never reports a symbolic link path. A
   symbolic link to a directory, such as `/bin -> usr/bin`, is skipped for the
   same reason. The real files under `/usr/bin` are already in the list.
6. Sort the paths and remove duplicates.

Each path is absolute and starts with `/`. This matches the regular-expression pattern
of `spec.rulesByContainer.*.executables.allowed`.

The list contains every file with an execute bit. Scripts with a shebang line
are included because the kernel reports the script path, not the interpreter.
Shared libraries are also included when the image sets an execute bit on them.
Some distributions do this. These paths are noise in the policy, but they are
not a security risk. A library is never the target of an `execve` call. The
handling of libraries is an unresolved question of this RFC.

The tool only sees the file system of the image. It does not see:

- Files on volumes that the pod mounts over a path of the image.
- Files that the workload creates at runtime, for example a package that a
  start script installs.
- Files from a foreign root, as RFC 0008 defines them.

The tool documents these limits in its `--help` text. In monitor mode, the
enforcer reports these paths as violations, and the user adds them by hand.

## Workload files

`wpgen workload FILE` reads a YAML file with one or more documents. The tool
accepts the same kinds that RFC 0001 lists, plus `Pod`:

- `Pod`
- `Deployment`
- `ReplicaSet`
- `DaemonSet`
- `StatefulSet`
- `Job`
- `CronJob`

The tool skips documents of other kinds and prints a notice for each one. The
tool reads the `PodSpec` of each accepted document. It collects the
`containers` and the `initContainers`. Ephemeral containers are not part of a
workload file, so the tool ignores them.

For each container the tool records the name and the image. If two containers
use the same image, the tool scans the image once.

The tool writes one `WorkloadPolicy` per workload. The fields are:

- `metadata.name` is `<kind>-<name>` in lowercase. This matches the name that
  the controller gives to a `WorkloadPolicyProposal`.
- `metadata.namespace` is the namespace of the workload. If the workload has
  no namespace, the tool uses `default`.
- `spec.mode` is the value of `--mode`.
- `spec.rulesByContainer` has one entry per container. The key is the
  container name. The value lists the executables of the image.

The tool does not change the workload file. On standard error it prints the
label that the pod template needs:
`runtimeenforcer.kubewarden.io/policy: <policy name>`.

## Single image

`wpgen image IMAGE` writes one `WorkloadPolicy` with one container. The
container name comes from `--container-name`. The default is `main`. The
policy name comes from `--name`. The default is the last path element of the
image repository, for example `nginx` for `docker.io/library/nginx:1.27`.

## Output

The tool writes the policy to standard output as YAML. With `-o json` it
writes JSON. When the input has more than one workload, the YAML output has
one document per policy, divided by `---`.

The tool builds the policy with the Go types of `api/v1alpha1`. The output
stays in sync with the CRD schema without extra work.

All messages for humans go to standard error. A user can pipe standard output
into `kubectl apply -f -` or into a file.

## Guardrails

The output is a draft. The tool makes this clear in three ways:

- `spec.mode` is `monitor` unless the user passes `--mode protect`.
- The tool prints a warning for each container that allows more executables
  than `--warn-threshold`. The warning says that a learned policy is usually
  smaller.
- The `--help` text and the documentation call the output a draft. They point
  to the learn phase as the recommended way to build a policy.

## The `check` subcommand

`wpgen check` reads a `WorkloadPolicy` or a `WorkloadPolicyProposal` from a
file. It reads the images from a workload file or from `--image`. For each
container in `spec.rulesByContainer`, the tool compares the allowed paths with
the executables of the image. The report has two parts:

- Allowed paths that do not exist in the image. These paths are stale after an
  image update, or they come from a volume or a foreign root. The tool lists
  each path.
- Executables of the image that the policy does not allow. This is the normal
  case for a learned policy. The tool prints only the count.

The exit code is `1` when at least one allowed path does not exist in the
image. The exit code is `0` in all other cases. A CI job can use this to
detect a stale policy after an image bump.

If a container of the policy is not in the workload, or the reverse, the tool
prints a notice and continues.

## Code layout

```text
cmd/wpgen/main.go           # cobra root command
internal/imagescan/         # image source -> sorted list of executable paths
internal/workloadparse/     # YAML file -> list of (workload, containers)
internal/policydraft/       # containers + executables -> v1alpha1.WorkloadPolicy
```

The three internal packages have no dependency on the kubectl plugin or on
the controller. The kubectl plugin can import `internal/imagescan` later, for
example to compare a live `WorkloadPolicy` with the images of a running pod.

## Build and release

The Makefile gets a `wpgen` target and a `wpgen-cross` target. They follow
the `kubectl-plugin` and `kubectl-plugin-cross` targets. The release workflow
publishes `wpgen` binaries for the same platforms as the kubectl plugin, with
the same attestation.

The version of `wpgen` follows the version of the repository, as RFC 0007
defines it.

## Why a separate binary

The tool is not part of the kubectl plugin for three reasons:

- The tool needs no cluster. The kubectl plugin assumes a kubeconfig and a
  cluster. The users of `wpgen` are developers and CI pipelines.
- The tool pulls images and flattens layers. This adds go-containerregistry
  and its transitive dependencies to the binary. The kubectl plugin does small
  API calls and does not need this weight.
- The tool does not need to track the controller version as closely as the
  kubectl plugin does.

## Relation to RFC 0004

RFC 0004 describes an `ImagePolicy` resource that ties rules to an image. When
that resource exists, `wpgen image` can emit an `ImagePolicy` instead of a
`WorkloadPolicy`. The scanning code is the same.

# Drawbacks

[drawbacks]: #drawbacks

- A user can treat the output as a final policy. A policy that allows every
  executable of a Debian or Ubuntu base image blocks almost nothing. The
  guardrails reduce this risk but do not remove it.
- Shared libraries with an execute bit end up in the allow-list. They are
  noise, and they make a review harder.
- The tool downloads full images. A large image takes time and disk space.
- The tool only sees the image file system. Volumes, runtime-installed files,
  and foreign roots are missing. A draft policy for such a workload produces
  violations in monitor mode until the user adds the paths.
- `go.mod` gains go-containerregistry. Only `wpgen` links it, but the
  dependency list of the module grows.
- The project gets one more binary to build, test, release, and document.

# Alternatives

[alternatives]: #alternatives

- Do nothing. Users keep the learn phase as the only automated source of
  policies. Users without a cluster, or with a workload that does not exist
  yet, write policies by hand.
- Add the commands to the kubectl plugin. Rejected for the reasons in
  [Why a separate binary](#why-a-separate-binary).
- Allow only the entrypoint by default. The tool reads `ENTRYPOINT` and `CMD`
  from the image configuration, or `command` and `args` from the container,
  and allows only those paths. The full list becomes an opt-in flag. This
  gives a tight draft but misses every helper that the entrypoint calls. This
  is listed as an unresolved question.
- Use an SBOM tool such as syft as input. An SBOM lists packages, not the
  paths of executables. The tool still has to read the image.
- Static analysis of the binaries to find which executables call other
  executables. This is a research topic and out of scope.

# Unresolved questions

[unresolved]: #unresolved-questions

- Shared libraries. The execute bit alone does not separate a library from a
  program. A possible filter reads the ELF header and skips files of type
  `ET_DYN` without a `PT_INTERP` segment. Shebang scripts and static binaries
  are not affected by this filter. The decision is deferred.
- Default list. The tool allows every executable by default. The alternative
  is to allow only the entrypoint by default. The team decides after the first
  users try the tool.
- Default value of `--warn-threshold`. The value `50` is a guess.
- Multi-platform images. One `WorkloadPolicy` covers all the nodes of a
  cluster. If the executables differ between platforms, the user needs the
  union. The tool can accept `--platform` more than once and merge the lists.
  This is not in the first implementation.
- A `check` command in the kubectl plugin that reads the images of a running
  pod. This is possible with `internal/imagescan` but is not in scope here.
