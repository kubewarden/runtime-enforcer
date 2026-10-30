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
  name: deploy-nginx
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
Deployment nginx (namespace web), policy deploy-nginx
┌───────────┬──────────────────────────────┬─────────────┬───────────────────┬───────────────┐
│ CONTAINER │ IMAGE                        │ EXECUTABLES │ SKIPPED LIBRARIES │ SKIPPED OTHER │
├───────────┼──────────────────────────────┼─────────────┼───────────────────┼───────────────┤
│ nginx     │ docker.io/library/nginx:1.27 │         312 │                 2 │             0 │
└───────────┴──────────────────────────────┴─────────────┴───────────────────┴───────────────┘
Use --include-libraries to keep the skipped shared libraries.

WARNING: container nginx allows 312 executables. A learned policy is usually
much smaller. Review the list before you switch the policy to protect mode.

Add this label to the pod template of Deployment nginx:
  runtimeenforcer.kubewarden.io/policy: deploy-nginx
```

The tool also reads from standard input. This is useful with the output of
Helm:

```console
$ helm template my-release ./chart | wpgen workload -
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
┌───────────┬───────────────────────────┬─────────────┬───────────────────┬───────────────┐
│ CONTAINER │ IMAGE                     │ EXECUTABLES │ SKIPPED LIBRARIES │ SKIPPED OTHER │
├───────────┼───────────────────────────┼─────────────┼───────────────────┼───────────────┤
│ api       │ ghcr.io/example/api:2.3.0 │          14 │                 0 │             0 │
└───────────┴───────────────────────────┴─────────────┴───────────────────┴───────────────┘

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
Policy deploy-nginx (namespace web)

┌───────────┬───────────────────────────────┬────────┬────────────────────────────────┐
│ CONTAINER │ PATH                          │ STATUS │ NOTE                           │
├───────────┼───────────────────────────────┼────────┼────────────────────────────────┤
│           │ /usr/local/bin/wait-for-it.sh │ stale  │ not an executable in the image │
│   nginx   │ /usr/sbin/nginx-debug         │ stale  │ not an executable in the image │
│           │ /docker-entrypoint.sh         │ ok     │                                │
│           │ /usr/sbin/nginx               │ ok     │                                │
└───────────┴───────────────────────────────┴────────┴────────────────────────────────┘

┌───────────┬──────────────────────────────┬─────────┬────┬───────┬─────────┬─────────────┐
│ CONTAINER │ IMAGE                        │ ALLOWED │ OK │ STALE │ SKIPPED │ NOT ALLOWED │
├───────────┼──────────────────────────────┼─────────┼────┼───────┼─────────┼─────────────┤
│ nginx     │ docker.io/library/nginx:1.27 │       4 │  2 │     2 │       0 │         502 │
└───────────┴──────────────────────────────┴─────────┴────┴───────┴─────────┴─────────────┘

2 allowed paths are not executables in the images:
  nginx: /usr/local/bin/wait-for-it.sh, /usr/sbin/nginx-debug
$ echo $?
1
```

The first table has one row for each allowed path, with its status. The
paths that need an action come first. In this example,
`/usr/sbin/nginx-debug` is gone from the new image, and
`/usr/local/bin/wait-for-it.sh` comes from a volume. The reviewer decides to
remove the first path and to keep the second one. The second table counts
the paths of each status. It also counts the executables of the image that
the policy does not allow. This count is high for a learned policy, and that
is the expected result. The last lines repeat the stale paths, so that the
reader does not have to search the table.

The exit code is `1` because some paths are stale. The CI job fails,
and the pull request cannot merge until the reviewer updates the policy or
accepts the difference.

The same check works for a single image:

```console
$ wpgen check ./policy.yaml --image ghcr.io/example/api:2.3.0 --container-name api
Policy api (namespace prod)

┌───────────┬────────────────────────┬────────┬──────┐
│ CONTAINER │ PATH                   │ STATUS │ NOTE │
├───────────┼────────────────────────┼────────┼──────┤
│    api    │ /usr/local/bin/api     │ ok     │      │
│           │ /usr/local/bin/migrate │ ok     │      │
└───────────┴────────────────────────┴────────┴──────┘

┌───────────┬───────────────────────────┬─────────┬────┬───────┬─────────┬─────────────┐
│ CONTAINER │ IMAGE                     │ ALLOWED │ OK │ STALE │ SKIPPED │ NOT ALLOWED │
├───────────┼───────────────────────────┼─────────┼────┼───────┼─────────┼─────────────┤
│ api       │ ghcr.io/example/api:2.3.0 │       2 │  2 │     0 │       0 │          12 │
└───────────┴───────────────────────────┴─────────┴────┴───────┴─────────┴─────────────┘

No allowed path is stale.
$ echo $?
0
```

A policy written by hand often allows the name of a symbolic link, for
example `/bin/sh` in a BusyBox image. The enforcer never reports this path.
The check shows the real path that the policy must allow:

```text
┌───────────┬─────────┬────────┬────────────────────────────────────────────────────┐
│ CONTAINER │ PATH    │ STATUS │ NOTE                                               │
├───────────┼─────────┼────────┼────────────────────────────────────────────────────┤
│    main   │ /bin/sh │ stale  │ symbolic link to /bin/busybox, the enforcer        │
│           │         │        │ reports the target                                 │
└───────────┴─────────┴────────┴────────────────────────────────────────────────────┘
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
wpgen workload FILE|- [flags]
wpgen check POLICY_FILE|- (--workload FILE|- | --image IMAGE [--container-name NAME]) [flags]
```

Common flags:

| Flag                  | Default                       | Description                                                                               |
| --------------------- | ----------------------------- | ----------------------------------------------------------------------------------------- |
| `--platform`          | `linux/<host>`                | Platform to select from a multi-platform image.                                           |
| `--image-src`         | `file,docker,podman,registry` | Image sources to try, in order. See [Image sources](#image-sources).                      |
| `--include-libraries` | `false`                       | Count shared libraries as executables. See [Kinds of executables](#kinds-of-executables). |
| `--include-unknown`   | `false`                       | Count files that are neither programs nor scripts as executables.                         |
| `--color`             | `auto`                        | When to use colors: `auto`, `always` or `never`. See [Colors](#colors).                   |

Flags of `wpgen image` and `wpgen workload`:

| Flag               | Default   | Description                                                         |
| ------------------ | --------- | ------------------------------------------------------------------- |
| `--mode`           | `monitor` | Value of `spec.mode`. Accepts `monitor` or `protect`.               |
| `--output`, `-o`   | `yaml`    | Output format. Accepts `yaml` or `json`.                            |
| `--warn-threshold` | `50`      | Print a warning when a container allows more executables than this. |

Flags of `wpgen image`:

| Flag               | Default                        | Description                          |
| ------------------ | ------------------------------ | ------------------------------------ |
| `--container-name` | `main`                         | Key used in `spec.rulesByContainer`. |
| `--name`           | Last path element of the image | Value of `metadata.name`.            |
| `--namespace`      | `default`                      | Value of `metadata.namespace`.       |

Flags of `wpgen check`:

| Flag                 | Default | Description                                                                 |
| -------------------- | ------- | --------------------------------------------------------------------------- |
| `--output`, `-o`     | `table` | Report format. Accepts `table` or `json`.                                   |
| `--list-not-allowed` | `false` | List the executables that the policy does not allow, not only their number. |

## Image sources

The tool looks for an image in a list of sources, in order, and uses the
first source that has the image. This is the same approach as Trivy and
Syft. The `--image-src` flag sets the list. The default list is:

1. `file`: a path to a tar archive that `docker save` or `podman save`
   produced, a path to an OCI archive, or a path to a directory in OCI image
   layout format.
2. `docker`: the local Docker daemon.
3. `podman`: the local Podman daemon.
4. `registry`: the remote registry of the image reference.

A daemon source pulls the image into the daemon when the daemon does not
have it. To read the image directly from the registry, the user passes
`--image-src registry`. The flag also accepts the other sources of the
library, for example `containerd`.

When every source fails, the error contains the reason of each source.

The tool uses the stereoscope library (`github.com/anchore/stereoscope`) to
read the images. Syft and Grype use the same library. It finds the image in
all the sources above, merges the layers, and handles the details of hard
links between layers. It has no CGO dependency.

A multi-platform image is an index that points to one image per platform.
The tool selects the image that matches `--platform`. The default is `linux`
with the architecture of the host. The tool prints the platform of the image
that it loaded. The set of executables can differ between platforms.

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
   in order and honors the whiteouts. Stereoscope does this step.
2. Go through all the files of the flattened tree.
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

## Kinds of executables

A file with an execute bit is not always a program. Some distributions set
the execute bit on shared libraries, and some images have data files with
mode `0755`. These paths are noise in a policy. The tool reads the content of
each file and puts it in one of four kinds:

| Kind    | Test                                                        | Example                 |
| ------- | ----------------------------------------------------------- | ----------------------- |
| program | ELF of type `ET_EXEC`, or `ET_DYN` that is not a library    | `/usr/sbin/nginx`       |
| library | ELF of type `ET_DYN`, with no `PT_INTERP` and no `DF_1_PIE` | `/lib/libz.so.1`        |
| script  | The file starts with `#!`                                   | `/docker-entrypoint.sh` |
| unknown | Any other file, for example an ELF object file              | `/etc/ssl/certs/ca.crt` |

An ELF file of type `ET_DYN` is either a shared library or a position
independent program (PIE). A dynamically linked PIE has a `PT_INTERP`
segment. A static PIE, for example a Rust program linked with musl, has no
`PT_INTERP`, but the linker sets the `DF_1_PIE` flag in its dynamic segment.
The `file` utility uses the same two signals. The tool reads the flag from
the `PT_DYNAMIC` segment, as the kernel does, so that a binary without
section headers is still classified correctly.

When in doubt, the tool chooses "program". An ELF file that the tool cannot
parse is a program. `libc.so.6` of glibc has a `PT_INTERP` segment, so that
you can run it to print its version, and it stays in the list. A program
that is missing from a policy blocks the workload. An extra library is only
noise.

By default, the tool skips libraries and unknown files. The flags
`--include-libraries` and `--include-unknown` keep them. The summary of each
container shows how many files the tool skipped. The `check` command uses
the same rule. An allowed path of a skipped kind is listed apart, and it does
not change the exit code.

Two cases show why the skipped kinds are safe by default, and why the flags
exist:

- The dynamic loader, for example `/lib64/ld-linux-x86-64.so.2`, is a
  library. The kernel maps it into the process when it starts a dynamically
  linked program, without an `execve` call for the loader itself. The
  enforcer only sees the path of the program. The loader is an exec target
  only when something starts it on purpose, as in `ld.so ./binary`. A policy
  that allows the loader lets the workload run any binary through it.
- A script without a `#!` line is an unknown file. When a shell starts it
  directly, `execve` fails with `ENOEXEC`, and the shell then runs the file
  itself. The enforcer sees the exec event for the script path before the
  kernel finds out that it cannot run the file. In protect mode, a denied
  path fails with a permission error, and the shell does not fall back. So
  a policy must allow such a script when the workload starts it directly.

In both cases, the enforcer reports the path as a violation in monitor mode,
and the user adds it to the policy, or runs the tool again with the flag.

The rule was tested on real images, and compared with the output of `file`.
No program was classified as a library:

| Image                              | Files with exec bit | Programs | Libraries | Scripts | Unknown |
| ---------------------------------- | ------------------- | -------- | --------- | ------- | ------- |
| `alpine:3.20`                      | 21                  | 7        | 10        | 4       | 0       |
| `debian:12`                        | 479                 | 316      | 2         | 161     | 0       |
| `nginx:1.27`                       | 506                 | 324      | 2         | 180     | 0       |
| `python:3.12-slim`                 | 549                 | 282      | 82        | 185     | 0       |
| `gcr.io/distroless/base-debian12`  | 6                   | 1        | 1         | 1       | 3       |
| `ghcr.io/kubewarden/policy-server` | 1                   | 1        | 0         | 0       | 0       |

Debian ships most libraries without an execute bit, so the gain is small
there. On Alpine, libraries are half of the list. On `python:3.12-slim`, most
libraries are Python extension modules. A Go program built as a static PIE
and the musl build of `kwctl` were also classified as programs. Reading and
classifying all the files took less than 100 milliseconds per image.

## Limits of the image scan

The tool only sees the file system of the image. It does not see:

- Files on volumes that the pod mounts over a path of the image.
- Files that the workload creates at runtime, for example a package that a
  start script installs.
- Files from a foreign root, as RFC 0008 defines them.

The tool documents these limits in its `--help` text. In monitor mode, the
enforcer reports these paths as violations, and the user adds them by hand.

## Workload files

`wpgen workload FILE` reads a file with one or more YAML or JSON documents.
If `FILE` is `-`, the tool reads from standard input. A document of kind
`List`, as `kubectl get -o yaml` writes it, counts as one document per item.

The tool accepts the kinds that the learn phase supports:

- `Deployment` (`apps/v1`)
- `ReplicaSet` (`apps/v1`)
- `DaemonSet` (`apps/v1`)
- `StatefulSet` (`apps/v1`)
- `Job` (`batch/v1`)
- `CronJob` (`batch/v1`)

The tool skips all the other documents and prints a notice for each one. A
bare `Pod` is also skipped, because runtime-enforcer does not learn policies
for bare pods. If the file has no accepted workload, the tool stops with an
error.

The tool reads the pod template of each accepted document. It collects the
`containers` and the `initContainers`. Ephemeral containers are not part of a
workload file, so the tool ignores them. A container without an image is an
error.

For each container the tool records the name and the image. If two containers
use the same image, the tool scans the image once. The tool removes the
temporary files of each image before it loads the next one.

The tool writes one `WorkloadPolicy` per workload. The fields are:

- `metadata.name` is the value of the `runtimeenforcer.kubewarden.io/policy`
  label of the pod template, when the label is there. The user already chose
  a name, and the tool keeps it.
- When the label is not there, `metadata.name` is `<short kind>-<name>`, for
  example `deploy-nginx`. The short kinds are `deploy`, `rs`, `ds`, `sts`,
  `job`, and `cronjob`. This is the name that the controller gives to a
  `WorkloadPolicyProposal`, and both use the same code.
- `metadata.namespace` is the namespace of the workload. If the workload has
  no namespace, the policy has no namespace either. As a result,
  `kubectl apply -n <namespace>` puts the workload and its policy in the same
  namespace. This is the usual case for the output of `helm template`.
- `spec.mode` is the value of `--mode`.
- `spec.rulesByContainer` has one entry per container and init container. The
  key is the container name. The value lists the executables of the image.

If two workloads of the same namespace get the same policy name, the tool
stops with an error. When applied, the second policy replaces the first one.

The tool does not change the workload file. On standard error it prints the
label that the pod template needs:
`runtimeenforcer.kubewarden.io/policy: <policy name>`.

## Single image

`wpgen image IMAGE` writes one `WorkloadPolicy` with one container. The
container name comes from `--container-name`. The default is `main`. The
policy name comes from `--name`. The default is the last path element of the
image repository, for example `nginx` for `docker.io/library/nginx:1.27`.
For an image from an archive or a directory, the repository comes from the
tag stored in the image, and never from the file name. When the tool cannot
find a repository, the policy name is `todo`, and the tool prints a warning
that asks the user to replace it.

## Output

The tool writes the policy to standard output as YAML. With `-o json` it
writes JSON. When the input has more than one workload, the YAML output has
one document per policy, divided by `---`. The JSON output has one object
after the other. `kubectl apply -f` accepts both.

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

`wpgen check` reads one `WorkloadPolicy` or one `WorkloadPolicyProposal` from
a file. If the file name is `-`, the tool reads from standard input. Other
kinds in the file are skipped with a notice. A file with no policy, or with
more than one, is an error.

The tool reads the images from one of two sources:

- `--workload FILE`: the file must contain exactly one supported workload,
  with the same kinds and rules as `wpgen workload`. A file with more than
  one workload is an error. The tool does not compare the name of the policy
  with the name of the workload.
- `--image IMAGE`: the image of one container of the policy. The container is
  the one given with `--container-name`. Without this flag, the policy must
  have exactly one container.

With `--workload`, the tool matches the containers of the policy and of the
workload by name. A container of the workload without rules in the policy,
for example a new container, makes the check fail: the enforcer does not
protect it. A container of the policy that is not in the workload is not
checked: the tool prints a notice and continues. If they have no container
in common, the tool stops with an error.

For each container, the tool compares the allowed paths with the executables
of the image. The report has two parts:

- Allowed paths that are not executables in the image. These paths are stale
  after an image update, or they come from a volume or a foreign root. The
  tool lists each path.
- Executables of the image that the policy does not allow. This is the normal
  case for a learned policy. The tool prints only the count.

Allowed paths that are libraries or unknown files are listed apart, as
[Kinds of executables](#kinds-of-executables) describes.

When a path of the first part is a symbolic link in the image, or goes
through a symbolic link to a directory, the tool shows the real path. The
enforcer reports only real paths, so this policy entry never matches.

The report always shows how many executables of the image the policy does
not allow. With `--list-not-allowed`, it also lists them. For a learned
policy, this list can have hundreds of paths.

The report goes to standard output, as tables or, with `-o json`, as one
JSON document. The tables use the same style as the other `wpgen` output. The
`table` and `json` names follow the `-o` flag of the kubectl plugin. The JSON
document has the same content as the tables. It also contains the containers
that are only in the policy or only in the workload, which the table mode
prints as notices on standard error. In the JSON
document, the number of executables that the policy does not allow is always
present. Their list is present only with `--list-not-allowed`.

The exit code is `1` when at least one allowed path is not an executable in
the image, or when a container of the workload has no rules in the policy.
The exit code is `0` in all other cases. The format of the report does not
change the exit code. A CI job can use this to detect a stale policy after an
image bump, or a new container that the policy does not protect.

The verdict, on standard error, says only what the tool checked. It counts
the allowed paths that the tool skipped, and the containers of the policy
that it did not check.

## Colors

The tool uses colors only to make the important lines stand out. The tables
have no colors. The colored lines are:

- The verdict of `check`, in red when a path is stale or a container has no
  rules, and in green otherwise. It goes to standard error, after the report.
- The `WARNING:` word in the summary of `image` and `workload`.
- The notices about containers that are only in the policy or only in the
  workload.
- The `Error:` word of a failed command.

The container names in the first table of `check` are bold.

The `--color` flag accepts `auto`, `always` and `never`. With `auto`, the
default, the tool follows the common conventions: no colors when the
`NO_COLOR` environment variable is set, colors when `CLICOLOR_FORCE` is set
to a value other than `0`, and otherwise colors only when the output stream
is a terminal. The tool decides for each stream. For example, the summary on
standard error has colors when standard output goes to a file. JSON output
never has colors.

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
- The tool pulls images and flattens layers. This adds stereoscope and its
  transitive dependencies to the binary. The kubectl plugin does small API
  calls and does not need this weight.
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
- The kinds of executables come from a heuristic. A static PIE program from
  a linker that does not set `DF_1_PIE` looks like a library, and the tool
  skips it. The tests found no such program, and monitor mode shows it if it
  exists.
- The tool downloads full images. A large image takes time and disk space.
- The tool only sees the image file system. Volumes, runtime-installed files,
  and foreign roots are missing. A draft policy for such a workload produces
  violations in monitor mode until the user adds the paths.
- `go.mod` gains stereoscope, which brings the client libraries of
  containerd and Podman. Only `wpgen` links them, but the dependency list of
  the module grows. Tools that scan `go.sum` instead of the binaries report
  these modules for the whole repository.
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

- Default list. The tool allows every program and script by default. The alternative
  is to allow only the entrypoint by default. The team decides after the first
  users try the tool.
- Default value of `--warn-threshold`. The value `50` is a guess.
- Multi-platform images. One `WorkloadPolicy` covers all the nodes of a
  cluster. If the executables differ between platforms, the user needs the
  union. The tool can accept `--platform` more than once and merge the lists.
  This is not in the first implementation.
- A `check` command in the kubectl plugin that reads the images of a running
  pod. The kubectl plugin can reuse the scanning code of `wpgen` for this, but
  it is not in scope here.
