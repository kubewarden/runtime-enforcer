tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

allow_k8s_contexts(settings.get("clusters"))

update_settings(
    k8s_upsert_timeout_secs=180,
)

# while it takes some time to install cert manager, it's okay to wait 
# because we rely on its ca injector to setup our mutating webhook.
load('ext://cert_manager', 'deploy_cert_manager')

deploy_cert_manager(version="v1.18.2")

load("ext://helm_resource", "helm_resource", "helm_repo")
helm_repo("jetstack", "https://charts.jetstack.io")
helm_resource(
    "cert-manager-csi-driver",
    "jetstack/cert-manager-csi-driver",
    namespace="cert-manager",
)

# Create the namespace
# This is required since the helm() function doesn't support the create_namespace flag
load("ext://namespace", "namespace_create")
namespace_create("runtime-enforcer")

controller_image = settings.get("controller").get("image")
agent_image = settings.get("agent").get("image")
debugger_image = settings.get("debugger").get("image")
oci_hook_installer_image = settings.get("oci_hook_installer").get("image")

helm_options = [
        "controller.image.repository=" + controller_image,
        "agent.image.repository=" + agent_image,
        "ociHook.install.image.repository=" + oci_hook_installer_image,
        "controller.replicas=1",
        "controller.containerSecurityContext.runAsUser=null",
        "controller.podSecurityContext.runAsNonRoot=false",
        "agent.containerSecurityContext.runAsUser=null",
        "agent.podSecurityContext.runAsNonRoot=false",
        "debugger.enabled=true",
        "debugger.image.repository=" + debugger_image,
		# this is necessary to copy the debugger binary under `/debugger`
        "debugger.containerSecurityContext.runAsUser=null",
]

yaml = helm(
    "./charts/runtime-enforcer",
    name="runtime-enforcer",
    namespace="runtime-enforcer",
    set=helm_options
)

k8s_yaml(yaml)

# Hot reloading containers
local_resource(
    "controller_tilt",
    "make controller",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/controller",
        "api",
        "internal/controller",
        "proto",
    ],
)

entrypoint = ["/controller"]
dockerfile = "./hack/Dockerfile.controller.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    controller_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/controller",
    ],
    live_update=[
        sync("./bin/controller", "/controller"),
    ],
)

exclusions = [
    "internal/bpf/bpf_**",
    "internal/controller/"
]

local_resource(
    "agent_tilt",
    "make agent",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/agent",
        "api",
        "internal",
        "pkg",
        "bpf",
        "proto",
    ],
    ignore = exclusions,
)

entrypoint = ["/agent"]
# We use a specific Dockerfile since tilt can't run on a scratch container.
dockerfile = "./hack/Dockerfile.agent.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    agent_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/agent",
    ],
    live_update=[
        sync("./bin/agent", "/agent"),
    ],
)

local_resource(
    "oci_hook_installer_tilt",
    "make oci-hook",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/oci-hook",
        "internal",
        "pkg",
    ],
    ignore = exclusions,
)

docker_build(
    oci_hook_installer_image,
    ".",
    dockerfile="./hack/Dockerfile.oci-hook-installer.tilt",
    only=[
        "./bin/oci-hook",
    ],
    live_update=[
        sync("./bin/oci-hook", "/oci-hook"),
    ],
)

local_resource(
    "runtime_debugger_tilt",
    "make debugger",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/debugger",
        "api",
        "internal",
        "proto",
    ],
    ignore = exclusions,
)

entrypoint = ["/debugger"]
dockerfile = "./hack/Dockerfile.debugger.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    debugger_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    only=[
        "./bin/debugger",
    ],
    live_update=[
        sync("./bin/debugger", "/debugger"),
    ],
)
