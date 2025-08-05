tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

update_settings(
	k8s_upsert_timeout_secs=180,
)

# while it takes some time to install cert manager, it's okay to wait 
# because we rely on its ca injector to setup our mutating webhook.
load('ext://cert_manager', 'deploy_cert_manager')

deploy_cert_manager(version="v1.18.2")

# Create the namespace
# This is required since the helm() function doesn't support the create_namespace flag
load("ext://namespace", "namespace_create")
namespace_create("runtime-enforcement")

operator_image = settings.get("operator").get("image")
daemon_image = settings.get("daemon").get("image")

yaml = helm(
    "./charts/runtime-enforcement",
    name="runtime-enforcement",
    namespace="runtime-enforcement",
    set=[
        "operator.manager.image.repository=" + operator_image,
        "daemon.daemon.image.repository=" + daemon_image,
        "operator.replicas=1",
	"operator.manager.containerSecurityContext.runAsUser=null",
	"operator.podSecurityContext.runAsNonRoot=false",
	"daemon.daemon.containerSecurityContext.runAsUser=null",
	"daemon.podSecurityContext.runAsNonRoot=false"
    ]
)

k8s_yaml(yaml)

# Hot reloading containers
local_resource(
    "operator_tilt",
    "make operator",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/operator",
        "api",
        "internal/controller",
	"pkg",
    ],
)

entrypoint = ["/operator"]
dockerfile = "./hack/Dockerfile.operator.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    operator_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/operator",
    ],
    live_update=[
        sync("./bin/operator", "/operator"),
    ],
)

local_resource(
    "daemon_tilt",
    "make daemon",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/daemon",
        "api",
        "internal/eventhandler",
        "internal/tetragon",
        "pkg"
    ],
)

entrypoint = ["/daemon"]
# We use a specific Dockerfile since tilt can't run on a scratch container.
dockerfile = "./hack/Dockerfile.daemon.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    daemon_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/daemon",
    ],
    live_update=[
        sync("./bin/daemon", "/daemon"),
    ],
)

