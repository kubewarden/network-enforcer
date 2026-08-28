tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

allow_k8s_contexts(settings.get("clusters"))

update_settings(
    k8s_upsert_timeout_secs=180,
)

# Create the namespace
# This is required since the helm() function doesn't support the create_namespace flag
release_namespace = "network-enforcer"
load("ext://namespace", "namespace_create")
namespace_create(release_namespace)

controller_image = settings.get("controller").get("image")

# allow the override of the provider from command line
config.define_string("provider")
cfg = config.parse()
providerName = cfg.get("provider") or settings.get("controller").get("providerName")

# Prepare Helm set values based on CNI type
helm_set_values = [
    "controller.image.repository=" + controller_image,
    "controller.replicas=1",
    "controller.containerSecurityContext.runAsUser=null",
    "controller.podSecurityContext.runAsNonRoot=false",
	"controller.provider.name=" + providerName,
	"controller.flowDumper.enabled=true",
]

yaml = helm(
    "./charts/network-enforcer",
    name="network-enforcer",
    namespace=release_namespace,
    set=helm_set_values
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
        "internal",
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
