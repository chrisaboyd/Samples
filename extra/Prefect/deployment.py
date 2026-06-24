"""Deployment script for Prefect2 Deployment."""
import sys
from os import environ, path

# aqua common
from gcp.runtime_configurator import RuntimeConfigurator
from prefect.deployments import Deployment

sys.path.insert(0, path.abspath(path.join(path.dirname(__file__), "../src")))
from flow import flow as supa_flow

# retrieve dynamic variables from environment
BOYD_ENVIRONMENT = environ.get("BOYD_ENVIRONMENT", "dev").upper()
GCP_PROJECT_ID = environ.get("GCP_PROJECT_ID", "gcp-boyddev-12345")
GCP_RESULTS_BUCKET = environ.get(
    "GCP_RESULTS_BUCKET", f"{GCP_PROJECT_ID}-prefect-results"
)
PYTHON_VERSION = ".".join(environ.get("PYENV_VERSION", "3.9").split(".")[:2])
PREFECT_VERSION = environ.get("PREFECT_VERSION", "2.14.9")
FLOW_NAME = aqua_flow.__name__
PROJECT_NAME = environ.get("PROJECT_NAME", f"{FLOW_NAME}_prefect2")
IMAGE_URL = "gcr.io/" + GCP_PROJECT_ID + "/" + PROJECT_NAME
DEPLOY_TYPE = (sys.argv[1:2] or ["regular"])[0]
K8S_JOB_NAME = f"{FLOW_NAME}-{DEPLOY_TYPE}".replace("_", "-")


def main():
    """Main function."""

    create_deployment()


def create_deployment():
    """Create deployment using Kubernetes Job Block."""
    deployment_name = f"{FLOW_NAME}_{DEPLOY_TYPE.replace('-', '_')}"
    print(f"Creating deployment {deployment_name}...")

    try:
        config = RuntimeConfigurator(BOYD_ENVIRONMENT)
        config_values_all = config.list_variables("deployment")
        config_values = {
            k.split("/")[1]: v
            for k, v in config_values_all.items()
            if k.split("/")[0] == PROJECT_NAME
        }
        print(f"Config values from RuntimeConfigurator: {config_values}")
    except Exception:
        config_values = {}

    environment = {
        "BOYD_ENVIRONMENT": BOYD_ENVIRONMENT,
        "GCP_PROJECT_ID": GCP_PROJECT_ID,
        "GCP_RESULTS_BUCKET": GCP_RESULTS_BUCKET,
        "PREFECT_VERSION": PREFECT_VERSION,
        "PYTHON_VERSION": PYTHON_VERSION,
    }

    infra_overrides = {
        "image": IMAGE_URL,
        "env": environment,
        "cpu_limit": config_values.get("cpu_limit", "1.8Ki"),
        "cpu_request": config_values.get("cpu_request", "1"),
        "memory_limit": config_values.get("memory_limit", "6Gi"),
        "memory_request": config_values.get("memory_request", "2Gi")
    }

    deployment = Deployment.build_from_flow(
        flow=supa_flow,
        name=deployment_name,
        work_queue_name="default",
        work_pool_name=f"aqua_{BOYD_ENVIRONMENT.lower()}_{DEPLOY_TYPE}",
        infra_overrides=infra_overrides,
        path="/opt/prefect/flows",
        entrypoint=f"flow.py:{FLOW_NAME}",
    )
    uuid = deployment.apply()
    print(f"Saved deployment {deployment_name}: {uuid}")


if __name__ == "__main__":
    main()
