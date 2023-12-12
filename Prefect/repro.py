from prefect import flow, get_run_logger
from prefect.context import FlowRunContext

@flow(name="test")
def heartbeat(partial_run_tasks: list[str] | None = None):
    flow_run_ctx = FlowRunContext.get()
    partial_run_tasks = flow_run_ctx.parameters.get("partial_run_tasks")
    get_run_logger.info(f"partial_run_tasks: {partial_run_tasks}")
    pass


if __name__ == "__main__":
    heartbeat.from_source(
        source=GitRepository(
            url="https://github.com/chrisaboyd/Samples.git"
        ),
        entrypoint="Prefect/repro.py:heartbeat",
    ).deploy(
        name=f"heartbeat_repro",
        work_pool_name="dev",
        build=False
    )