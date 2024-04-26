from prefect import flow, task, get_run_logger, pause_flow_run
import random
import sys
from prefect.runner.storage import GitRepository
from functools import wraps
from prefect.input import RunInput
from pydantic import BaseModel, ValidationError
from enum import Enum
from pydantic import Field


class UserOptions(BaseModel):
    should_approve: bool = Field(description="Approve this model?", default=False)


def prefect_flow_on_completion(flow, flow_run, state):
    print("This is in an on_completion hook")
    return

def prefect_flow_on_failure(flow, flow_run, state):
    print("This is in an on_failure hook")
    return

def wrapped_flow(**kwargs):
    return flow(
        on_failure=[prefect_flow_on_failure],
        on_completion=[prefect_flow_on_completion],
        **kwargs
    )

@task
def model_task_cost():
    return 1100


@wrapped_flow()
def interactive():
    logger = get_run_logger()
    cost = model_task_cost()

    if cost > 1000:
        print("Cost is greater than 1000, pausing flow run")
        user = pause_flow_run(wait_for_input=UserOptions)

        if user.should_approve:
            print("Approved")
        else:
            print("Denied")
    else:
        print("Cost is less than 1000, continuing flow run")


if __name__ == "__main__":
    interactive.serve(
        name="wrapped_flow"
    )
