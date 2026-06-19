from prefect import task, flow, get_run_logger
import time

def handle_cancelled(flow, flow_run, state) -> None:
    print("cancelled!!!!!!!")


def handle_crashed(flow, flow_run, state) -> None:
    print("crashed!!!!!!!")

@task
def do_the_sleep():
    time.sleep(120)


@flow(name="generic-testing-flow", on_cancellation=[handle_cancelled], on_crashed=[handle_crashed])
def hello():
    logger = get_run_logger()
    logger.info("Testing Hello")
    print("Testing Hello Print")
    logger.info("Sleeping for 120 seconds")
    print("Sleeping for 120 seconds - Print")
    do_the_sleep()
    
if __name__ == "__main__":
    hello()
