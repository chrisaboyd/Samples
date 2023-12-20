from prefect import task, flow, get_run_logger, serve
import time

def this_is_not_a_task(logger):
    logger.info("I am not a task context")


@task()
def log_platform_info():
    logger = get_run_logger()
    logger.info("hello world")
    this_is_not_a_task(logger)


@task()
def foo_bar():
    logger = get_run_logger()
    logger.info("foo bar")



@flow(log_prints=True)
def hello_world():
    logger = get_run_logger()
    log_platform_info()

@flow(log_prints=True)
def foo():
    logger = get_run_logger()
    foo_bar()

if __name__ == "__main__":

    fast_foo = foo.to_deployment(name="foo", interval=10)
    hello = hello_world.to_deployment(name="hello", interval=10)
    serve(fast_foo, hello)


