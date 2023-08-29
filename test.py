from prefect import flow, get_run_logger


@flow(log_prints=True)
def test(numbers: list = [1, 2]):
    logger = get_run_logger()
    for i in numbers:
        logger.info(i)
