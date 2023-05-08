from prefect import task, flow
from prefect import get_run_logger
import time
import pandas as pd

def this_is_not_a_task(logger):
    logger.info("I am not a task context")

@task
def log_platform_info():
    logger = get_run_logger()
    logger.info("hello world")
    this_is_not_a_task(logger)


@task
def read_file(path):
    return pd.read_csv(path)


@task(log_prints=True)
def transform_pd(df):
    results = [ row['col1'] * row['col2'] for index,row in df.iterrows() ]
    print (results)
    #for index,row in df.iterrows():
    #    print (row['col1'] * row['col2'])


@flow(log_prints=True)
def hello_world():
    logger = get_run_logger()
    log_platform_info()

    csv_path = "./file.csv"
    df = read_file(csv_path)
    transform_pd(df)


if __name__ == "__main__":
    hello_world()

