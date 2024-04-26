import time

from prefect import flow, task
from prefect_dask import DaskTaskRunner

@task
def shout(number):
    time.sleep(0.5)
    print(f"#{number}")
    raise ValueError("This is a test")

@flow(task_runner=DaskTaskRunner)
def count_to(highest_number):
    for number in range(highest_number):
        shout.submit(number)

if __name__ == "__main__":
    count_to(10)

# outputs
#3
#7
#2
#6
#4
#0
#1
#5
#8
#9
