from prefect import flow, task, get_run_logger
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import sys
from prefect.runner.storage import GitRepository

def send_email(msg):
# Email Parameters
    sender_email = "chris.allan.boyd@gmail.com"
    receiver_email = "chris.b@prefect.io"
    password = os.environ.get('EMAIL_PASSWORD')  # Read password from environment variable

    # Create the MIME Object
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Flow Run Hooks"

    # Email Body
    message.attach(MIMEText(msg, "plain"))

    # Send the Email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully")
    except Exception as e:
        print(f"Error: {e}")

    
def prefect_flow_on_completion(flow, flow_run, state):
    send_email("This is in an on_completion hook")
    return

def prefect_flow_on_failure(flow, flow_run, state):
    send_email("This is in an on_failure hook")
    return


def wrapped_flow(**kwargs):
    return flow(
        on_failure=[prefect_flow_on_failure],
        on_completion=[prefect_flow_on_completion],
        **kwargs
    )


def send_logs(func):
    def wrapper(*args, **kwargs):
        print("Sending some logs")
        print("Sending some logs to stderr", file=sys.stderr)
        return func(*args, **kwargs)
    return wrapper

# @send_logs
@flow
def hello_flow():
    logger = get_run_logger()
    logger.info("Hello world!")
    logger.info("Going to send an email now...")
    random_number = random.randint(1, 10)

    if random_number % 2 == 0:
        raise ValueError("Random number is even, so we'll fail the flow")
    else:
        return 


if __name__ == "__main__":
    # hello_flow()
    flow.from_source(
        source=GitRepository(
            url="https://github.com/chrisaboyd/Samples.git"
        ),
        entrypoint="Prefect/wrapped_flow_test.py:hello_flow"
    ).deploy(
        name=f"decorated_and_wrapped_flow",
        work_pool_name="dev",
        build=False
    )