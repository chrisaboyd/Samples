import json
import boto3
from chalice import Chalice

app = Chalice(app_name='sqs-to-batch-lambda')

@app.on_sqs_message(queue='east-boyd-q1')
def handler(event):
    for record in event:
        #record.body is the message sent through
        job_details = json.loads(record.body)
        jobName = job_details.pop('jobName')
        jobQueue = job_details.pop('jobQueue')
        jobDefinition = job_details.pop('jobDefinition')
        containerOverrides = {
            "environment": [ {
                "name": "flow_id",
                "value": job_details['flowId']
            } ]
        }
        print (f"""Job Name: {jobName} \
                Job Queue: {jobQueue} \
                Job Definition: {jobDefinition} \
                Flow ID: {containerOverrides['environment'][0]['value']} \
                """)
        batch = boto3.client('batch')

        response = batch.submit_job(
            jobDefinition=jobDefinition,
            jobName=jobName,
            jobQueue=jobQueue,
            containerOverrides=containerOverrides,
        )

        print (json.dumps(response, indent=4))