import os

import boto3
import json

#Map the jobQueue to the accounts SQS Queue
batch_to_sqs_map = {
    "Fargate_boyd": "east-boyd-q1",
}

#Sets up the sqs client resource
sqs = boto3.resource(
    'sqs',
    region_name="us-east-1"
    )

#Build the message for Batch + State tracking
def build_batch_job_params():
    message = {
        "jobName": "",
        "jobQueue": "",
        "jobDefinition": "",
        "sqsQueue": "",
        "flowId": "",
    }

    message['jobName'] = input("Job Name:")
    message['jobQueue'] = input("Job Queue:")
    message['jobDefinition'] = input("Job Definition:")
    message['sqsQueue'] = batch_to_sqs_map[message['jobQueue']]
    message['flowId'] = "abc123"#prefect.context.flow_id
    return message

#Submits the message to the appropriate queue
def public_message_to_sqs(message: str, queue):
    data = json.dumps(message)
    response = queue.send_message(MessageBody=data)
    print (f"Message sent to queue: {message['sqsQueue']}")
    print (json.dumps(response, indent=4))

#Returns a templated message for testing
def test():
    message = {
        "jobName": "test_one",
        "jobQueue": "Fargate_boyd",
        "jobDefinition": "Boyd_job_fargate",
        "sqsQueue": "east-boyd-q1",
        "flowId": "bcd-1234-efgh-5678",
    }

    return message

def main():
    message = test()
    #message = build_batch_job_params()
    queue_client = sqs.get_queue_by_name(QueueName=message['sqsQueue'])
    public_message_to_sqs(message,queue_client)

if __name__ == "__main__":
    main()


