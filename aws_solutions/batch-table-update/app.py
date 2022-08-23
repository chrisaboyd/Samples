from chalice import Chalice
from botocore.exceptions import ClientError
import boto3
import json
import sys
import os

app = Chalice(app_name='batch-table-update')

dynamodb = boto3.resource('dynamodb')

#Main handler to receive eventbridge events
@app.lambda_function()
def lambda_handler(event, context):
    print(f"Event Received: {json.dumps(event)}")
    db_item = build_item(event)
    print (f"{db_item}")
    try:
        # write the flowId, jobId, jobState, timestamp, and jobName to dynamo
        write_to_dynamo(db_item)
        return generate_return_body('200', "Successfully updated DynamoDB")
    except ClientError as e:
        print('ClientError', e)
        return generate_return_body('500', str(e))


#Builds and returns the table row
def build_item(event):
    db_item = {
        'flowId': event['detail']['container']['environment'][0]['value'],
        'jobId': event['detail']['jobId'],
        'batchState':event['detail']['status'],
        'jobName':event['detail']['jobName'],
        'timeOfState':event['time'],
    }
    return db_item


#Writes the row to dynamoDB
def write_to_dynamo(db_item: dict):
    table = dynamodb.Table("boyd_batch_state")
    table.put_item(
        Item={
                'jobId': db_item['jobId'],
                'flowId': db_item['flowId'],
                'batchState': db_item['batchState'],
                'timeOfState': db_item['timeOfState'],
                'jobName': db_item['jobName'],
            }
    )

#Constructs a return payload for observability
def generate_return_body(status_code, message):
    return {
        'statusCode': status_code,
        'body': json.dumps({
            'message': message
        })
    }

# For running locally. Pass in the path to a valid event in a JSON file to test
# if __name__ == '__main__':
#     lambda_handler
#     if os.getenv('LAMBDA_ENV') != 'true':
#         with open(sys.argv[1], 'r') as f:
#             print(lambda_handler(json.load(f), 'context'))
