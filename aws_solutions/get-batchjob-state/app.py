from chalice import Chalice
from collections import Counter
import boto3
import json

app = Chalice(app_name='get-batchjob-state')

dynamodb = boto3.resource('dynamodb')

@app.route('/describe-jobs')
def describe_jobs():
    response = table_lookup()
    count = Counter(msg['batchState'] for msg in response)

    return count

@app.route('/describe-jobs/{state}')
def describe_job_state(state):
    filterExpression=f'batchState = {state}'
    response = table_lookup(filterExpression)
    print (response)

    return response

def table_lookup(filterExpression=None):
    table = dynamodb.Table("boyd_batch_state")
    if filterExpression:
        db_items = table.scan(
            FilterExpression=filterExpression
        )
    else:
        db_items = table.scan()
    return db_items['Items']

def generate_return_body(status_code, message):
    return {
        'statusCode': status_code,
        'body': json.dumps({
            'message': message
        })
    }

# The view function above will return {"hello": "world"}
# whenever you make an HTTP GET request to '/'.
#
# Here are a few more examples:
#
# @app.route('/hello/{name}')
# def hello_name(name):
#    # '/hello/james' -> {"hello": "james"}
#    return {'hello': name}
#
# @app.route('/users', methods=['POST'])
# def create_user():
#     # This is the JSON body the user sent in their POST request.
#     user_as_json = app.current_request.json_body
#     # We'll echo the json body back to the user in a 'user' key.
#     return {'user': user_as_json}
#
# See the README documentation for more examples.
#
