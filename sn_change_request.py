#!/usr/bin/env python3

import requests
import json
import base64
import sys
import argparse, os, logging
from datetime import datetime, timedelta
from requests.models import Response

CLIENT_ID=os.getenv("CLIENT_ID")
CLIENT_SECRET=os.getenv("CLIENT_SECRET")
SCOPE=os.getenv("SCOPE")
# Tenant is the azure tenant ID, and used for retrieving the access token. Must be set.
TENANT=""

if CLIENT_ID is None or CLIENT_SECRET is None or SCOPE is None:
    print("CLIENT_ID, CLIENT_SECRET, and SCOPE environment variables must be set")
    quit(1)

template_change_request = "daa8a2ae1bee3cd0e2cd8402604bcb63"

maintenance_window = 2
change_start_time = datetime.now()
change_end_time = change_start_time + timedelta(hours=maintenance_window)
change_end_time = change_end_time.strftime("%Y-%m-%d %H:%M:%S")
change_start_time = change_start_time.strftime("%Y-%m-%d %H:%M:%S")
access_token = ""
change_request_sysid = ""
change_request = ""

CHANGE = {
    "impact": "3",
    "description": "",
    "reason": "Update CI",
    "requested_by": "",
    "assigned_to": "",
    "u_service_interruption": False,
    "u_third_weekend_maintenance": False,
    "short_description": "",
    "u_change_manager": "",
    "cmdb_ci": "",
    "start_date": change_start_time,
    "end_date": change_end_time,
    "work_start": change_start_time,
    "work_end": change_end_time
}

# Retrieve the access_token to a global variable
def azure_authorize():
    """Checks the token_file for an access token.
    If it does not exist, or is older than 60 minutes, requests a new token and writes it out. """

    try:
        if os.path.exists("token_file"):
            t = os.path.getmtime("token_file")
            d = datetime.fromtimestamp(t)        
            if datetime.now() > d + timedelta(minutes=55):
                os.remove("token_file")
            else:
                with open("token_file", 'r') as token:
                    data = json.load(token)
                    access_token = data['access_token'].strip()
                token.close()
                return access_token
    except Exception as e:
        print(str(e), file=sys.stderr)
        print("Failed in azure_authorize", file=sys.stderr)
        raise e

    url = "https://login.microsoftonline.com/" + TENANT + "/oauth2/v2.0/token"
    body = {
            'grant_type': "client_credentials",
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'scope': SCOPE
    }
    response = requests.request("POST", url, data=body)
    response = json.loads(response.text)
    access_token=response['access_token'].strip()
    if access_token != "":
        with open("token_file", "w") as token:
            json.dump(response, token)
        token.close()
    return access_token

# Return the change request for the SYS_ID - only used for debugging and evaluating a change ticket 
def check_change_request(sysid):
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }
    url = 'https://service-now.com/api/sn_chg_rest/change/standard/' + sysid


    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        print(str(e), file=sys.stderr)
        print(response.text, file=sys.stderr)
        raise e

    json_message = json.loads(response.text)
    change_request = json_message['result']['number']['value'].strip()
    u_template_name = json_message['result']['u_template']['display_value']
    u_template_id = json_message['result']['u_template']['value']
    u_change_producer_display = json_message['result']['std_change_producer_version']['display_value']
    u_change_producer_value = json_message['result']['std_change_producer_version']['value']
    u_change_state = json_message['result']['state']['value']
    u_configuration_item = json_message['result']['cmdb_ci']['display_value']
    u_change_probability = json_message['result']['u_probability']['value']
    u_close_code = json_message['result']['u_close_code']['value']
    u_assignment_group = json_message['result']['assignment_group']['display_value']
    #print (json_message)
    print ("Change Request Number: " + change_request)
    print ("Template Name: " + str(u_template_name))
    print ("Template ID: " + str(u_template_id))
    print ("Change Producer Name: " + str(u_change_producer_display))
    print ("Change Producer ID: " + str(u_change_producer_value))
    print ("Change State: " + str(u_change_state))
    print ("Configuration Item: " + str(u_configuration_item))
    print ("Change Probability: " + str(u_change_probability))
    print ("Closure Code: " + str(u_close_code))
    print ("Assignment group: " + str(u_assignment_group))
    print ("Change Ticket URL: https://service-now.com/nav_to.do?uri=change_request.do?sys_id="+sysid)

#Submit a change request, with SYS_ID as the template
def draft_change_request(template_change_request):
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }
    url = 'https://service-now.com/api/sn_chg_rest/change/standard/' + template_change_request

    success = 0
    try:
        response = requests.post(url, headers=headers, data=json.dumps(CHANGE))
        response.raise_for_status()
        success = 1
    except Exception as e:
        print(str(e), file=sys.stderr)
        print ("Failing in draft_change_request", file=sys.stderr)
        raise Exception(response.text)

    json_message = json.loads(response.text)
    if success == 1:
        change_request_ticket = json_message['result']['number']['value'].strip()
        change_request_sysid = json_message['result']['sys_id']['value'].strip()
    return change_request_sysid, change_request_ticket

def set_change_request_open(sysid):
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }
    url = 'https://service-now.com/api/sn_chg_rest/change/updateChange'

    SET_OPEN = {
        "values": {
            "change": {
                "sys_id": sysid,
                "state": "1",
                }
            }
        }
    try:
        response = requests.put(url, headers=headers, data=json.dumps(SET_OPEN))
    except Exception as e:
        print(str(e), file=sys.stderr)
        print ("Failing in set_change_to_open", file=sys.stderr)
        raise Exception(response.text)

def update_change_request(sysid, notes):
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }
    url = 'https://service-now.com/api/sn_chg_rest/change/updateChange'

    UPDATE = {
        "values": {
            "change": {
                "sys_id": sysid,
                "work_notes": notes,
            }
        }
    }

    try:
        response = requests.put(url, headers=headers, data=json.dumps(UPDATE))
    except Exception as e:
        print(str(e), file=sys.stderr)
        print ("Failing in update change request", file=sys.stderr)
        raise Exception(response.text)

def close_change_request(sysid, close_status, close_notes):
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }

    url = 'https://service-now.com/api/sn_chg_rest/change/updateChange'

    close_status_map = {
        "Completed Successful": "1",
        "Completed Unsuccessful": "2",
        "Successful with Issues": "3",
    }

    CLOSE = {
        "values": {
            "change": {
                "sys_id": sysid,
                "state": "3",
                "u_close_code": close_status_map[close_status],
                "close_notes": close_notes,
            }
        }
    }

    try:
        response = requests.put(url, headers=headers, data=json.dumps(CLOSE))
    except Exception as e:
        print(str(e), file=sys.stderr)
        print("Failed to close change request", file=sys.stderr)
        raise Exception(response.text)

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="action")

create_cmd = subparsers.add_parser("create", help="Create (draft) and open a new SN change request")
create_cmd.add_argument("-t", "--change-template-id", help="Template change request ID", default=os.getenv('CHG_TEMPLATE_ID'))
create_cmd.add_argument("-p", "--change-payload", help="JSON payload for creation of the CHG ticket", default=os.getenv('CHANGE_PAYLOAD'))
#sn_change_request.py create -t 5df584be1b6af45077ff866ecc4bcb79 -p CHANGE_PAYLOAD

update_cmd = subparsers.add_parser("update", help="Update existing CHG ticket with provided sys_id")
update_cmd.add_argument('-i', '--sys-id', help="sys_id of the existing CHG ticket", required=True)
update_cmd.add_argument('-n', '--notes', help="Update an existing CHG ticket with the provided notes", required=True)
#sn_change_request.py update -i 09e221b81ba2705077ff866ecc4bcb03 -n "This is a test note"

close_cmd = subparsers.add_parser("close", help="Close existing CHG ticket with close status and optional close notes")
close_cmd.add_argument('-i', '--sys-id', help="sys_id of the existing CHG ticket", required=True)
close_cmd.add_argument('-s', '--close-status', help="Close status", choices=["Completed Successful", "Completed Unsuccessful", "Successful with Issues"], required=True)
close_cmd.add_argument('-n', '--notes', help="Close notes")
#sn_change_request.py close -i 09e221b81ba2705077ff866ecc4bcb03 -s "Completed Successful" -n "Completed Successful"

check_cmd = subparsers.add_parser("check", help="Check a CHG ticket with provided sys_id")
check_cmd.add_argument('-i', '--sys-id', help="sys_id of the existing CHG ticket", required=True)
#sn_change_request.py check -i 09e221b81ba2705077ff866ecc4bcb03

args = parser.parse_args()

if args.action in ["create", "update", "close", "check"]:
    response = {"success": True }

    access_token = azure_authorize()

    try:
        if args.action == "create":
            logging.info(f"RUNNING {args.action}...")
            if args.change_payload is not None:
                CHANGE.update(json.loads(args.change_payload))
            request_sysid, change_request = draft_change_request(args.change_template_id)
            set_change_request_open(request_sysid)
            response["sys_id"] = request_sysid
            response["change_ticket"] = change_request
        elif args.action == "update":
            logging.info(f"RUNNING {args.action}...")
            args.notes = str(base64.b64decode(args.notes))
            formatted_notes = args.notes.replace('\\n', '\n').replace('\\t', '\t').replace('\\', '')
            update_change_request(args.sys_id, formatted_notes)
        elif args.action == "check":
            logging.info(f"RUNNING {args.action}...")
            check_change_request(args.sys_id)
        elif args.action == "close":
            logging.info(f"RUNNING {args.action}...")
            close_change_request(args.sys_id, args.close_status, args.notes)
    except Exception as e:
        print(str(e), file=sys.stderr)
        print (CHANGE, file=sys.stderr)
        response["success"] = False
        print(json.dumps(response), file=sys.stderr)
        quit(1)

    print(json.dumps(response))

else:
    parser.print_help()