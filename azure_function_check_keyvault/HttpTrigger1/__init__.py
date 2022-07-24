import logging
import os
import json
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    password = os.getenv('PassfromKeyVault')

    keyvaultList = [
        {'vault_name': "ollieassignmentkv4", 'secret_name': "", 'created_on': "", 'secret_value': ""},
        {'vault_name': "ollieassignmentkv5", 'secret_name': "", 'created_on': "", 'secret_value': ""},
        {'vault_name': "ollieassignmentkv6", 'secret_name': "", 'created_on': "", 'secret_value': ""}
    ]
    
    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

# Here it is statically defined for the assignment, and returning out otherwise.
# Improving this would be if name is not None: 
#   Check each keyvault to see if name exists in the keyvault.
#   If name exists - retrieve values
#   Else - return generic error.
    if name == "ollieAssignmentSecret":
        response = ''
        credential = DefaultAzureCredential()
        for item in keyvaultList:
            item['secret_name'] = name
            vaultUri = f"https://{item['vault_name']}.vault.azure.net/"
            client1 = SecretClient(vault_url=vaultUri, credential=credential)
            print (f"Trying to retrieve {item['secret_name']} from {vaultUri}")
            try:
                retrieved_secret = client1.get_secret(item['secret_name'])
                secret_versions = client1.list_properties_of_secret_versions(item['secret_name'])
                for secret in secret_versions:
                    if secret.name == "ollieAssignmentSecret":
                        item['created_on'] = secret.created_on
                        item['secret_value'] = retrieved_secret.value
                response += f"""
                Key Vault: {item['vault_name']}
                Secret Name: {item['secret_name']}
                Creation Date: {item['created_on']}
                Secret Value: {item['secret_value']}

                """
            except Exception as e:
                print ("AHHHH")
        return func.HttpResponse(f"{response}")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Please review your query for accuracy.",
             status_code=200)
