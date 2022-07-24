import os
import logging
from azure.keyvault.secrets import SecretClient
from azure.identity import AzureCliCredential

for item in keyvaultList:
    item['secret_name'] = "OllieAssignmentSecret"
    credential = AzureCliCredential()
    vaultUri = f"https://{item['vault_name']}.vault.azure.net/"
    client1 = SecretClient(vault_url=vaultUri, credential=credential)
    print (f"Retrieving your secret from {item['vault_name']}")
    try:
        retrieved_secret = client1.get_secret(item['secret_name'])
        secret_versions = client1.list_properties_of_secret_versions(item['secret_name'])
        for secret in secret_versions:
            if secret.name == "OllieAssignmentSecret":
                item['created_on'] = secret.created_on
                item['secret_value'] = retrieved_secret.value
    except Exception as ex:
        print("No secret found.")

for item in keyvaultList:
    print (item['vault_name'])
    print (item['secret_name'])
    print (item['created_on'])
    print (item['secret_value'])





