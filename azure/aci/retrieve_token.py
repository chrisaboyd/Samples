from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Set up the default credential, which uses the managed identity of the Azure resource (ACI, VM, etc.)
credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)

# Create a secret client using the default credential and the URL to the Key Vault
secret_client = SecretClient(vault_url="https://aci.vault.azure.net", credential=credential)

# Retrieve the secret
secret_name = ""
retrieved_secret = secret_client.get_secret(secret_name)

# Write the secret to a .env file
with open('/tmp/.env', 'w') as file:
    file.write(f"export GIT_USERNAME={secret_name}\n")
    file.write(f"export GIT_PASSWORD={retrieved_secret.value}\n")
