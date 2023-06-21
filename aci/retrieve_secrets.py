from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
import sys

# Set up the default credential, which uses the managed identity of the Azure resource (ACI, VM, etc.)
def get_creds(auth_type):
    if auth_type == "managed_identity":
        credential = ManagedIdentityCredential(client_id="830268e4-7ab3-4302-95ff-eb2364010878") # myaciid clientId
    else:
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
    return credential


def get_secret(credential):
    # Create a secret client using the default credential and the URL to the Key Vault
    secret_client = SecretClient(vault_url="https://boydaciprefectkv.vault.azure.net", credential=credential)
    secret_name = "prefectboyd"
    # Retrieve the secret
    retrieved_secret = secret_client.get_secret(secret_name)
    print (retrieved_secret.value)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "managed_identity":
        credential = get_creds("managed_identity")
    else:
        credential = get_creds("default")
    get_secret(credential)

if __name__ == "__main__":
    main()
