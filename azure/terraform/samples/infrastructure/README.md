
## Create Terraform Backend

```bash
rgName=rg-terraformstate
random=$RANDOM 
saName=terraformstate${random}
containerName=springstate

# Create Azure Resource Group
az group create \
    --name $rgName \
    --location eastus
# Create Storage Account with public access disabled
az storage account create \
    --resource-group $rgName \
    --name $saName \
    --sku Standard_LRS \
    --allow-blob-public-access $false
# Create container to store configuration state file
az storage container create \
    --name $containerName \
    --account-name $saName
```