# Azure AKS

<!-- TABLE OF CONTENTS -->
  <ol>
    <li>
      <a href="#pre-requisites">Pre-requisites</a>
    <li>
      <a href="#provisioning-infrastructure">Provisioning infrastructure</a>
    <li>
      <a href="#setting-up-workers-on-aks">Setting up workers on AKS</a>
    <li>
      <a href="#additional-resources">Additional resources</a>
  </ol>
​
## File References
The following files included will be referenced throughout the tutorial.

[Dockerfile](/part_2/aks/Dockerfile) - Sample Dockerfile Template  
[README.md](/part_2/aks/README.md) - This document  
[SecretProviderClass.yaml](/part_2/aks/SecretProviderClass.yaml) - Sample SecretProviderClass  
[advanced_workpool.yaml](/part_2/aks/advanced_workpool.yaml) - Sample Complete Workpool  
[override1.yaml](/part_2/aks/override1.yaml) - Sample Helm Worker Override1  
[override2.yaml](/part_2/aks/override2.yaml) - Sample Helm Worker Override2   
[requirements.txt](/part_2/aks/requirements.txt) - Docker Image Packages  
[prefect.yaml](/part_2/aks/prefect.yaml) - Demo Deploy Pull using $Env variable  
[transform_flow.py](/part_2/aks/transform_flow.py) - Prefect Flow  
<!-- Pre-requisites -->

# Pre-requisites

- azure-cli  
- kubectl  
- kubelogin  
- Prefect 2  
​
Additionally, this document anticipates you have a valid Service Principal or User Authorization to perform the necessary roles and steps. As this is provisioning compute, network, and storage, the "Contributor" role should have sufficient permissions necessary.
More details can be found [here](https://docs.microsoft.com/en-us/azure/developer/terraform/authenticate-to-azure?tabs=bash#create-a-service-principal)
  

### Install pre-requisites
```bash
brew install azure-cli
az aks install-cli --kubelogin-install-location mykubetools/kubelogin
brew install kubectl
pip install prefect
```

<!-- Provisioning infrastructure -->  
# Provisioning infrastructure

### Login with your [service principal](https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli)
```bash 
az login --service-principal -u <app-id> -p <password-or-cert> --tenant <tenant>
```
​
### Register the [AKS provider](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types) in Azure
```bash
az provider register -n Microsoft.ContainerService
```
​
### Create a resource group, and export the value for re-use later
```bash
export rg="prefect_aks-rg"
az group create --name $rg --location eastus
```
​
### Create VNet and Subnet
For simplicity in this tutorial, we will allow AKS to use "kubenet" networking, which is by default, and requires no additional steps or configuration.   
If provisioning through Terraform, Azure CNI will be used - more details can be found [here](https://docs.microsoft.com/en-us/azure/aks/configure-azure-cni#advanced-networking)
​
```bash
az network vnet create -g $rg -n prefectvnet --address-prefix 10.1.0.0/16 \
    --subnet-name prefectsubnet --subnet-prefix 10.1.1.0/24
```
​
### Enable Service Endpoints
We need to enable the vnet and subnet for Service Endpoints (vnet / subnet) - Storage can only be accessed from inside the same Subnet, and explicitly whitelisted IP's for security.
​
```bash
az network vnet subnet update --resource-group "$rg" --vnet-name "prefectvnet" --name "prefectsubnet" --service-endpoints "Microsoft.Storage"
```
​
### Setup Storage Account 
**Storage account names must be GLOBALLY unique - you will need to change this to a custom value**  
Limitations are 3-24 characters, all lowercase alpha-numeric. [a-z0-9].
​
```bash
export san="oneofakind112233"
az storage account create -n "$san" -g $rg -l eastus --sku Standard_LRS
```
​
### Retrieve account key and connection string 
```bash
export sas_key=$(az storage account keys list -g $rg -n "$san" --query "[0].value" --output tsv)
export AZURE_STORAGE_CONNECTION_STRING=$(az storage account show-connection-string --resource-group "$rg" --name "$san" --output tsv)
```
​
### Create Storage Container
Here we are creating a container named `prefect-logs` in the storage account.
```sh
az storage container create -n "prefect-logs" --account-name "$san"
```
​
### Verify IP address
We want to whitelist our own IP address for security reasons.  
If this step is not completed, you will be locked out from further configuration at the CLI.  
Additionally, add the Subnet to the allow list.
```
my_ip=$(curl ifconfig.me)
az storage account network-rule add --resource-group "$rg" --account-name "$san" --ip-address "$my_ip"
subnetid=$(az network vnet subnet show --resource-group "$rg" --vnet-name "prefectvnet" --name "prefectsubnet" --query id --output tsv)
az storage account network-rule add --resource-group "$rg" --account-name "$san" --subnet $subnetid
```
​
### Set Default Deny
Set the default action to deny all traffic other than what was just permitted in step 10.  
```sh
az storage account update -n "$san" --default-action Deny
```
​
###  Create an AKS cluster. 
Here we are creating a minimal configuration with 2 nodes for tutorial purposes. 

:exclamation: - Standard_B2s nodes might not be available in the eastus region if you are using a free-tier Azure account.   
See [this](https://docs.microsoft.com/en-us/rest/api/compute/resource-skus/list) and [this](https://docs.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-sku-not-available?tabs=azure-cli) article for more help in determining suitable locations / sku's if you are using a free tier.
​
```bash
export aks="myprefectAKSCluster"
az aks create \
--resource-group $rg \
--name "$aks" \
--node-count 2 \
--node-vm-size "Standard_B2s" \
--enable-oidc-issuer \
--enable-workload-identity \
--enable-addons azure-keyvault-secrets-provider \
--generate-ssh-keys
```
​
### Retrieve KUBECONFIG

In order to interface with the created cluster, we need to retrieve connection settings, referred to as the `KUBECONFIG`.  
Here we are setting the output `KUBECONFIG` to an alternate location, to not merge with any existing contexts you might already have.  
`az aks get-credentials --resource-group $rg --name "$aks" -f "~/.kube/$aks_config"`


### Updating KUBECONFIG
We need to use the newly created config.
`export KUBECONFIG=~/.kube/$aks_config`


### (Optional) - Enabling Required Cluster Add-Ons
:exclamation: - If you created the cluster following this tutorial, this step can be skipped.   
:exclamation: - If you have a pre-existing cluster, this step is required.  
Requirements include:  
  - enable-oidc-issuer  
  - enable-workload-identity  
  - azure-keyvaults-secrets-provider 

[Azure Vault Provider](https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver)

```sh
# Update cluster to enable add-ons
az aks update -g "${RESOURCE_GROUP}" -n myAKSCluster --enable-oidc-issuer --enable-workload-identity
az aks enable-addons -g "${RESOURCE_GROUP}" -n myAKSCluster --addons azure-keyvault-secrets-provider 
```


### Retrieve OIDC Issuer URL
Retrieve the OIDC Issuer URL, and save to an environment variable. The OIDC Issuer will be used in a later step to link the cluster `Managed Identity` with the `Service Account Issuer` and the `Subject`. 
```
export AKS_OIDC_ISSUER="$(az aks show -n myAKSCluster -g "${RESOURCE_GROUP}" --query "oidcIssuerProfile.issuerUrl" -otsv)"
```

### Create a Managed Identity
A Managed Identity is simply another term for a `user`.   
In this case, the Identity will be linked to a Service Account which will be used in the cluster. 
We can then assign any Azure permissions to the Identity (as if it were a user), which will be inherited by the Service Account tied to the identity. 

The purpose of doing this, would be for a Kubernetes Pod to have the necessary permissions to access a specific secret (like a `StorageConnectionString`) without needing to store it in code. 
In the event this code is ran locally, an error would be thrown, as you would have insufficient permissions. 
When the code is ran from a pod with a configured identity, the secret will be accessible. 

```sh
# Export Required variables
export RESOURCE_GROUP="myResourceGroup"
export LOCATION="westcentralus"
export SERVICE_ACCOUNT_NAMESPACE="default" # Should match the namespace for your Prefect Jobs
export SERVICE_ACCOUNT_NAME="workload-identity-sa" # Can be default / Name is arbitrary
export SUBSCRIPTION="$(az account show --query id --output tsv)"
export USER_ASSIGNED_IDENTITY_NAME="myIdentity" #Can be default / Name is arbitrary
export FEDERATED_IDENTITY_CREDENTIAL_NAME="myFedIdentity" # Can be default / Name is arbitrary

# Create the identity
az identity create --name "${USER_ASSIGNED_IDENTITY_NAME}" \
--resource-group "${RESOURCE_GROUP}" \
--location "${LOCATION}" \
--subscription "${SUBSCRIPTION}"

# Export the clientId of the identity
export USER_ASSIGNED_CLIENT_ID="$(az identity show --resource-group "${RESOURCE_GROUP}" \
--name "${USER_ASSIGNED_IDENTITY_NAME}" \
--query 'clientId' -otsv)"
```

### Create A Kubernetes Service Account
In the previous step we created a Managed Identity which roles and permissions can be assigned to in Azure. In this step, we create a Kubernetes Service Account to link these roles and permissions into the cluster. As this tutorial is intended for Prefect, the service account should be created in the same Namespace as Prefect. 
:exclamation: Alternatively, we can apply the annotations to the existing `prefect` service account.
```sh
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    azure.workload.identity/client-id: "${USER_ASSIGNED_CLIENT_ID}"
  name: "${SERVICE_ACCOUNT_NAME}"
  namespace: "${SERVICE_ACCOUNT_NAMESPACE}"
EOF
```

:exclamation: Alternatively, we can apply the annotations to the existing `prefect` service account. Assuming an existing `prefect-worker` or `prefect-agent` service account, you can simply add the annotation in the metadata section:
```sh
k edit serviceaccount prefect-worker

apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    azure.workload.identity/client-id: <USER ASSIGNED CLIENT ID>
```

### Federate the Identity Credential
This step creates the trust link between the identity, the issuer, and the service account. The variables were exported in the identity create step.
This step takes a few minutes to propagate to the service account.
```sh
az identity federated-credential create \
--name ${FEDERATED_IDENTITY_CREDENTIAL_NAME} \
--identity-name "${USER_ASSIGNED_IDENTITY_NAME}" \
--resource-group "${RESOURCE_GROUP}" \
--issuer "${AKS_OIDC_ISSUER}" \
--subject system:serviceaccount:"${SERVICE_ACCOUNT_NAMESPACE}":"${SERVICE_ACCOUNT_NAME}" \
--audience api://AzureADTokenExchange
```

### Enable Identity Access to the KeyVault
The intent behind these steps is to limit access to an exclusive identity, that has explicit permissions to retrieve a resource. Using the earlier example, this could be **explicit** access to a single secret, or an entire keyvault.

```sh
export KEYVAULT_NAME="myKeyVault"

az keyvault set-policy --name "${KEYVAULT_NAME}" \
--secret-permissions get --spn "${USER_ASSIGNED_CLIENT_ID}"
```
### Configuring CSI Secrets Driver
The [CSI Secrets Driver](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html) will allow the K8s cluster to sync a secret directly from the Keyvault, to the pod. This will be used to access the SCM / Bitbucket Token before flow execution.

```sh
# Add the CSI Driver Helm Repo
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
# Install the CSI Driver Helm Chart
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver --namespace kube-system --set syncSecret.enabled=true --set enableSecretRotation=true
```

### Verify Installation of CSI + Key Vault Provider
With the helm chart successfully installed, the secrets-provider add-on enabled for the cluster, we should see the following output from `kubectl`:
```sh
kubectl get pods -n kube-system -l 'app in (secrets-store-csi-driver,secrets-store-provider-azure)'

NAME                                     READY   STATUS    RESTARTS   AGE
aks-secrets-store-csi-driver-4vpkj       3/3     Running   2          4m25s
aks-secrets-store-csi-driver-ctjq6       3/3     Running   2          4m21s
aks-secrets-store-csi-driver-tlvlq       3/3     Running   2          4m24s
aks-secrets-store-provider-azure-5p4nb   1/1     Running   0          4m21s
aks-secrets-store-provider-azure-6pqmv   1/1     Running   0          4m24s
aks-secrets-store-provider-azure-f5qlm   1/1     Running   0          4m25s
```

### Create a SecretProviderClass to Mount Secret
The `SecretProviderClass` is a set of instructions - it providers the Kubernetes Cluster all the details it needs to access the secret. If the CSI Driver and Azure Vault Provider are the equipment, the ProviderClass is the set of instructions to execute. 
Let's use the [SecretProviderClass.yaml](/part_2/aks/SecretProviderClass.yaml)
Also see examples [here](https://secrets-store-csi-driver.sigs.k8s.io/topics/sync-as-kubernetes-secret.html)
There are a number of fields we will need to update and pay attention to here, so lets go through them.  The following list is comprehensive - the short of this step is **where do we retrieve the secret, what secret do we retrieve, what user are we using to retrieve it, and once we have retrieved the secret, what do we DO with it**. 
  1. With no namespace defined in `metadata`, this will be default. If you have a `prefect` namespace, SPC.yaml should specify this namespace.  
  2. `clientID` - This should be the clientID of the managed identity. It looks like `123acde-60e6-4cb7-9c8f-abc9abc9ab9c`  
  3. `keyvaultName` - This is the literal name of your Azure Keyvault containing the secrets.   
  4. `objects` - contains an array of objects, where each object is something to retrieve from the keyvault.   
     1. The `objectName` is the literal name of the object as it appears in Keyvault.   
     2. The `objectType` is either `key`, `secret`, or `certificate`. `secret` is what we use for string type values.  
     3. The `objectAlias` is an arbitrary name we assign to reference in the Deployment and Pod spec to reference this secret.  
  5. The `tenantId` can be found on the Keyvault page - it's the tenantId that hosts the Keyvault. Use `JSON View` or retrieve via: `az keyvault show --name <VAULT NAME> --query "properties.tenantId" --output tsv`
  6. `usePodIdentity` and `useVMManagedIdentity` should both be false. We are using `Workload Identity` which is determined based on the provided `clientId` in step 2.  
  7. The `provider` is azure - A secret provider class can reference many different vaults so here we specify this is an Azure one.  
  8. The `SecretObjects` line - while the `object` section defines _what_ to retrieve, the `SecretObjects` tells Kubernetes how and where to create it as a secret.   
        1. Recall a kubernetes `secret` has the following properties: a `name`, a `key`, and a `value`.   
        2. The `key` will be how the `value` is accessed in the secret.  
        3. The `objectName` is a **REFERENCE** to the `objectAlias`. Here we are saying the secret that is being created in Kubernetes is coming from the `objectAlias` as a source.  
        4. The `secretName` is simply the name you wish to save your secret as.  
        5. Type is always `opaque` - each secret can have different types.  

### Updating the Prefect Work-Pool
Almost all of the steps until now were focused on the infrastructure to enable and configure managed identity. Now we need to instruct Prefect how to use this. Because the secrets provider class creates a `secret` for us in the cluster, we can use that inside the pod. The Pod definition for prefect originates from the Job spec, which in turn is defined in the `work-pool`.  
See [this](/part_2/aks/advanced_workpool.yaml) advanced workpool configuration for a complete example, but we will highlight the necessary changes below.  
We will use dot (.) notation to reference structure so `.spec` references the `spec` object, while `.spec.volumes` indicates that volumes is an attribute of `.spec`.  
* Add a Secret Volume at `.spec.volumes` - see the full `csi` section
* Add a volumeMount at `.spec.containers.[0].volumeMounts` to mount the secret volume to `/mnt/secrets-store`  
* Expose the cluster secret as an environment variable in the spec   
* Update the service account to one with the Managed Identity.  
```yaml
        "spec": {
            "volumes": [
              {
                "name": "workdir",
                "emptyDir": {}
              },
              {
                "csi:": {
                  "driver": "secrets-store.csi.k8s.io",
                  "readOnly": "true",
                  "volumeAttributes": {
                    "secretProviderClass": "azure-sync"
                  }
                },
                "name": "secrets-store01-inline"
              }
            ],
            "containers": [
              {
                "env": [
                  {
                    "name": "SECRET_USERNAME",
                    "valueFrom": {
                      "secretKeyRef": {
                        "name": "<SECRET NAME FROM PROVIDER CLASS>",
                        "key": "<SECRET KEY FROM PROVIDER CLASS>"
                      }
                    }
                  }
                ],
                "args": "{{ command }}",
                "name": "prefect-job",
                "image": "{{ image }}",
                "volumeMounts": [
                  {
                    "name": "workdir",
                    "mountPath": "/opt/prefect/flows"
                  },
                  {
                    "name": "secrets-store01-inline",
                    "mountPath": "/mnt/secrets-store/"
                  }
                ],
                "imagePullPolicy": "{{ image_pull_policy }}"
              }
            ],
            ...snipped...
            "serviceAccountName": "workload-identity-sa"
          }
        },
```

### Assigning Roles / Permissions to new Service Account
:exclamation: - If you created a NEW service account and added the managed identity label, it will not have all the same permissions that your existing `prefect-<worker|agent>` service account has.   
You can add these permissions to the new service account by modifying the rolebinding which ties the permissions from the role, to the service account:
```sh
# Get name of the role-binding
 $ k get RoleBinding
NAME             ROLE                  AGE
prefect-worker   Role/prefect-worker   70d

# Edit the existing role-binding to include the new service account
 $ k edit rolebinding prefect-worker
```

The updated rolebinding should have two subjects, and appear like:
```yaml
subjects:
- kind: ServiceAccount
  name: prefect-worker
  namespace: default
- kind: ServiceAccount
  name: workload-identity-sa
  namespace: default
 ```

 ### Verifying Configuration
 This section is just intended to re-capture the number of steps along the way.
 We have:
   1. Created / Updated a K8s cluster with necessary add-ons
   2. Created a Managed Identity
   3. Created a Service Account
   4. Installed the CSI Secrets Driver
   5. Federated the Identity <-> Service Account
   6. Assigned Permissions (like KeyVault) to the Managed Identity
   7. Created a SecretProviderClass
   8. Updating RoleBinding to include Service Account
   9. Updated Prefect Kubernetes Work-Pool adding sections for `Env`, `Volumes`, `VolumeMount` and `ServiceAccountName`


<!-- Setting up workers on AKS --> 

# Setting up workers on AKS

### Deploy the [prefect worker helm chart](https://github.com/PrefectHQ/prefect-helm)

:exclamation: - By default, recall that each helm chart will create a service account named based on the `nameOverride`. It is necessary to either include the identity annotation, **or** update the work-pools to use the existing service account, **or** update the helm chart to use the existing service account. 
```sh
helm repo add prefect https://prefecthq.github.io/prefect-helm
helm search repo prefect
helm install {release-name} prefect/prefect-worker
```

To pass in specific values such as workpool during the install step create a `values.yaml` file: [Example1](/part_2/aks/override1.yaml) and [Example2](/part_2/aks/override2.yaml)

```bash
# Install with override1
helm install {release-name} prefect/prefect-worker -f override1.yaml  
# Install a second worker with override2
helm install {release-name} prefect/prefect-worker -f override2.yaml  
```

After running this step, a worker pod should spin up in your kubernetes cluster and a worker should spin up in the cloud ui. As a quick check, run these commands to grab the pod name and check its status. It should be in a running state.   
**If you input a name override in the values.yaml search for that name, instead of worker.**

```bash
kubectl get pods --all-namespaces | grep worker
kubectl describe pod {name of worker pod}
```

### Creating a Prefect Deployment
Included in this repo is a basic `prefect.yaml` that contains a `git_clone_step` using an environment variable.  [Recall](https://confluence.atlassian.com/bitbucketserver/personal-access-tokens-939515499.html) a `bitbucket_token` takes either the form `<username>:<personal access token>` **OR** `x-token-auth:<repo access token>`. Your secret should be stored as such in the Keyvault.
The main usage is like:
```yaml
- prefect.deployments.steps.git_clone:
    repository: https://github.com/chrisaboyd/Samples.git
    branch: main
    access_token: '{{ $BITBUCKET_TOKEN }}'
```

Some additional configuration examples for reference of usage:
```yaml
- prefect.deployments.steps.run_shell_script:
    id: test
    script: echo '{{ $BITBUCKET_TOKEN }}'
    stream_output: true
- prefect.deployments.steps.git_clone:
    repository: https://github.com/chrisaboyd/Samples.git
    branch: main
    access_token: '{{ test.stdout }}'
```
and:  
```yaml
- prefect.deployments.steps.run_shell_script:
    id: test
    script: cat /mnt/secrets-store/BITBUCKET_TOKEN # This is how the secret is mounted in container
    stream_output: false
- prefect.deployments.steps.git_clone:
    repository: https://github.com/chrisaboyd/Samples.git
    branch: main
    access_token: '{{ test.stdout }}'
```


<!-- Additional resources -->
# Additional resources  
- [Deployments](https://docs.prefect.io/latest/concepts/deployments/)  
- [Projects](https://docs.prefect.io/latest/concepts/projects/)  
- [Workers & Workpools](https://docs.prefect.io/latest/concepts/work-pools/)
- [Workload Identity Overview](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
- [CSI Secrets](https://secrets-store-csi-driver.sigs.k8s.io/introduction.html)
- [CSI Identity Access](https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-identity-access)
- [Azure Vault Provider](https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver)
- [AKS Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster)
- [Update an AKS Cluster](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster#update-an-existing-aks-cluster)
- [Bitbucket Private Repo Access](https://confluence.atlassian.com/bitbucketserver/personal-access-tokens-939515499.html)
