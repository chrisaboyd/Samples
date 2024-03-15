### Create a .pass and .user local file for configuring ACI credentials
```bash
# Create the file
touch .pass
touch .user

#Update the contents
vim .pass
this_is_my_docker_password

vim .user
this_is_my_docker_username
```

### Create a Prefect Work-Pool using Prefect CLI or UI
```bash
# This will create a work-pool named aci-test of type azure-container-instance
prefect work-pool create -t azure-container-instance aci-test
```

### Update the Worker Pool
    - (Required) Update the Subscription ID
    - (Required) Update the Resource Group Name, otherwise there will be insufficient scope to execute over in Azure.
    - (Optional) If it's a Private Image, attach a Docker Registry Credentials Block


### Create a Resource group:
```bash
az group create --name "rg_name_here" --location eastus
```

### Edit create_container.sh and update the necessary values to deploy:
```bash
rg=BoydACIPrefectAgent
container_name="prefect-aci-worker"
image='index.docker.io/chaboy/private_test:latest'
registry_server='index.docker.io'
```

### Execute create_container.sh:
```bash
./create_container.sh
```

### Deploy Code
    - Create a Deployment (To run flow code stored in the docker image)
    - Create a Project (To pull flow code from a code repository into a container at execution time)


## Build an Image Containing Flow Code
Flow code, Dockerfile, and deployment.py are included to follow along with.

```bash
export image_tag="your repo/image:tag"
#e.g. export image_tag="chaboy/private_test:latest"
docker build --platform linux/amd64 -t $image_tag .

#Push to registry:
docker push $image_tag
```

### Deploy / Apply a Deployment
A sample deployment is provided for this tutorial.  
This includes an (optional) infra_overrides, that you can use to customize the infrastructure values, such as image, memory, cpu, etc. 
```bash
python deployment.py
```

### Create an Azure Blob Credentials block 
This is the credentials block we will load from the transform_flow.py.
If this does not exist, the flow will fail as credentials could not be loaded.

### Run the Deployment from UI
As the ACI Worker is already running at this point, you should see a new Flow-Run in Scheduled, then Pending state.
Scheduled means a Flow Run has been created.
Pending means that it has been received by the worker, and infrastructure is being provisioned.
At this point it will transition into a few states - `Running`, `Failed`, or `Crashed`.
`Running` will occur if the worker is running, the code is available in the image, and there are no dependency issues.
`Crashed` will occur if there is an issue with provisioning - usually this is at the infrastructure level, and will not be available in Prefect logs - it would be necessary to review container / ACI logs.
`Failed` will occur if there is an issue with the code logic as it might fail running locally. This could be a missing dependency, or a misplaced comma.


### Run the Flow from UI

## Gotchas
    - Ensure .pass is set (for create_container.sh), and the correct path is used (your discretion)
    - Ensure .user is set,(for create_container.sh)  and the correct path is used (your discretion)
    - Ensure both PREFECT_API_KEY and PREFECT_API_URL are set - these are picked up from env variables for create_container.sh
    - Bitbucket requires a PAT token with the x-token-auth header- ensure this is accurately referenced in the prefect.yaml in the form `x-token-auth:<pat>`. Some various WORKING configurations are listed below.
    - Ensure a Azure Blob Storage Credentials block is created (for use in the flow)
    - Ensure a Docker Image Registry Block is created (otherwise a private image will fail to pull)
