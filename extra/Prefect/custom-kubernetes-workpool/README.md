1. Get the base kubernetes manifest:

```
prefect work-pool get-default-base-job-template --type kubernetes > base-job-template.json

```

2. Update the base-job-template.json as  required

3. Create a secret if it doesnt already exist:

```
kubectl create secret generic prefect-api-key --from-literal=key=pnu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

4. Create values if they dont already exist:

```
worker:
  cloudApiConfig:
    accountId: "< Prefect Account ID>"
    workspaceId: "< Prefect Workspace ID>"
  config:
    workPool: "test-kube
```

5. Install the helm chart, specifying the values + custom manifest:

```
helm install prefect-work prefect/prefect-worker -f values.yaml --set-file worker.config.baseJobTemplate.configuration=base-job-template.json
```
