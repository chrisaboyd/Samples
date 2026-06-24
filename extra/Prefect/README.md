# Prefect Sidecar Logging


### Create a new logging.yml to add a file handler:
[logging.yml](/Prefect/logging.yml)


### Build the Image with the logging.yml
Unfortunately, we can't clone the `logging.yml` in at runtime, as the process would need to be restarted to pick up the new logging configuration. 
For this reason, this __must__ be added to a custom image.
[Dockerfile](/Prefect/Dockerfile)

```bash
FROM prefecthq/prefect:2-latest
COPY logging.yml /root/logging.yml
ENV PREFECT_LOGGING_SETTINGS_PATH=/root/logging.yml
```


### Build and push your image:

```shell
export image_tag="chaboy/prefect2:custom-logger"
docker build --platform linux/amd64 -t $image_tag .
docker push $image_tag
```

### Update the workpool configuration to use the new $image_tag.
![image](/Prefect/workpool_image.png)


### Add a Sidecar container Configuration to the Kubernetes Work-pool:
[Sidecar Workpool Configuration](/Prefect/sidecar_advanced_workpool.yaml)

Notably we are adding the following:


1. A volume to store logs 
`.spec.template.spec.volumes`:

```json
{
    "name": "logs",
    "emptyDir": {}
}
```

2. A volumeMount (for the new volume) to the existing Prefect container `.spec.template.spec.containers.[0].volumeMounts`:
   
```json
{
    "name": "logs",
    "mountPath": "/var/log/"
}
```

3. A new sidecar logging container `spec.template.spec.containers.[1]`:

```json
{
    "name": "log-shipper",
    "image": "busybox",
    "args": [
        "/bin/sh",
        "-c",
        "sleep 3 && tail -f /var/log/prefect.log"
    ],
    "volumeMounts": [
        {
            "name": "logs",
            "mountPath": "/var/log/"
        },
        {
            "name": "workdir",
            "mountPath": "/opt/prefect/flows"
        }
    ],
    "imagePullPolicy": "{{ image_pull_policy }}"
}
```


### Save the workpool and run the flow
![flowrun](/Prefect/flowrun.png)

### Shutdown sidecar container on flow exit
The sidecar will continue to `tail` prefect.log, even though the main container has exited. We need to introduce some additional clean-up to ensure the sidecar exits appropriately.
