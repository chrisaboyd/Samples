# Kubernetes Operators from Scratch


### Install the operator-sdk
```bash
brew install operator-sdk
```

### Pre-requisites
Kubernetes cluster (can be a local one like Minikube or Kind)
Go programming environment (most operators are written in Go)
Access to your Kubernetes API from your development environment


###  Create an operator project
```bash
operator-sdk init --domain=mydomain.com --repo=github.com/myrepo/myoperator
```


### Create your first controller and CRD

```bash
operator-sdk create api --group webapp --version v1 --kind MyApp
```

The controller is the core of your operator. It watches for changes to your CRD and other resources that interest you. The controller reacts by creating, updating, or deleting resources based on the desired state defined in the CRD.

### Test local against your cluster
```bash
make install run
```

Once you're satisfied with your operator, deploy it to a real cluster. You will need to build a container image for your operator, push it to a container registry, and then deploy it using Helm or a simple Kubernetes manifest.

https://sdk.operatorframework.io/docs/

### Resources:

* Examples - https://github.com/operator-framework/operator-sdk/tree/master/testdata  
* FAQ - https://sdk.operatorframework.io/docs/faqs/  
* Layout - https://sdk.operatorframework.io/docs/overview/project-layout/  
* Operator SDK - https://sdk.operatorframework.io/docs/overview/cheat-sheet/  
* Operator capabilities - https://sdk.operatorframework.io/docs/overview/operator-capabilities/
* Building with Helm - https://sdk.operatorframework.io/docs/building-operators/helm/
* Building with Go - https://sdk.operatorframework.io/docs/building-operators/golang/