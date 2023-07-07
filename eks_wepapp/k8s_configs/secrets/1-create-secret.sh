#!/bin/bash

#Setup env vars
REGION=us-east-1
CLUSTERNAME=cam-eks-dev

# Create a secret named MySecret with profile Cisco credentials
aws --region "$REGION" secretsmanager  create-secret --name MySecret --secret-string '{"username":"memeuser", "password":"hunter2"}' --profile cisco
