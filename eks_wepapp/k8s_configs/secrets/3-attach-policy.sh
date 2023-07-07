# Either create a service account with the policy attached, or update an existing service account with the new policy

#Create New
eksctl create iamserviceaccount --name nginx-deployment-sa --region="$REGION" --cluster "$CLUSTERNAME" --attach-policy-arn "$POLICY_ARN" --approve --override-existing-serviceaccounts


##OR

#Policy was the one we created in 2-create-policy.sh
#Update existing role 
aws iam attach-role-policy --role-name my-role --policy-arn="$POLICY_ARN"
