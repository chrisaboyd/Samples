# Create the policy named "eks-cluster-secrets" on secret created from 1-create-secret.sh

POLICY_ARN=$(aws --profile cisco --region "$REGION" --query Policy.Arn --output text iam create-policy --policy-name eks-cluster-secrets --policy-document '{
    "Version": "2012-10-17",
    "Statement": [ {
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
        "Resource": ["arn:*:secretsmanager:*:*:prd_cps_dsci_etl_svc_cloud_conn_str-VajChn"]
    } ]
}')
