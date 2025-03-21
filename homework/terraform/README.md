# AWS infrastructure as code

Directory to host AWS infrastructure as code

Create an AWS Profile:

```bash
aws configure
AWS Access Key ID [None]: ####
AWS Secret Access Key [None]: #######
Default region name [None]: us-east-1
Default output format [None]: json
❯ aws sts get-caller-identity

{
    "UserId": "AIDATUN3C3U4CEJF3TQIM",
    "Account": "######",
    "Arn": "arn:aws:iam::######:user/terraform-dev"
}
```

Navigate to ./vpc to deploy:
```bash
cd vpc
terraform init
terraform plan -out ps.out

Saved the plan to: ps.out

To perform exactly these actions, run the following command to apply:
    terraform apply "ps.out"

terraform apply "ps.out"
```