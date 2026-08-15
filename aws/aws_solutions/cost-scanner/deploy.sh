#!/usr/bin/env bash
#
# Deploy the daily cost-scanner Lambda into the sandbox account.
#
# Requirements: aws-cli v2, zip, jq (optional), and write access to an S3
# bucket in the target account (used by `cloudformation deploy` to stage the
# packaged Lambda zip).  No SAM CLI is required.
#
# Usage:
#   SLACK_WEBHOOK_URL=https://hooks.slack.com/... ./deploy.sh \
#       --bucket my-sandbox-deploy-bucket --stack cost-scanner-lambda
#
#   # or be prompted for the webhook (it stays out of your shell history):
#   ./deploy.sh --bucket my-sandbox-deploy-bucket
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

##################### defaults #####################
BUCKET=""
STACK_NAME="cost-scanner-lambda"
REGION="${AWS_DEFAULT_REGION:-us-east-2}"
PROFILE="${AWS_PROFILE:-sandbox}"
WEBHOOK="${SLACK_WEBHOOK_URL:-}"
ENABLE_CE="${ENABLE_CE:-1}"
SCHEDULE="${SCHEDULE:-cron(0 12 * * ? *)}"   # daily 12:00 UTC
SCHEDULE_ENABLED="${SCHEDULE_ENABLED:-true}"

usage() {
  sed -n 's/^#//p' "$0" | sed -n '1,20p'
  echo
  echo "Options: --bucket BUCKET --stack NAME --region R --profile P --schedule CRON --no-schedule --no-ce"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bucket) BUCKET="$2"; shift 2;;
    --stack)  STACK_NAME="$2"; shift 2;;
    --region) REGION="$2"; shift 2;;
    --profile) PROFILE="$2"; shift 2;;
    --schedule) SCHEDULE="$2"; shift 2;;
    --no-schedule) SCHEDULE_ENABLED="false"; shift;;
    --no-ce) ENABLE_CE="0"; shift;;
    -h|--help) usage;;
    *) echo "unknown option: $1"; usage;;
  esac
done

if [[ -z "$BUCKET" ]]; then
  echo "ERROR: --bucket <s3-bucket> is required (used to stage the lambda zip)" >&2
  exit 2
fi

if [[ -z "$WEBHOOK" ]]; then
  read -r -p "Slack incoming-webhook URL (will be NoEcho'd into the stack): " WEBHOOK
fi
if [[ -z "$WEBHOOK" ]]; then
  echo "ERROR: a SlackWebhookUrl is required (pass via SLACK_WEBHOOK_URL or prompt)" >&2
  exit 2
fi

echo "==> Profile: $PROFILE  Region: $REGION  Bucket: $BUCKET  Stack: $STACK_NAME"

##################### build the lambda zip #####################
ZIP="$SCRIPT_DIR/cost-scanner-lambda.zip"
rm -f "$ZIP"
# Include ONLY what the Lambda needs: app.py + the cost_scanner package.
( cd "$SCRIPT_DIR" && zip -q -r "$ZIP" app.py cost_scanner/ )
echo "==> Built $ZIP ($(du -h "$ZIP" | cut -f1))"

##################### deploy #####################
echo "==> Deploying stack..."
aws cloudformation deploy \
  --profile "$PROFILE" \
  --region "$REGION" \
  --template-file "$SCRIPT_DIR/template.yaml" \
  --stack-name "$STACK_NAME" \
  --s3-bucket "$BUCKET" \
  --capabilities CAPABILITY_IAM CAPABILITY_AUTOEXPAND \
  --parameter-overrides \
    SlackWebhookUrl="$WEBHOOK" \
    Profile="$PROFILE" \
    EnableCostExplorer="$ENABLE_CE" \
    ScheduleExpression="$SCHEDULE" \
    ScheduleEnabled="$SCHEDULE_ENABLED"

echo "==> Done. The Lambda runs every morning at the schedule and posts to Slack."
echo "==> Run it on demand:  aws lambda invoke --function-name $STACK_NAME /tmp/out.json --profile $PROFILE --region $REGION"
