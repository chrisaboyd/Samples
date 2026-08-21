# AWS Cost Scanner

A small, dependency-free Python engine that scans an AWS account for the
resources **you** and the **Solutions Architect team** own, works out how
long each piece of always-on compute has been running, and estimates how
much money that has cost so far.

It was built for the `sandbox` account (`992382466748`, `us-east-2`) as you
(`chris.boyd@poolside.ai`, tagged `creator=boyd`) + the SA team (tagged
`team` = `sa` / `Solution Architects` / `solutions-architecture`), and
delivers a **daily morning report**.

> **Why two delivery paths?** An AWS Lambda *cannot* write to your local
> Obsidian vault. So the scanner has a shared core with **two front-ends**:
> a Lambda that posts to Slack (scheduled via EventBridge), and a local
> script that writes a dated Markdown report into your Obsidian vault
> (scheduled via macOS `launchd`). Pick one, or use both.

---

## What it scans & how it prices

**Discovery** — combines the Resource Groups Tagging API (to classify
*ownership*) with per-service describes (to get launch/creation timestamps,
which the tagging API doesn't expose):

| Service | "Owned by me" signal | "SA team" signal | Cost model |
|---|---|---|---|
| EC2 | `creator=boyd` (your short name) | `team=sa` | running instances: uptime × on-demand rate |
| RDS | same tags | same | `available` instances: uptime × on-demand rate |
| EKS | same tags | same | control-plane: uptime × $0.10/hr (your node cost is captured via EC2) |
| Lambda | same tags | same | count only (pay-per-invocation; not wall-clock) |
| everything else | same tags | same | counts by service (S3, ECR, KMS, …) |

**Rates** come from the **AWS Price List API** (`pricing.get_products`) in
the account's region, taking the minimum positive on-demand `Hrs` price
(the price list can return several offer variants per type; the smallest
is the standard on-demand rate). A small hardcoded **fallback table** is
used if a rate can't be resolved (e.g. API throttling), so the report never
shows a blank.

**Cost check** — a best-effort **Cost Explorer** call pulls actual
month-to-date spend for the whole account as a sanity cross-check (per-tag
breakdowns need *activated* cost-allocation tags; `creator`/`team` aren't
activated in this account, so that slice isn't available).

---

## Quick start (local → Obsidian) — works today, no cloud changes

```bash
cd aws_solutions/cost-scanner
AWS_PROFILE=sandbox python3 scan.py            # writes ~/Documents/Devault/AWS Sandbox Resource tracking/
AWS_PROFILE=sandbox python3 scan.py --print    # also print to stdout
```

This scans your sandbox account and writes a file like
`2026-08-15 AWS Cost Report.md` into `~/Documents/Devault/AWS Sandbox
Resource tracking/` (a new folder in your existing Obsidian vault).

### Run it every morning automatically (macOS `launchd`)

```bash
# 1. adjust the plist if your checkout path differs (it already matches yours)
cp com.poolside.cost-scanner.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.poolside.cost-scanner.plist
# verify:
launchctl list | grep cost-scanner
```

The agent runs `scan.py` at 08:00 every morning. Logs land at
`~/Library/Logs/cost-scanner.log`.

---

## AWS Lambda path (→ Slack, scheduled via EventBridge)

Use this instead of/in addition to the local script if you want the report
pushed to a Slack channel every morning from the cloud.

### 1. Get a Slack incoming webhook URL

In Slack: *Settings & admin → Manage apps → Custom Integrations → Incoming
Webhooks*, pick (or create) a channel and copy the webhook URL. It looks
like `https://hooks.slack.com/services/T000.../B000.../XXXX`.

### 2. Deploy

You need an S3 bucket in the sandbox account to stage the packaged Lambda
zip (e.g. `cost-scanner-deploy-992382466748`).

```bash
# either export it
export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'

# then deploy (no SAM CLI required):
cd aws_solutions/cost-scanner
./deploy.sh --bucket cost-scanner-deploy-992382466748
```

`deploy.sh` will prompt for the webhook if `SLACK_WEBHOOK_URL` isn't set,
build a tight zip (`app.py` + `cost_scanner/`), and run
`aws cloudformation deploy` with the SAM transform. The Lambda:

- runs in the sandbox account with an execution role scoped to read-only
  scanning (EC2/RDS/EKS/Lambda/Tagging/Pricing/CE/STS),
- is invoked every morning at 12:00 UTC by an EventBridge `cron` rule
  (8am EDT / 7am EST),
- posts the compact summary to Slack.

Run it on demand:
```bash
aws lambda invoke --function-name cost-scanner-lambda /tmp/out.json --profile sandbox
```

---

## Environment variables

Everything is optional except where noted. Defaults match the sandbox
account.

| Variable | Default | Purpose |
|---|---|---|
| `AWS_PROFILE` / `AWS_DEFAULT_REGION` | `sandbox` / `us-east-2` | Which account/region to scan (`scan.py` and Lambda exec role). |
| `OWNER_TAGS` | `creator,owner` | Tag *keys* that mark personal ownership. |
| `MY_OWNER_VALUES` | `boyd,chris.boyd@poolside.ai` | Tag values meaning "me". |
| `TEAM_TAG` | `team` | Tag *key* for team ownership. |
| `TEAM_OWNER_VALUES` | `sa,Solution Architects,solutions-architecture` | Team values meaning "Solutions Architect". |
| `ENABLE_CE` | `1` | Set `0` to skip the Cost-Explorer cross-check (faster). |
| `SLACK_WEBHOOK_URL` | *(none)* | Slack incoming-webhook URL. Required only if you want Slack. |
| `ScheduleExpression` (CFN) | `cron(0 12 * * ? *)` | EventBridge schedule (Lambda path). |

---

## Project layout

```
cost-scanner/
├── app.py                  # Lambda entry point  -> Slack (scheduled via EventBridge)
├── scan.py                 # Local CLI           -> Obsidian (+ optional Slack)
├── template.yaml           # CloudFormation (SAM transform) for the Lambda
├── deploy.sh               # Builds the zip + deploys the stack
├── com.poolside.cost-scanner.plist  # macOS launchd agent (local morning schedule)
├── requirements.txt        # only stdlib + boto3; `requests` optional
├── cost_scanner/           # the shared engine (no AWS credentials baked in)
│   ├── model.py            # dataclasses: Resource, Ec2Instance, RdsInstance, ...
│   ├── owner.py            # tag-based ownership classification
│   ├── discovery.py        # tagging API + EC2/RDS/EKS/Lambda describes
│   ├── rates.py            # Price List API + fallback rate table
│   ├── cost.py             # rollup into totals + burn rate + waste notes
│   ├── ce.py               # Cost Explorer actuals cross-check
│   ├── render.py           # Markdown (Obsidian) + Slack renderers
│   └── notify.py           # Slack webhook delivery (stdlib urllib)
└── README.md
```

## Notes / limitations

- **Stopped vs running:** a stopped EC2 instance stops accruing instance
  cost (EBS storage still bills — not modelled; the report notes stopped
  instances). A *stopped* RDS instance keeps accruing hourly RDS cost until
  it's deleted (the `Multi-AZ`/`Single-AZ` distinction is reflected).
- **EKS node cost** is captured through the underlying EC2 instances (which
  carry `eks:nodegroup-name` / `team` tags). The EKS *control plane*
  ($0.10/hr in us-east-2) is charged separately and always on.
- **Regions:** only the configured single region is scanned. For a
  multi-region scan, run once per region (or set `AWS_DEFAULT_REGION` and
  repeat).
- **Lambda is pay-per-invocation**, so it's counted but not wall-clock
  charged; the report only mentions its count.
