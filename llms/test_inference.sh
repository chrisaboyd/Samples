#!/usr/bin/env bash
#
# test_inference.sh - smoke-test the (public) vLLM inference endpoint for a
# Poolside reference deployment.
#
# Each model is served OpenAI-compatible at:
#   https://<model-key>.<inference_domain>/v1
# and may or may not require an API key. To keep this runnable "blindly":
#
#   1. AUTH PROBE  - we first hit GET /v1/models with NO credentials. If the
#      endpoint answers 200, it is open and we never touch a key.
#   2. KEY RESOLUTION - if the probe says auth is required (401/403), we prompt
#      you to pick a source, in this order of preference:
#        a. one of the "Poolside" config blocks declared in ~/.env
#           (which carry their own base URL *and* api key), or
#        b. paste an api key directly at the prompt, or
#        c. fetch the key from AWS Secrets Manager
#      If none of the above yields a key (non-interactive shell, EOF, or every
#      lookup failing), the FINAL fallback is Secrets Manager; if that also
#      fails the script exits non-zero.
#
# Your ~/.env may define several Poolside blocks (each introduced by a `#`
# comment header). Duplicate keys (e.g. POOLSIDE_API_KEY appearing in more than
# one block) are disambiguated by section, so each block is offered as a
# distinct choice. Exporting API_KEY before running skips the probe entirely.
#
# Requirements: aws-cli, curl, jq.
#
# Usage:
#   ./test_inference.sh             # default: `models`
#   ./test_inference.sh models      # GET  /v1/models            (lightweight)
#   ./test_inference.sh chat        # POST /v1/chat/completions  (full round-trip)
#   ./test_inference.sh health      # GET  /health               (ALB healthcheck)
#
# Overridable settings (export these to target a different env):
#   AWS_REGION, INFERENCE_DOMAIN, MODEL_KEY, API_KEY_SECRET_NAME
#
# Auto-detected settings (read from ~/.env when auth is required):
#   POOLSIDE_API_KEY, POOLSIDE_API_KEY_SANDBOX, POOLSIDE_BASE_URL{,
#   _SANDBOX, _STANDALONE}, POOLSIDE_STANDALONE_MODEL
#

set -euo pipefail

# ----------------------------------------------------------------------------
# Configuration for THIS deployment. Defaults match the current tfstate outputs;
# override via environment variables if needed.
# ----------------------------------------------------------------------------
AWS_REGION="${AWS_REGION:-us-east-2}"
INFERENCE_DOMAIN="${INFERENCE_DOMAIN:-boyd.demo.poolsi.de}"
MODEL_KEY="${MODEL_KEY:-laguna-s}"
# Secrets Manager secret WHOSE VALUE is the inference API key (plain string).
# This is an identifier only, NOT the key value. The ARN is the most robust
# form for `--secret-id`; the bare name also works. Note: AWS appends a 6-char
# suffix to the ARN's secret segment (`-3zAKYk`), but the secret's canonical
# Name is the suffix-free form. Using the full ARN avoids that mismatch.
API_KEY_SECRET_NAME="${API_KEY_SECRET_NAME:-arn:aws:secretsmanager:us-east-2:992382466748:secret:poolside-boyd-ref0730-inference-api-key-3zAKYk}"

# Derived default URLs. A selected ~/.env config may override these (it brings
# its own base URL) by re-deriving them through normalize_base_url_from().
BASE_URL="https://${MODEL_KEY}.${INFERENCE_DOMAIN}/v1"
HEALTH_URL="https://${MODEL_KEY}.${INFERENCE_DOMAIN}/health"

# Resolved at runtime: empty means "no auth (open endpoint)". Honouring an
# inherited API_KEY lets a caller skip the probe entirely.
API_KEY="${API_KEY:-}"
# curl args carrying the bearer header; rebuilt by build_auth_header(). Empty
# when no key is in play so requests stay unauthenticated.
AUTH_ARGS=()

# Parallel arrays describing each Poolside config block found in ~/.env. Kept in
# lockstep (no associative arrays, so this runs on bash 3.2 / macOS default).
CFG_LABEL=()
CFG_BASE=()
CFG_KEY=()

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# Pull the API key out of Secrets Manager into a local var. The value is never
# echoed, logged, or written to history beyond whatever your shell records.
fetch_api_key() {
  aws secretsmanager get-secret-value \
    --region "$AWS_REGION" \
    --secret-id "$API_KEY_SECRET_NAME" \
    --query SecretString \
    --output text
}

usage() {
  cat <<EOF
Usage: $0 {models|chat|health}

  models   GET  /v1/models            List served models (lightweight; good first check).
  chat     POST /v1/chat/completions  Send a tiny completion request end-to-end.
  health   GET  /health               ALB healthcheck path (unauthenticated).

Override defaults with env: AWS_REGION INFERENCE_DOMAIN MODEL_KEY API_KEY_SECRET_NAME
Provide a key explicitly with env: API_KEY
Pull a key from ~/.env Poolside blocks at runtime (when auth is required).
EOF
}

# Rewrite BASE_URL / HEALTH_URL from a config's base URL, tolerating a trailing
# "/v1" (some of your ~/.env values include it, some do not) and any trailing
# slash.
normalize_base_url_from() {
  local u="$1" origin
  origin="$u"
  [[ "$origin" == */v1 ]] && origin="${origin%/v1}"
  origin="${origin%/}"
  BASE_URL="${origin}/v1"
  HEALTH_URL="${origin}/health"
}

# Emit ~/.env "Poolside" config blocks as TSV: name \t base \t key \t model.
# Blocks are delimited by '#' comment headers; only sections that carry BOTH a
# base URL and an api key are emitted (a partial block is not a usable config).
list_poolside_env_configs() {
  [[ -f "${HOME}/.env" ]] || return 0
  awk '
    BEGIN { name=""; base=""; key=""; model="" }
    # A comment line starts a new section; flush the previous one first.
    /^[[:space:]]*#/ {
      if (name != "" && base != "" && key != "")
        printf "%s\t%s\t%s\t%s\n", name, base, key, model
      line = substr($0, 2)
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      if (line != "") name = line
      base=""; key=""; model=""
      next
    }
    /^[[:space:]]*$/ { next }
    {
      line = $0
      sub(/^[[:space:]]*export[[:space:]]+/, "", line)
      eq = index(line, "=")
      if (eq == 0) next
      var = substr(line, 1, eq - 1)
      val = substr(line, eq + 1)
      sub(/[[:space:]]+$/, "", val)
      gsub(/^"|"$/, "", val)
      if      (var == "POOLSIDE_API_KEY" || var == "POOLSIDE_API_KEY_SANDBOX") key = val
      else if (var == "POOLSIDE_BASE_URL" || var == "POOLSIDE_BASE_URL_SANDBOX" || var == "POOLSIDE_STANDALONE_BASE_URL") base = val
      else if (var == "POOLSIDE_STANDALONE_MODEL") model = val
    }
    END {
      if (name != "" && base != "" && key != "")
        printf "%s\t%s\t%s\t%s\n", name, base, key, model
    }
  ' "${HOME}/.env"
}

# Populate CFG_* in lockstep from ~/.env.
load_poolside_env_configs() {
  CFG_LABEL=(); CFG_BASE=(); CFG_KEY=()
  local name base key model origin label
  while IFS=$'\t' read -r name base key model; do
    [[ -z "$name" ]] && continue
    origin="$base"; [[ "$origin" == */v1 ]] && origin="${origin%/v1}"
    origin="${origin%/}"
    label="$name"
    [[ -n "$origin" ]] && label+="  (${origin})"
    [[ -n "$model" ]] && label+="  [${model}]"
    CFG_LABEL+=("$label")
    CFG_BASE+=("$base")
    CFG_KEY+=("$key")
  done < <(list_poolside_env_configs)
}

# Fill AUTH_ARGS with the bearer header iff a key is present.
build_auth_header() {
  AUTH_ARGS=()
  if [[ -n "${API_KEY:-}" ]]; then
    AUTH_ARGS=(-H "Authorization: Bearer ${API_KEY}")
  fi
}

# Read the key from Secrets Manager; return non-zero on any failure.
resolve_api_key_from_secrets_manager() {
  echo "-> Fetching API key from Secrets Manager (${AWS_REGION})..."
  local val
  if ! val="$(fetch_api_key 2>/dev/null)"; then
    echo "!! Failed to read secret '${API_KEY_SECRET_NAME}' from Secrets Manager in ${AWS_REGION}." >&2
    return 1
  fi
  if [[ -z "$val" || "$val" == "None" ]]; then
    echo "!! Secrets Manager returned an empty value." >&2
    return 1
  fi
  API_KEY="$val"
  export API_KEY
  return 0
}

# Apply a selected ~/.env config (by index): switch the endpoint and set the
# key. The endpoint is NOT re-probed; the config is presumed to be a real,
# auth-gated deployment whose bundled key applies.
apply_env_config() {
  local idx="$1"
  local base="${CFG_BASE[$idx]}"
  local key="${CFG_KEY[$idx]}"
  local label="${CFG_LABEL[$idx]}"
  normalize_base_url_from "$base"
  if [[ -n "$key" ]]; then
    API_KEY="$key"
    export API_KEY
    echo "-> Selected '${label}' -> ${BASE_URL} (api key provided)."
  else
    echo "-> Selected '${label}' -> ${BASE_URL} (this config has no api key)."
  fi
}

# Present an interactive menu for the API key source: a ~/.env Poolside config
# block, a pasted key, or Secrets Manager. Returns 0 with API_KEY set (and
# possibly a new BASE_URL); 1 if nothing resolves. `select` re-prompts on bad
# input, and an EOF (Ctrl-D / non-interactive stdin) drops through to the
# Secrets Manager final fallback, then fails.
prompt_for_api_key() {
  load_poolside_env_configs

  local -a opts=()
  local i opt k
  for i in "${!CFG_LABEL[@]}"; do
    opts+=("${CFG_LABEL[$i]}")
  done
  opts+=("Paste an API key directly")
  opts+=("Resolve from AWS Secrets Manager")

  if [[ ${#CFG_LABEL[@]} -eq 0 ]]; then
    echo "-> No Poolside configs were found in ~/.env."
  fi

  echo
  echo "Choose an API key source (Ctrl-D = Secrets Manager final fallback, then fail):"
  PS3="  select> "
  select opt in "${opts[@]}"; do
    if [[ -n "$opt" ]]; then
      case "$opt" in
        "Paste an API key directly")
          read -rsp "  API key (hidden): " k || k=""
          echo
          if [[ -n "$k" ]]; then
            API_KEY="$k"; export API_KEY
            return 0
          fi
          echo "  (empty) try again, or pick another option."
          ;;
        "Resolve from AWS Secrets Manager")
          if resolve_api_key_from_secrets_manager; then return 0; fi
          echo "  Secrets Manager lookup failed; try another option."
          ;;
        *)
          # A ~/.env config label was chosen.
          for i in "${!CFG_LABEL[@]}"; do
            if [[ "${CFG_LABEL[$i]}" == "$opt" ]]; then
              apply_env_config "$i"
              if [[ -n "${API_KEY:-}" ]]; then return 0; fi
              echo "  (this config has no api key) try another option."
              break
            fi
          done
          ;;
      esac
    else
      # EOF / no selection -> final fallback.
      break
    fi
  done

  # Reached via EOF (Ctrl-D) or non-interactive stdin.
  echo "-> Final fallback: resolving key from AWS Secrets Manager..."
  if resolve_api_key_from_secrets_manager; then return 0; fi
  echo "!! Could not resolve an API key; aborting." >&2
  return 1
}

# Decide whether BASE_URL needs auth. Probes GET /v1/models unauthenticated:
# 200 -> open, no key needed; anything else -> auth/unreachable, so we resolve
# a key (possibly switching BASE_URL via a ~/.env config). Exits non-zero if no
# key can be resolved.
ensure_api_key() {
  # Explicit key in the environment wins instantly (no probe).
  if [[ -n "${API_KEY:-}" ]]; then
    echo "-> Using API_KEY from environment."
    return 0
  fi

  # Quick unauthenticated probe: does the endpoint require auth?
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
            -H "Accept: application/json" \
            "${BASE_URL}/models" 2>/dev/null || true)"

  case "$code" in
    200)
      echo "-> ${BASE_URL}/models is open (no auth required)."
      API_KEY=""
      return 0
      ;;
    401|403)
      echo "-> ${BASE_URL}/models requires authentication (HTTP ${code})."
      ;;
    000|"")
      echo "-> ${BASE_URL}/models did not respond (unreachable?)."
      ;;
    *)
      echo "-> ${BASE_URL}/models returned HTTP ${code}."
      ;;
  esac

  # Auth is required (or the endpoint is unreachable): resolve a key. If we
  # can't, fail loudly.
  if ! prompt_for_api_key; then
    echo "!! No API key could be resolved; aborting." >&2
    exit 1
  fi
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

ACTION="${1:-models}"

case "$ACTION" in

  models)
    ensure_api_key
    build_auth_header
    echo "-> Listing models at ${BASE_URL}/models ..."
    # The trailing pipe+jq will exit non-zero if the body isn't JSON, which
    # (with set -e + pipefail) fails the script loudly on a bad/empty response.
    curl -fsSL \
      "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
      -H "Accept: application/json" \
      "${BASE_URL}/models" \
      | jq .
    ;;
  chat)
    ensure_api_key
    build_auth_header
    echo "-> Discovering served model id at ${BASE_URL}/models ..."
    MODEL_ID="$(curl -fsSL \
      "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
      -H "Accept: application/json" \
      "${BASE_URL}/models" | jq -r '.data[0].id')"
    if [[ -z "$MODEL_ID" || "$MODEL_ID" == "null" ]]; then
      echo "!! /v1/models returned no models; nothing to chat with." >&2
      exit 1
    fi
    echo "-> Sending chat completion to ${BASE_URL}/chat/completions (model: ${MODEL_ID}) ..."
    curl -fsSL \
      "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
      -H "Content-Type: application/json" \
      -d '{
        "model": "'"${MODEL_ID}"'",
        "messages": [{"role": "user", "content": "Say hello in one sentence."}],
        "max_tokens": 32
      }' \
      "${BASE_URL}/chat/completions" \
      | jq .
    ;;

  health)
    echo "-> Checking ALB health at ${HEALTH_URL} ..."
    # /health is the ALB healthcheck path (see helm values
    # alb.ingress.kubernetes.io/healthcheck-path). The ALB probes it without a
    # bearer token, so this call is intentionally unauthenticated. The endpoint
    # returns 200 with an empty body, so we report status + size instead of
    # assuming a JSON payload.
    http_code="$(curl -sS -o /tmp/h.txt -w '%{http_code}' "${HEALTH_URL}")"
    size="$(wc -c < /tmp/h.txt | tr -d ' ')"
    rm -f /tmp/h.txt
    if [[ "$http_code" == "200" ]]; then
      echo "OK: ${HEALTH_URL} -> HTTP ${http_code} (${size} bytes)"
    else
      echo "!! ${HEALTH_URL} -> HTTP ${http_code} (${size} bytes)" >&2
      exit 1
    fi
    ;;

  *)
    usage
    exit 2
    ;;

esac
