#!/usr/bin/env bash
# repo-exposure-check
# Reads the public file tree of a GitHub repository and flags paths whose
# names match patterns associated with secrets, credentials, keys, dumps,
# and sensitive config files.
# READS PATHS ONLY — never downloads or inspects file contents.
# MIT License — see LICENSE

set -euo pipefail

REPO="${1:-}"

if [[ -z "$REPO" ]]; then
  echo "Usage: $0 owner/repository" >&2
  exit 2
fi

API_BASE="https://api.github.com"
ACCEPT="Accept: application/vnd.github+json"

# ── 1. Resolve default branch ────────────────────────────────────────────────
REPO_META=$(curl -sf -H "$ACCEPT" "${API_BASE}/repos/${REPO}") || {
  echo "ERROR: Could not reach GitHub API for '${REPO}'. Check the repo name and your network." >&2
  exit 2
}

DEFAULT_BRANCH=$(printf '%s' "$REPO_META" | grep -o '"default_branch":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -z "$DEFAULT_BRANCH" ]]; then
  echo "ERROR: Could not determine default branch for '${REPO}'." >&2
  exit 2
fi

# ── 2. Resolve the SHA of the branch tip ────────────────────────────────────
BRANCH_DATA=$(curl -sf -H "$ACCEPT" \
  "${API_BASE}/repos/${REPO}/branches/${DEFAULT_BRANCH}") || {
  echo "ERROR: Could not fetch branch data for '${DEFAULT_BRANCH}'." >&2
  exit 2
}

SHA=$(printf '%s' "$BRANCH_DATA" | grep -o '"sha":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -z "$SHA" ]]; then
  echo "ERROR: Could not resolve commit SHA." >&2
  exit 2
fi

# ── 3. Fetch the full recursive tree ────────────────────────────────────────
TREE_DATA=$(curl -sf -H "$ACCEPT" \
  "${API_BASE}/repos/${REPO}/git/trees/${SHA}?recursive=1") || {
  echo "ERROR: Could not fetch tree for SHA '${SHA}'." >&2
  exit 2
}

# Extract all paths (type blob only) from the JSON
# Uses only bash built-ins after curl — no jq, no python
PATHS=$(printf '%s' "$TREE_DATA" \
  | grep -o '"path":"[^"]*"' \
  | cut -d'"' -f4)

TRUNCATED=$(printf '%s' "$TREE_DATA" | grep -o '"truncated":true' | head -1)
if [[ -n "$TRUNCATED" ]]; then
  echo "WARNING: GitHub truncated this tree (very large repo). Results may be incomplete." >&2
fi

# ── 4. Pattern matching and reporting ───────────────────────────────────────
FOUND=0

flag() {
  local path="$1"
  local reason="$2"
  if [[ "$FOUND" -eq 0 ]]; then
    echo ""
    printf "%-70s  %s\n" "PATH" "WHY IT MATTERS"
    printf '%0.s-' {1..110}
    echo ""
  fi
  printf "%-70s  %s\n" "$path" "$reason"
  FOUND=1
}

match_path() {
  local p="$1"
  local base
  base=$(basename "$p")
  local lower_base
  lower_base=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')
  local lower_p
  lower_p=$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')

  # ── Environment files ────────────────────────────────────────────────────
  case "$lower_base" in
    .env|.env.*|*.env)
      flag "$p" ".env files commonly hold API keys, DB passwords, and OAuth secrets in plain text." ; return ;;
  esac

  # ── Keys and certificates ────────────────────────────────────────────────
  case "$lower_base" in
    *.pem)
      flag "$p" "PEM file: may be a private key or certificate chain — private keys must never be committed." ; return ;;
    id_rsa|id_rsa.pub|id_dsa|id_ecdsa|id_ed25519)
      flag "$p" "SSH private (or public) key file — private keys give shell access to every server they are authorised on." ; return ;;
    id_rsa.*|id_dsa.*|id_ecdsa.*|id_ed25519.*)
      flag "$p" "SSH key file variant — check whether this is the private half." ; return ;;
    *.p12|*.pfx)
      flag "$p" "PKCS#12 bundle: bundles a private key with its certificate — exposure allows impersonation and decryption." ; return ;;
    *.jks)
      flag "$p" "Java KeyStore: often contains private keys and trusted certificates used by Java services." ; return ;;
    *.key)
      flag "$p" "Generic .key file — private keys for TLS, GPG, or API access are commonly named this way." ; return ;;
    *.ppk)
      flag "$p" "PuTTY private key file — equivalent exposure risk to id_rsa." ; return ;;
    *.keystore)
      flag "$p" "Keystore file: Android and Java apps store signing keys here; exposure allows APK signing forgery." ; return ;;
  esac

  # ── Credential-shaped names ──────────────────────────────────────────────
  case "$lower_base" in
    credentials.json|credentials.yml|credentials.yaml)
      flag "$p" "File explicitly named 'credentials' — cloud CLIs (AWS, GCP, Azure) write access keys here." ; return ;;
    serviceaccount*.json|service_account*.json)
      flag "$p" "GCP service account key: grants IAM-scoped API access; a leaked key does not expire until
