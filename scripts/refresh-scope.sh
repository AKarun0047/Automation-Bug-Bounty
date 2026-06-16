#!/usr/bin/env bash
# Refresh scope.txt files from Bugcrowd / HackerOne APIs.
# Run weekly — program scopes change.
set -euo pipefail

BUGBOUNTY_ROOT="${BUGBOUNTY_ROOT:-$HOME/bugbounty}"
PROGRAMS_DIR="$BUGBOUNTY_ROOT/programs"

echo "==> Scope refresh for programs in $PROGRAMS_DIR"

# --- Bugcrowd via bbscope ---
# Install: go install github.com/sw33tLie/bbscope@latest
if command -v bbscope &>/dev/null && [[ -n "${BUGCROWD_TOKEN:-}" ]]; then
  for dir in "$PROGRAMS_DIR"/*/; do
    name=$(basename "$dir")
    platform=$(grep -E '^platform:' "$dir/program.yaml" 2>/dev/null | awk '{print $2}' || true)
    if [[ "$platform" == "bugcrowd" ]]; then
      echo "  bbscope: $name"
      bbscope bc -t "$BUGCROWD_TOKEN" -p "$name" -b -o tsv 2>/dev/null \
        | awk -F'\t' '$2=="URL" || $2=="DOMAIN" {print $3}' \
        | sort -u > "$dir/scope.txt" || echo "    (bbscope failed for $name)"
    fi
  done
else
  echo "  skip bbscope — set BUGCROWD_TOKEN and install bbscope"
fi

# --- HackerOne via API ---
# Token: https://hackerone.com/settings/api_token/edit
if [[ -n "${HACKERONE_TOKEN:-}" ]]; then
  for dir in "$PROGRAMS_DIR"/*/; do
    name=$(basename "$dir")
    platform=$(grep -E '^platform:' "$dir/program.yaml" 2>/dev/null | awk '{print $2}' || true)
    if [[ "$platform" == "hackerone" ]]; then
      handle=$(grep -E '^h1_handle:' "$dir/program.yaml" 2>/dev/null | awk '{print $2}' || echo "$name")
      echo "  hackerone: $handle"
      curl -s -u "$HACKERONE_TOKEN:" \
        "https://api.hackerone.com/v1/hackers/programs/${handle}/structured_scopes" \
        | python3 -c "
import json, sys
data = json.load(sys.stdin)
for s in data.get('data', []):
    a = s.get('attributes', {})
    if a.get('eligible_for_submission') and a.get('asset_type') in ('URL', 'DOMAIN'):
        print(a.get('asset_identifier', '').replace('https://','').replace('http://','').split('/')[0])
" | sort -u > "$dir/scope.txt" || echo "    (H1 API failed for $handle)"
    fi
  done
else
  echo "  skip HackerOne — set HACKERONE_TOKEN"
fi

echo "Done. Review scope.txt diffs before running recon."
