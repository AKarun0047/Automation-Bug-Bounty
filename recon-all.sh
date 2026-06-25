#!/usr/bin/env bash
# recon-all.sh — Full bug bounty recon in one script (24/7 capable)
# Usage:
#   ./recon-all.sh target.com
#   ./recon-all.sh -f targets.txt
#   ./recon-all.sh --daemon -f targets.txt
#
# Output → ./output/<domain>/  (flat files for manual testing)

set -uo pipefail

OUTPUT_BASE="${OUTPUT_BASE:-./output}"
TARGETS_FILE="${TARGETS_FILE:-targets.txt}"
WORDLISTS_DIR="${WORDLISTS_DIR:-./wordlists}"
LOOP_HOURS="${LOOP_HOURS:-6}"
RATE_LIMIT="${RATE_LIMIT:-80}"
THREADS="${THREADS:-30}"
SLEEP_BETWEEN_TOOLS="${SLEEP_BETWEEN_TOOLS:-3}"
SLEEP_BETWEEN_TARGETS="${SLEEP_BETWEEN_TARGETS:-60}"
MAX_SUBS_PROBE="${MAX_SUBS_PROBE:-5000}"
MAX_FFUF_HOSTS="${MAX_FFUF_HOSTS:-5}"
MAX_ARJUN_HOSTS="${MAX_ARJUN_HOSTS:-15}"
MAX_SUBDOMAIN_BRUTE="${MAX_SUBDOMAIN_BRUTE:-3000}"   # coffsec #4 — capped from 110k list
FFUF_EXTENSIONS="${FFUF_EXTENSIONS:-php,bak,old,txt,json,xml,asp,aspx,jsp}"
RECURSIVE_FUZZ="${RECURSIVE_FUZZ:-1}"               # ffuf -recursion on dir/API/CeWL
FFUF_RECURSION_DEPTH="${FFUF_RECURSION_DEPTH:-2}"   # how deep: /admin → /admin/users → …
FFUF_RECURSION_STRATEGY="${FFUF_RECURSION_STRATEGY:-greedy}"
MAX_RECURSIVE_SEEDS="${MAX_RECURSIVE_SEEDS:-15}"     # 2nd pass: fuzz again inside hits
MAX_PERMUTE_SEEDS="${MAX_PERMUTE_SEEDS:-150}"       # subs fed to gotator permutations
MAX_JS_DOWNLOAD="${MAX_JS_DOWNLOAD:-40}"            # JS files to download + analyze
SCOPE_FILE="${SCOPE_FILE:-./scope.txt}"
NAABU_PORTS="${NAABU_PORTS:-21,22,80,443,2375,3000,4000,4848,5000,5900,6379,8080,8443,8888,9000,9200,9300,27017,28017}"
TOOLS_PATH="${TOOLS_PATH:-${HOME}/.pdtm/go/bin:${HOME}/go/bin:${HOME}/.local/bin}"
DAEMON=0
RESUME=0
TARGETS=()

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINKFINDER_DIR="${LINKFINDER_DIR:-${SCRIPT_DIR}/tools/LinkFinder}"
cd "$SCRIPT_DIR"
export PATH="${PATH}:${TOOLS_PATH}"
# shellcheck disable=SC1091
[ -f .env ] && set -a && source .env && set +a

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
warn() { echo "[$(date '+%H:%M:%S')] WARN: $*" >&2; }
die()  { echo "[$(date '+%H:%M:%S')] ERROR: $*" >&2; exit 1; }

have() { command -v "$1" &>/dev/null; }
rate_sleep() { sleep "${SLEEP_BETWEEN_TOOLS}"; }

dedupe_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  sort -u "$f" -o "$f"
}

count_lines() {
  [ -f "$1" ] && wc -l <"$1" | tr -d ' ' || echo 0
}

cap_lines() {
  head -n "$3" "$1" >"$2"
}

wordlist() {
  local name="$1"
  [ -f "${WORDLISTS_DIR}/${name}" ] && echo "${WORDLISTS_DIR}/${name}" && return 0
  return 1
}

ffuf_append_json() {
  local json="$1" out="$2"
  shift 2
  [ -f "$json" ] && have jq && jq -r "$@" "$json" >>"$out" 2>/dev/null || true
}

ffuf_recursion_enabled() {
  [ "${RECURSIVE_FUZZ:-0}" = "1" ] && [ "${FFUF_RECURSION_DEPTH:-0}" -gt 0 ]
}

# Populates global FFUF_RECUR_ARGS for: ffuf ... "${FFUF_RECUR_ARGS[@]}" ...
ffuf_build_recursion_args() {
  FFUF_RECUR_ARGS=()
  if ffuf_recursion_enabled; then
    FFUF_RECUR_ARGS=(-recursion -recursion-depth "$FFUF_RECURSION_DEPTH" \
      -recursion-strategy "${FFUF_RECURSION_STRATEGY:-greedy}")
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --daemon|-d)     DAEMON=1; shift ;;
      --resume|-r)     RESUME=1; shift ;;
      -f|--file)       TARGETS_FILE="$2"; shift 2 ;;
      -o|--output)     OUTPUT_BASE="$2"; shift 2 ;;
      --rate)          RATE_LIMIT="$2"; shift 2 ;;
      --loop-hours)    LOOP_HOURS="$2"; shift 2 ;;
      --no-recursive)  RECURSIVE_FUZZ=0; shift ;;
      --recursion-depth) FFUF_RECURSION_DEPTH="$2"; shift 2 ;;
      -h|--help)
        sed -n '2,8p' "$0"
        exit 0
        ;;
      -*) die "Unknown option: $1" ;;
      *)  TARGETS+=("$1"); shift ;;
    esac
  done
  if [ ${#TARGETS[@]} -eq 0 ] && [ -f "$TARGETS_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%%#*}"
      line="$(echo "$line" | xargs)"
      [ -n "$line" ] && TARGETS+=("$line")
    done <"$TARGETS_FILE"
  fi
  [ ${#TARGETS[@]} -gt 0 ] || die "No targets. Pass domain or use -f targets.txt"
}

should_skip() {
  local dir="$1"
  [ "$RESUME" -eq 0 ] && return 1
  local report="$dir/REPORT_$(basename "$dir").txt"
  [ -f "$report" ] || return 1
  local mtime age
  mtime="$(stat -c %Y "$report" 2>/dev/null || stat -f %m "$report" 2>/dev/null || echo 0)"
  age=$(( $(date +%s) - mtime ))
  [ "$age" -lt 86400 ]
}

backup_if_exists() {
  local src="$1" dest="$2"
  [ -f "$src" ] && cp "$src" "$dest"
}

phase_subdomains() {
  local target="$1" dir="$2"
  local subs="$dir/subdomains.txt"
  local newsubs="$dir/subdomains_new.txt"
  local tmp="$dir/.tmp"
  mkdir -p "$tmp"
  backup_if_exists "$subs" "$tmp/subdomains_prev.txt"
  : >"$subs"

  log "[$target] Phase 1: subdomain discovery"

  if have subfinder; then
    subfinder -d "$target" -all -recursive -silent -o "$tmp/subfinder.txt" 2>/dev/null || true
    cat "$tmp/subfinder.txt" >>"$subs" 2>/dev/null || true
    rate_sleep
  else warn "subfinder not found — run ./install.sh"; fi

  if have assetfinder; then
    assetfinder --subs-only "$target" >>"$subs" 2>/dev/null || true
    rate_sleep
  fi

  if have amass; then
    timeout 600 amass enum -passive -d "$target" -o "$tmp/amass.txt" 2>/dev/null || true
    cat "$tmp/amass.txt" >>"$subs" 2>/dev/null || true
    rate_sleep
  fi

  if have curl; then
    curl -fsSL "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null \
      | grep -oP '"name_value"\s*:\s*"\K[^"]+' 2>/dev/null \
      | tr ',' '\n' | sed 's/^\*\.//' >>"$subs" || true
    rate_sleep
  fi

  curl -fsSL "https://api.hackertarget.com/hostsearch/?q=${target}" 2>/dev/null \
    | cut -d, -f1 >>"$subs" || true
  rate_sleep

  echo "$target" >>"$subs"
  echo "www.${target}" >>"$subs"

  {
    grep -iF ".${target}" "$subs" 2>/dev/null || true
    grep -iFx "${target}" "$subs" 2>/dev/null || true
  } | tr '[:upper:]' '[:lower:]' | sort -u >"$tmp/filtered.txt" || true
  mv "$tmp/filtered.txt" "$subs"
  dedupe_file "$subs"

  if [ -f "$tmp/subdomains_prev.txt" ]; then
    comm -23 <(sort "$subs") <(sort "$tmp/subdomains_prev.txt") >"$newsubs" 2>/dev/null || : >"$newsubs"
    log "[$target] New subdomains since last run: $(count_lines "$newsubs")"
  else
    : >"$newsubs"
  fi

  # coffsec #4 — ffuf subdomain brute (rate-limited, capped)
  phase_subdomain_bruteforce "$target" "$dir"

  log "[$target] Subdomains: $(count_lines "$subs")"
}

phase_subdomain_bruteforce() {
  local target="$1" dir="$2"
  local subs="$dir/subdomains.txt"
  local tmp="$dir/.tmp"
  local wl

  wl="$(wordlist subdomains-top110k.txt || wordlist vhost-subdomains-top100k.txt || true)"
  if [ -z "$wl" ] || ! have ffuf; then
    return
  fi

  log "[$target] ffuf subdomain brute (top ${MAX_SUBDOMAIN_BRUTE} prefixes)"
  head -n "$MAX_SUBDOMAIN_BRUTE" "$wl" >"$tmp/sub_brute_wl.txt"
  ffuf -w "$tmp/sub_brute_wl.txt" -u "https://FUZZ.${target}" \
    -mc 200,301,302,403 -t "$THREADS" -rate "$RATE_LIMIT" -timeout 8 -s \
    -of json -o "$tmp/sub_brute.json" 2>/dev/null || true

  if have jq && [ -f "$tmp/sub_brute.json" ]; then
    jq -r '.results[]?.input.FUZZ // empty' "$tmp/sub_brute.json" 2>/dev/null | while read -r prefix; do
      [ -n "$prefix" ] && echo "${prefix}.${target}" >>"$subs"
    done
    dedupe_file "$subs"
  fi
  rate_sleep
}

phase_scope_filter() {
  local target="$1" dir="$2"
  local subs="$dir/subdomains.txt"
  local scope="${SCOPE_FILE}"
  local tmp="$dir/.tmp/scope_filtered.txt"

  [ ! -f "$scope" ] && return
  [ ! -s "$subs" ] && return

  log "[$target] Scope filter → $(basename "$scope")"
  : >"$tmp"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs | sed 's/^\*\.//')"
    [ -z "$line" ] && continue
    grep -iF ".$line" "$subs" 2>/dev/null >>"$tmp" || true
    grep -iFx "$line" "$subs" 2>/dev/null >>"$tmp" || true
  done <"$scope"
  dedupe_file "$tmp"
  if [ -s "$tmp" ]; then
    mv "$tmp" "$subs"
    log "[$target] In-scope subdomains: $(count_lines "$subs")"
  else
    warn "[$target] Scope filter removed everything — check $scope"
  fi
  rate_sleep
}

phase_dnsx() {
  local target="$1" dir="$2"
  local subs="$dir/subdomains.txt"
  local out="$dir/dns_resolved.txt"
  local tmp="$dir/.tmp"

  : >"$out"
  if ! have dnsx || [ ! -s "$subs" ]; then
    return
  fi

  log "[$target] dnsx — resolve subdomains"
  dnsx -l "$subs" -a -aaaa -cname -resp -silent -o "$tmp/dnsx_raw.txt" 2>/dev/null || true
  if [ -s "$tmp/dnsx_raw.txt" ]; then
    awk '{print $1}' "$tmp/dnsx_raw.txt" | tr '[:upper:]' '[:lower:]' | sort -u >"$out"
  fi
  rate_sleep
  log "[$target] DNS resolved: $(count_lines "$out")"
}

phase_permutations() {
  local target="$1" dir="$2"
  local subs="$dir/subdomains.txt"
  local tmp="$dir/.tmp"
  local perm_wl

  if ! have gotator || ! have dnsx || [ ! -s "$subs" ]; then
    return
  fi

  perm_wl="$(wordlist permute-words.txt || wordlist vhost-5k.txt || true)"
  [ -z "$perm_wl" ] && return

  log "[$target] gotator permutations (seeds: ${MAX_PERMUTE_SEEDS})"
  head -n "$MAX_PERMUTE_SEEDS" "$subs" >"$tmp/perm_seeds.txt"
  gotator -sub "$tmp/perm_seeds.txt" -perm "$perm_wl" -depth 1 -numbers 2 -md 2>/dev/null \
    | dnsx -silent -a -resp 2>/dev/null >"$tmp/permuted.txt" || true

  if [ -s "$tmp/permuted.txt" ]; then
    awk '{print $1}' "$tmp/permuted.txt" | tr '[:upper:]' '[:lower:]' >>"$subs"
    dedupe_file "$subs"
    log "[$target] After permutations: $(count_lines "$subs") subs"
  fi
  rate_sleep
}

phase_live_and_ports() {
  local target="$1" dir="$2"
  local subs="$dir/subdomains.txt"
  local live="$dir/live_hosts.txt"
  local priority="$dir/priority_hosts.txt"
  local ports="$dir/open_ports.txt"
  local nmap_out="$dir/nmap_results.txt"
  local probe="$dir/.probe_urls.txt"
  local capped="$dir/.subs_capped.txt"
  local tmp="$dir/.tmp"

  log "[$target] Phase 2: live hosts + ports"
  : >"$live"; : >"$priority"; : >"$ports"; : >"$nmap_out"

  local probe_src="$subs"
  [ -s "$dir/dns_resolved.txt" ] && probe_src="$dir/dns_resolved.txt"
  cap_lines "$probe_src" "$capped" "$MAX_SUBS_PROBE"

  if have naabu; then
    naabu -list "$capped" -p "$NAABU_PORTS" -rate "$RATE_LIMIT" -silent -o "$tmp/naabu.txt" 2>/dev/null || true
    [ -f "$tmp/naabu.txt" ] && cp "$tmp/naabu.txt" "$ports"
    if [ -s "$ports" ]; then
      grep -E ':3000|:4848|:6379|:9200|:27017|:2375|:5900|:8888|:9000|:9300' "$ports" 2>/dev/null \
        | sort -u >"$dir/interesting_ports.txt" || : >"$dir/interesting_ports.txt"
    else
      : >"$dir/interesting_ports.txt"
    fi
    rate_sleep
  else
    : >"$dir/interesting_ports.txt"
  fi

  : >"$probe"
  if [ -s "$ports" ]; then
    while IFS= read -r line; do
      host="${line%%:*}"; port="${line##*:}"
      if [ "$port" = "443" ]; then echo "https://${host}" >>"$probe"
      elif [ "$port" = "80" ]; then echo "http://${host}" >>"$probe"
      else echo "http://${host}:${port}" >>"$probe"; fi
    done <"$ports"
  fi
  while IFS= read -r sub; do
    echo "https://${sub}" >>"$probe"
    echo "http://${sub}" >>"$probe"
  done <"$capped"
  dedupe_file "$probe"

  if have httpx; then
    httpx -l "$probe" -silent -status-code -title -tech-detect \
      -rate-limit "$RATE_LIMIT" -threads "$THREADS" \
      -o "$tmp/httpx.txt" 2>/dev/null || true
    if [ -s "$tmp/httpx.txt" ]; then
      awk '{print $1}' "$tmp/httpx.txt" | sort -u >"$live"
      cp "$tmp/httpx.txt" "$dir/httpx_full.txt"
      grep -iE 'admin|staging|dashboard|internal|dev|test|beta|portal|vpn|sso|console|manage|jenkins|grafana|kibana|elastic|graphql|swagger' \
        "$tmp/httpx.txt" 2>/dev/null | awk '{print $1}' | sort -u >"$priority" || true
    fi
    rate_sleep
  else
    warn "httpx not found"
    cp "$probe" "$live"
  fi

  [ ! -s "$priority" ] && head -n 10 "$live" >"$priority" 2>/dev/null || true
  dedupe_file "$live"
  log "[$target] Live: $(count_lines "$live") | Priority: $(count_lines "$priority")"

  if have nmap && [ -s "$live" ]; then
    head -n 30 "$live" | sed -E 's|https?://||; s|/.*||; s|:.*||' | sort -u >"$tmp/nmap_hosts.txt"
    while IFS= read -r host; do
      nmap -sV -T3 --max-rate "$RATE_LIMIT" -Pn -p "$NAABU_PORTS" \
        "$host" >>"$nmap_out" 2>/dev/null || true
      sleep 2
    done <"$tmp/nmap_hosts.txt"
    rate_sleep
  elif [ -s "$ports" ]; then
    { echo "# naabu (nmap unavailable)"; cat "$ports"; } >"$nmap_out"
  fi
}

phase_urls() {
  local target="$1" dir="$2"
  local urls="$dir/urls.txt"
  local sensitive="$dir/sensitive_urls.txt"
  local tmp="$dir/.tmp"

  log "[$target] Phase 3: URL harvest"
  : >"$urls"

  if have gauplus; then
    gauplus --threads 5 --subs "$target" --blacklist ttf,woff,woff2,svg,png,jpg,gif,ico,css \
      2>/dev/null >>"$urls" || true
    rate_sleep
  elif have gau; then
    gau --subs "$target" 2>/dev/null >>"$urls" || true
    rate_sleep
  fi

  if have waybackurls; then
    waybackurls "$target" 2>/dev/null >>"$urls" || true
    rate_sleep
  fi

  if have waymore; then
    waymore -i "$target" -mode U -oU "$tmp/waymore.txt" 2>/dev/null || true
    [ -f "$tmp/waymore.txt" ] && cat "$tmp/waymore.txt" >>"$urls"
    rate_sleep
  fi

  if have gospider && [ -s "$dir/live_hosts.txt" ]; then
    head -n 1 "$dir/live_hosts.txt" | while read -r seed; do
      gospider -s "$seed" -d 2 -c 5 -t 5 --other-source -q 2>/dev/null \
        | grep -oE 'https?://[^ ]+' >>"$urls" || true
    done
    rate_sleep
  fi

  if have hakrawler && [ -s "$dir/live_hosts.txt" ]; then
    head -n 5 "$dir/live_hosts.txt" | while read -r seed; do
      echo "$seed" | hakrawler -depth 2 -plain 2>/dev/null >>"$urls" || true
    done
    rate_sleep
  fi

  if have katana && [ -s "$dir/live_hosts.txt" ]; then
    head -n 15 "$dir/live_hosts.txt" >"$tmp/katana_seeds.txt"
    katana -list "$tmp/katana_seeds.txt" -d 3 -jc -jsl -c 10 -silent 2>/dev/null >>"$urls" || true
    rate_sleep
  fi

  dedupe_file "$urls"
  grep -iE '^https?://' "$urls" >"$tmp/http.txt" 2>/dev/null && mv "$tmp/http.txt" "$urls" || true

  if have uro && [ -s "$urls" ]; then
    uro -i "$urls" -o "$tmp/uro.txt" 2>/dev/null || true
    [ -s "$tmp/uro.txt" ] && mv "$tmp/uro.txt" "$urls"
    rate_sleep
  fi

  grep -iE 'admin|api|token|logout|password|secret|dashboard|staging|internal|debug|metrics|\.env|\.git|redirect=|url=|next=|callback=' \
    "$urls" 2>/dev/null | sort -u >"$sensitive" || : >"$sensitive"

  log "[$target] URLs: $(count_lines "$urls") | Sensitive: $(count_lines "$sensitive")"
}

phase_js_mining() {
  local target="$1" dir="$2"
  local urls="$dir/urls.txt"
  local js_out="$dir/js_urls.txt"
  local endpoints="$dir/js_endpoints.txt"
  local grep_secrets="$dir/js_secrets_grep.txt"
  local secrets="$dir/secrets.txt"
  local tmp="$dir/.tmp"
  local js_dir="$tmp/js_files"

  log "[$target] Phase 3b: JavaScript mining"
  : >"$js_out"; : >"$endpoints"; : >"$grep_secrets"

  if [ -s "$urls" ]; then
    grep -iE '\.js($|\?)' "$urls" 2>/dev/null | sort -u >>"$js_out" || true
  fi

  if have katana && [ -s "$dir/priority_hosts.txt" ]; then
    head -n 5 "$dir/priority_hosts.txt" >"$tmp/js_katana_seeds.txt"
    katana -list "$tmp/js_katana_seeds.txt" -d 3 -jc -jsl -c 10 -silent 2>/dev/null \
      | grep -iE '\.js($|\?)' >>"$js_out" || true
    rate_sleep
  fi

  if have gauplus; then
    gauplus --threads 3 --subs "$target" 2>/dev/null | grep -iE '\.js($|\?)' >>"$js_out" || true
    rate_sleep
  fi

  dedupe_file "$js_out"
  [ ! -s "$js_out" ] && return

  mkdir -p "$js_dir"
  head -n "$MAX_JS_DOWNLOAD" "$js_out" | while read -r jsurl; do
    [ -z "$jsurl" ] && continue
    safe="$(echo "$jsurl" | md5sum 2>/dev/null | cut -c1-12 || echo js)"
    curl -sk --max-time 15 "$jsurl" -o "$js_dir/${safe}.js" 2>/dev/null || true
    sleep 0.3
  done

  for f in "$js_dir"/*.js; do
    [ -f "$f" ] || continue
    grep -oEi 'https?://[a-zA-Z0-9./_?=&%-]+' "$f" 2>/dev/null \
      | grep -iE '/api|/v[0-9]|/internal|/admin|/graphql' >>"$endpoints" || true
    grep -iE '(api[_-]?key|apikey|secret[_-]?key|aws_access|private[_-]?key|password|token|mongodb\+srv|authorization)' "$f" 2>/dev/null \
      | grep -viE '^[[:space:]]*//' >>"$grep_secrets" || true
    if [ -f "${LINKFINDER_DIR}/linkfinder.py" ] && have python3; then
      python3 "${LINKFINDER_DIR}/linkfinder.py" -i "$f" -o cli 2>/dev/null \
        | grep -iE '^/|https?://' >>"$endpoints" || true
    fi
  done

  dedupe_file "$endpoints"
  dedupe_file "$grep_secrets"

  if have nuclei && [ -s "$js_out" ]; then
    : >"$secrets"
    head -n 150 "$js_out" >"$tmp/js_nuclei.txt"
    nuclei -l "$tmp/js_nuclei.txt" -t exposures/tokens/,exposures/apis/,exposures/configs/ \
      -silent -rate-limit "$RATE_LIMIT" -o "$tmp/js_nuclei_out.txt" 2>/dev/null || true
    [ -s "$tmp/js_nuclei_out.txt" ] && cat "$tmp/js_nuclei_out.txt" >>"$secrets"
    rate_sleep
  else
    : >"$secrets"
  fi

  [ -s "$grep_secrets" ] && cat "$grep_secrets" >>"$secrets"
  dedupe_file "$secrets"

  log "[$target] JS: $(count_lines "$js_out") files | endpoints: $(count_lines "$endpoints") | secrets: $(count_lines "$secrets")"
}

phase_cloud_buckets() {
  local target="$1" dir="$2"
  local out="$dir/cloud_buckets.txt"
  local tmp="$dir/.tmp/buckets.txt"
  local slug stem sfx

  log "[$target] Phase 3c: cloud bucket probe (no API keys)"
  : >"$out"
  : >"$tmp"

  slug="${target%%.*}"
  slug="${slug//./}"
  for stem in "$slug" "${target%%.*}" "${target//./-}"; do
    [ -z "$stem" ] && continue
    for sfx in dev prod staging backup assets files internal logs test media uploads static data public private; do
      echo "${stem}-${sfx}" >>"$tmp"
      echo "${stem}.${sfx}" >>"$tmp"
      echo "${sfx}-${stem}" >>"$tmp"
      echo "aws-${stem}-${sfx}" >>"$tmp"
    done
  done
  dedupe_file "$tmp"

  if have s3scanner; then
    s3scanner scan -bucket-file "$tmp" 2>/dev/null | tee -a "$out" || true
    rate_sleep
  else
    head -n 40 "$tmp" | while read -r bucket; do
      code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "https://${bucket}.s3.amazonaws.com" 2>/dev/null || echo 0)"
      [ "$code" != "404" ] && [ "$code" != "000" ] && echo "s3://${bucket} → HTTP ${code}" >>"$out"
      sleep 0.2
    done
    rate_sleep
  fi

  log "[$target] Cloud buckets: $(count_lines "$out")"
}

phase_params() {
  local target="$1" dir="$2"
  local urls="$dir/urls.txt"
  local tmp="$dir/.tmp"
  local patterns="sqli ssrf idor xss lfi rce ssti redirect"

  log "[$target] Phase 4: parameter mining"

  # paramspider
  if have paramspider; then
    (cd "$tmp" && paramspider -d "$target" --exclude png,jpg,gif,jpeg,svg,css,woff,ico 2>/dev/null) || true
    find "$tmp" -name "*.txt" 2>/dev/null | while read -r f; do cat "$f"; done >>"$tmp/paramspider.txt" 2>/dev/null || true
    if [ -s "$tmp/paramspider.txt" ]; then
      cat "$tmp/paramspider.txt" >>"$urls"
      dedupe_file "$urls"
    fi
    rate_sleep
  fi

  # wayback CDX params
  curl -fsSL "https://web.archive.org/cdx/search/cdx?url=*.${target}/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200" \
    2>/dev/null | grep '?' | sort -u >"$dir/wayback_params.txt" || : >"$dir/wayback_params.txt"
  [ -s "$dir/wayback_params.txt" ] && cat "$dir/wayback_params.txt" >>"$urls" && dedupe_file "$urls"
  rate_sleep

  # gf classification
  if have gf && [ -s "$urls" ]; then
    for p in $patterns; do
      gf "$p" <"$urls" 2>/dev/null | sort -u >"$dir/params_${p}.txt" || : >"$dir/params_${p}.txt"
    done
    rate_sleep
  elif [ -s "$urls" ]; then
    warn "gf not found — using grep fallback for params"
    grep -iE '[?&](url|uri|redirect|next|return|dest|target|callback)=' "$urls" | sort -u >"$dir/params_redirect.txt" || true
    grep -iE '[?&](id|user_id|uid|order_id|account_id)=' "$urls" | sort -u >"$dir/params_idor.txt" || true
    grep -iE '[?&](q|query|search|sort|filter|order|column)=' "$urls" | sort -u >"$dir/params_sqli.txt" || true
    grep -iE '[?&](file|page|template|include|path|doc)=' "$urls" | sort -u >"$dir/params_lfi.txt" || true
  fi

  # arjun hidden params on priority hosts
  : >"$dir/arjun_results.txt"
  if have arjun && [ -s "$dir/priority_hosts.txt" ]; then
    head -n "$MAX_ARJUN_HOSTS" "$dir/priority_hosts.txt" | while read -r url; do
      [ -z "$url" ] && continue
      safe="$(echo "$url" | sed 's|https\?://||; s|/|_|g; s|[^a-zA-Z0-9._-]||g')"
      arjun -u "$url" -oJ "$tmp/arjun_${safe}.json" -t 15 -d 2 -q 2>/dev/null || true
      [ -f "$tmp/arjun_${safe}.json" ] && echo "=== $url ===" >>"$dir/arjun_results.txt" \
        && cat "$tmp/arjun_${safe}.json" >>"$dir/arjun_results.txt"
      sleep 2
    done
    rate_sleep
  fi

  log "[$target] Params — SSRF:$(count_lines "$dir/params_ssrf.txt") SQLi:$(count_lines "$dir/params_sqli.txt") Redirect:$(count_lines "$dir/params_redirect.txt")"
}

phase_ffuf() {
  local target="$1" dir="$2"
  local tmp="$dir/.tmp"
  local dirs_wl vhost_wl api_wl

  ffuf_build_recursion_args
  if ffuf_recursion_enabled; then
    log "[$target] Phase 5: ffuf recursive (depth ${FFUF_RECURSION_DEPTH}, ${FFUF_RECURSION_STRATEGY})"
  else
    log "[$target] Phase 5: ffuf (dirs + API + vhost)"
  fi
  : >"$dir/dir_fuzz_results.txt"
  : >"$dir/api_fuzz_results.txt"
  : >"$dir/vhost_fuzz_results.txt"

  if ! have ffuf; then
    warn "ffuf not found — run ./install.sh"
    return
  fi

  # coffsec #2 raft-large > common; #9 onelist fallback
  dirs_wl="$(wordlist dirs-raft-large.txt || wordlist dirs-onelist.txt || wordlist dirs-common.txt || true)"
  vhost_wl="$(wordlist vhost-subdomains-top100k.txt || wordlist vhost-5k.txt || true)"
  api_wl="$(wordlist api-endpoints.txt || true)"

  if [ -n "$dirs_wl" ] && [ -s "$dir/priority_hosts.txt" ]; then
    head -n "$MAX_FFUF_HOSTS" "$dir/priority_hosts.txt" | while read -r base; do
      base="${base%/}"
      safe="$(echo "$base" | sed 's|https\?://||; s|/|_|g; s|[^a-zA-Z0-9._-]||g')"
      ffuf -w "$dirs_wl" -u "${base}/FUZZ" -mc 200,301,302,401,403 \
        -e "$FFUF_EXTENSIONS" -t "$THREADS" -rate "$RATE_LIMIT" -timeout 10 -s \
        "${FFUF_RECUR_ARGS[@]}" \
        -of json -o "$tmp/ffuf_dir_${safe}.json" 2>/dev/null || true
      ffuf_append_json "$tmp/ffuf_dir_${safe}.json" "$dir/dir_fuzz_results.txt" \
        '.results[]? | "\(.url) [\(.status)]"'
      sleep 3
    done
    rate_sleep
  fi

  # coffsec #6 — API endpoint discovery (recursive under /api/)
  if [ -n "$api_wl" ] && [ -s "$dir/priority_hosts.txt" ]; then
    head -n 3 "$dir/priority_hosts.txt" | while read -r base; do
      base="${base%/}"
      safe="$(echo "$base" | sed 's|https\?://||; s|/|_|g; s|[^a-zA-Z0-9._-]||g')"
      ffuf -w "$api_wl" -u "${base}/api/FUZZ" -mc 200,201,204,301,302,400,401,403 \
        -t "$THREADS" -rate "$RATE_LIMIT" -timeout 10 -s \
        "${FFUF_RECUR_ARGS[@]}" \
        -of json -o "$tmp/ffuf_api_${safe}.json" 2>/dev/null || true
      ffuf_append_json "$tmp/ffuf_api_${safe}.json" "$dir/api_fuzz_results.txt" \
        '.results[]? | "\(.url) [\(.status)]"'
      sleep 2
    done
    rate_sleep
  fi

  if [ -n "$vhost_wl" ] && [ -s "$dir/open_ports.txt" ]; then
    grep -E ':443$|:80$' "$dir/open_ports.txt" 2>/dev/null | head -n 5 | while IFS= read -r line; do
      ip="${line%%:*}"
      port="${line##*:}"
      scheme="https"; [ "$port" = "80" ] && scheme="http"
      ffuf -w "$vhost_wl" -u "${scheme}://${ip}/" -H "Host: FUZZ.${target}" \
        -mc 200,301,302,403 -t "$THREADS" -rate "$RATE_LIMIT" -timeout 10 -s \
        -of json -o "$tmp/ffuf_vhost_${ip}.json" 2>/dev/null || true
      ffuf_append_json "$tmp/ffuf_vhost_${ip}.json" "$dir/vhost_fuzz_results.txt" \
        --arg ip "$ip" --arg t "$target" '.results[]? | "\($ip) Host:\(.input.FUZZ).\($t) [\(.status)]"'
      sleep 3
    done
    rate_sleep
  fi

  log "[$target] ffuf dirs:$(count_lines "$dir/dir_fuzz_results.txt") api:$(count_lines "$dir/api_fuzz_results.txt") vhosts:$(count_lines "$dir/vhost_fuzz_results.txt")"
}

phase_cewl() {
  local target="$1" dir="$2"
  local tmp="$dir/.tmp"
  local out="$dir/custom_wordlist.txt"

  log "[$target] Phase 5a: CeWL custom wordlist (coffsec #10)"
  : >"$out"
  if ! have cewl || [ ! -s "$dir/live_hosts.txt" ]; then
    return
  fi

  head -n 1 "$dir/live_hosts.txt" | while read -r seed; do
    cewl "$seed" -d 2 -m 4 --with-numbers -w "$out" 2>/dev/null || true
    break
  done

  if [ ! -s "$out" ] || ! have ffuf; then
    rate_sleep
    return
  fi

  log "[$target] ffuf with CeWL custom list on primary host"
  ffuf_build_recursion_args
  head -n 1 "$dir/live_hosts.txt" | while read -r base; do
    base="${base%/}"
    ffuf -w "$out" -u "${base}/FUZZ" -mc 200,301,302,401,403 \
      -e "$FFUF_EXTENSIONS" -t "$THREADS" -rate "$RATE_LIMIT" -timeout 10 -s \
      "${FFUF_RECUR_ARGS[@]}" \
      -of json -o "$tmp/ffuf_cewl.json" 2>/dev/null || true
    ffuf_append_json "$tmp/ffuf_cewl.json" "$dir/dir_fuzz_results.txt" \
      '.results[]? | "\(.url) [cewl:\(.status)]"'
  done
  rate_sleep
  log "[$target] CeWL words: $(count_lines "$out")"
}

phase_recursive_ffuf() {
  local target="$1" dir="$2"
  local tmp="$dir/.tmp"
  local out="$dir/recursive_fuzz_results.txt"
  local wl

  : >"$out"
  [ "${RECURSIVE_FUZZ:-0}" = "1" ] || return
  ! have ffuf && return

  ffuf_build_recursion_args
  wl="$(wordlist dirs-common.txt || wordlist dirs-onelist.txt || true)"
  [ -z "$wl" ] && return

  log "[$target] Phase 5d: 2nd-pass recursive fuzz inside discovered paths (max ${MAX_RECURSIVE_SEEDS} seeds)"

  : >"$tmp/recurse_seeds.txt"
  for src in "$dir/dir_fuzz_results.txt" "$dir/api_fuzz_results.txt" "$dir/sensitive_paths.txt"; do
    [ ! -s "$src" ] && continue
    grep -oE 'https?://[^ ]+' "$src" 2>/dev/null | sed 's/\[.*//' | sed 's/ →.*//' | while read -r u; do
      u="${u%/}"
      [ -n "$u" ] && echo "$u" >>"$tmp/recurse_seeds.txt"
    done
  done
  dedupe_file "$tmp/recurse_seeds.txt"
  [ ! -s "$tmp/recurse_seeds.txt" ] && return

  head -n "$MAX_RECURSIVE_SEEDS" "$tmp/recurse_seeds.txt" | while read -r seed; do
    seed="${seed%/}"
    safe="$(echo "$seed" | md5sum 2>/dev/null | cut -c1-8 || echo r)"
    ffuf -w "$wl" -u "${seed}/FUZZ" -mc 200,301,302,401,403 \
      -e "$FFUF_EXTENSIONS" -t "$THREADS" -rate "$RATE_LIMIT" -timeout 10 -s \
      "${FFUF_RECUR_ARGS[@]}" \
      -of json -o "$tmp/recurse_${safe}.json" 2>/dev/null || true
    ffuf_append_json "$tmp/recurse_${safe}.json" "$out" \
      '.results[]? | "\(.url) [\(.status)]"'
    sleep 2
  done

  # Merge deep hits into main dir results for the report
  [ -s "$out" ] && cat "$out" >>"$dir/dir_fuzz_results.txt" && dedupe_file "$dir/dir_fuzz_results.txt"
  rate_sleep
  log "[$target] Recursive deep fuzz: $(count_lines "$out")"
}

phase_lfi_probe() {
  local dir="$2"
  local tmp="$dir/.tmp"
  local lfi_wl="$dir/lfi_fuzz_results.txt"
  local wl

  log "[$(basename "$dir")] Phase 5c: LFI probe (coffsec #7 Jhaddix)"
  : >"$lfi_wl"
  wl="$(wordlist lfi-jhaddix.txt || true)"
  [ -z "$wl" ] || ! have ffuf || [ ! -s "$dir/params_lfi.txt" ] && return

  head -n 5 "$dir/params_lfi.txt" | while read -r url; do
    case "$url" in
      *file=*)   param="file" ;;
      *page=*)   param="page" ;;
      *path=*)   param="path" ;;
      *include=*) param="include" ;;
      *) continue ;;
    esac
    base="${url%%${param}=*}${param}="
    safe="$(echo "$url" | md5sum 2>/dev/null | cut -c1-8 || echo lfi)"
    ffuf -w "$wl" -u "${base}FUZZ" -mc all -mr "root:" -t 20 -rate 40 -timeout 10 -s \
      -of json -o "$tmp/lfi_${safe}.json" 2>/dev/null || true
    ffuf_append_json "$tmp/lfi_${safe}.json" "$lfi_wl" \
      --arg u "$url" '.results[]? | "\($u) → \(.input.FUZZ)"'
    sleep 2
  done
  rate_sleep
  log "[$(basename "$dir")] LFI probes: $(count_lines "$lfi_wl")"
}

phase_sensitive_paths() {
  local dir="$2"
  local out="$dir/sensitive_paths.txt"
  local paths="/health /metrics /actuator /actuator/env /.env /.git/config /.git/HEAD /server-status /phpinfo.php /api/swagger.json /swagger.json /debug /trace /admin /graphql /api/graphql /v1/graphql"
  log "[$2] Phase 5b: sensitive path probe"
  : >"$out"
  [ -s "$dir/priority_hosts.txt" ] || return
  head -n 15 "$dir/priority_hosts.txt" | while read -r base; do
    base="${base%/}"
    for p in $paths; do
      code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "${base}${p}" 2>/dev/null || echo 0)"
      [ "$code" != "404" ] && [ "$code" != "000" ] && echo "${base}${p} → ${code}" >>"$out"
      sleep 0.2
    done
  done
  rate_sleep
  log "[$(basename "$dir")] Sensitive paths: $(count_lines "$out")"
}

phase_takeover() {
  local target="$1" dir="$2"
  local subs="$dir/subdomains.txt"
  local out="$dir/takeover_candidates.txt"
  local tmp="$dir/.tmp"

  log "[$target] Phase 6: takeover checks"
  : >"$out"

  if have subzy && [ -s "$subs" ]; then
    cap_lines "$subs" "$tmp/subs_cap.txt" 1000
    subzy run --targets "$tmp/subs_cap.txt" --concurrency 20 --output "$tmp/subzy.txt" 2>/dev/null || true
    grep -i vulnerable "$tmp/subzy.txt" 2>/dev/null >>"$out" || true
    rate_sleep
  fi

  if have nuclei && [ -s "$subs" ]; then
    head -n 500 "$subs" | sed 's/^/https:\/\//' >"$tmp/subs_https.txt"
    nuclei -l "$tmp/subs_https.txt" -t takeovers/ -silent -rate-limit "$RATE_LIMIT" \
      -o "$tmp/nuclei_takeover.txt" 2>/dev/null || true
    cat "$tmp/nuclei_takeover.txt" >>"$out" 2>/dev/null || true
    rate_sleep
  fi

  dedupe_file "$out"
  log "[$target] Takeovers: $(count_lines "$out")"
}

phase_nuclei() {
  local target="$1" dir="$2"
  local out="$dir/nuclei_results.txt"
  local critical="$dir/nuclei_critical.txt"
  local tmp="$dir/.tmp"

  log "[$target] Phase 7: nuclei full scan"
  : >"$out"; : >"$critical"

  if ! have nuclei; then warn "nuclei not found"; return; fi

  {
    head -n 300 "$dir/live_hosts.txt" 2>/dev/null
    head -n 500 "$dir/urls.txt" 2>/dev/null
    head -n 100 "$dir/sensitive_urls.txt" 2>/dev/null
    head -n 50 "$dir/params_ssrf.txt" 2>/dev/null
    head -n 50 "$dir/params_sqli.txt" 2>/dev/null
  } | grep -iE '^https?://' | sort -u >"$tmp/nuclei_targets.txt"

  [ ! -s "$tmp/nuclei_targets.txt" ] && return

  nuclei -l "$tmp/nuclei_targets.txt" \
    -severity critical,high,medium,low \
    -rate-limit "$RATE_LIMIT" -bulk-size 25 -c 25 \
    -t cves/,exposures/,misconfigurations/,technologies/,default-logins/,network/,http/ \
    -silent -o "$out" 2>/dev/null || true
  rate_sleep

  grep -iE '\[critical\]|\[high\]' "$out" 2>/dev/null | sort -u >"$critical" || true

  # Fuzz templates on param-classified URLs (light)
  for pfile in "$dir/params_xss.txt" "$dir/params_sqli.txt" "$dir/params_ssrf.txt"; do
    [ ! -s "$pfile" ] && continue
    head -n 30 "$pfile" >"$tmp/fuzz_seed.txt"
    case "$pfile" in
      *xss*)   nuclei -l "$tmp/fuzz_seed.txt" -t fuzzing/xss-reflected.yaml -silent -rate-limit "$RATE_LIMIT" -o "$tmp/nx.txt" 2>/dev/null || true ;;
      *sqli*)  nuclei -l "$tmp/fuzz_seed.txt" -t fuzzing/sqli.yaml -silent -rate-limit "$RATE_LIMIT" -o "$tmp/ns.txt" 2>/dev/null || true ;;
      *ssrf*)  nuclei -l "$tmp/fuzz_seed.txt" -t fuzzing/ssrf.yaml -silent -rate-limit "$RATE_LIMIT" -o "$tmp/nr.txt" 2>/dev/null || true ;;
    esac
    cat "$tmp"/n*.txt 2>/dev/null >>"$out" || true
    rate_sleep
  done

  dedupe_file "$out"
  log "[$target] Nuclei: $(count_lines "$out") | Critical/High: $(count_lines "$critical")"
}

phase_secrets() {
  # JS secrets handled in phase_js_mining; keep for backward-compatible log line
  local dir="$2"
  log "[$(basename "$dir")] Phase 8: secrets in $(count_lines "$dir/secrets.txt") lines (see phase_js_mining)"
}

write_report() {
  local target="$1" dir="$2"
  local report="$dir/REPORT_${target}.txt"
  local now; now="$(date '+%Y-%m-%d %H:%M UTC')"

  log "[$target] Writing report → $report"

  {
    echo "================================================================"
    echo "  RECON REPORT: ${target}"
    echo "  Generated: ${now}  |  Rate: ${RATE_LIMIT}/s  |  Threads: ${THREADS}"
    echo "================================================================"
    echo ""
    echo "=== SUMMARY ==="
    printf "%-22s %s\n" "Subdomains:" "$(count_lines "$dir/subdomains.txt")"
    printf "%-22s %s\n" "NEW subdomains:" "$(count_lines "$dir/subdomains_new.txt")"
    printf "%-22s %s\n" "DNS resolved:" "$(count_lines "$dir/dns_resolved.txt")"
    printf "%-22s %s\n" "Live hosts:" "$(count_lines "$dir/live_hosts.txt")"
    printf "%-22s %s\n" "Interesting ports:" "$(count_lines "$dir/interesting_ports.txt")"
    printf "%-22s %s\n" "JS files:" "$(count_lines "$dir/js_urls.txt")"
    printf "%-22s %s\n" "JS endpoints:" "$(count_lines "$dir/js_endpoints.txt")"
    printf "%-22s %s\n" "Cloud buckets:" "$(count_lines "$dir/cloud_buckets.txt")"
    printf "%-22s %s\n" "Priority hosts:" "$(count_lines "$dir/priority_hosts.txt")"
    printf "%-22s %s\n" "URLs:" "$(count_lines "$dir/urls.txt")"
    printf "%-22s %s\n" "Sensitive URLs:" "$(count_lines "$dir/sensitive_urls.txt")"
    printf "%-22s %s\n" "SSRF params:" "$(count_lines "$dir/params_ssrf.txt")"
    printf "%-22s %s\n" "SQLi params:" "$(count_lines "$dir/params_sqli.txt")"
    printf "%-22s %s\n" "Redirect params:" "$(count_lines "$dir/params_redirect.txt")"
    printf "%-22s %s\n" "IDOR params:" "$(count_lines "$dir/params_idor.txt")"
    printf "%-22s %s\n" "Dir fuzz hits:" "$(count_lines "$dir/dir_fuzz_results.txt")"
    printf "%-22s %s\n" "Recursive deep fuzz:" "$(count_lines "$dir/recursive_fuzz_results.txt")"
    printf "%-22s %s\n" "API fuzz hits:" "$(count_lines "$dir/api_fuzz_results.txt")"
    printf "%-22s %s\n" "CeWL words:" "$(count_lines "$dir/custom_wordlist.txt")"
    printf "%-22s %s\n" "LFI probes:" "$(count_lines "$dir/lfi_fuzz_results.txt")"
    printf "%-22s %s\n" "Vhost fuzz hits:" "$(count_lines "$dir/vhost_fuzz_results.txt")"
    printf "%-22s %s\n" "Sensitive paths:" "$(count_lines "$dir/sensitive_paths.txt")"
    printf "%-22s %s\n" "Takeovers:" "$(count_lines "$dir/takeover_candidates.txt")"
    printf "%-22s %s\n" "Nuclei (all):" "$(count_lines "$dir/nuclei_results.txt")"
    printf "%-22s %s\n" "Nuclei crit/high:" "$(count_lines "$dir/nuclei_critical.txt")"
    printf "%-22s %s\n" "Secrets:" "$(count_lines "$dir/secrets.txt")"
    echo ""

    section() {
      local title="$1" file="$2" n="${3:-30}"
      [ -s "$file" ] || return 0
      echo "=== ${title} ==="
      head -n "$n" "$file"
      echo ""
    }

    section "NEW SUBDOMAINS (since last run)" "$dir/subdomains_new.txt" 40
    section "INTERESTING PORTS (Jenkins/Redis/ES…)" "$dir/interesting_ports.txt" 20
    section "JS ENDPOINTS from source" "$dir/js_endpoints.txt" 30
    section "CLOUD BUCKETS — verify manually" "$dir/cloud_buckets.txt" 20
    section "TAKEOVER — test first" "$dir/takeover_candidates.txt" 25
    section "NUCLEI CRITICAL/HIGH — confirm manually" "$dir/nuclei_critical.txt" 40
    section "DIR FUZZ HITS" "$dir/dir_fuzz_results.txt" 30
    section "RECURSIVE DEEP FUZZ" "$dir/recursive_fuzz_results.txt" 30
    section "API FUZZ HITS" "$dir/api_fuzz_results.txt" 25
    section "LFI PROBES (verify manually)" "$dir/lfi_fuzz_results.txt" 15
    section "VHOST FUZZ HITS" "$dir/vhost_fuzz_results.txt" 25
    section "SENSITIVE PATHS" "$dir/sensitive_paths.txt" 30
    section "SSRF CANDIDATES → Burp" "$dir/params_ssrf.txt" 25
    section "OPEN REDIRECT CANDIDATES" "$dir/params_redirect.txt" 25
    section "SQLi CANDIDATES" "$dir/params_sqli.txt" 25
    section "IDOR CANDIDATES" "$dir/params_idor.txt" 25
    section "SENSITIVE URLs → Burp" "$dir/sensitive_urls.txt" 40
    section "PRIORITY HOSTS" "$dir/priority_hosts.txt" 25
    section "SECRETS — validate before report" "$dir/secrets.txt" 15

    echo "=== ALL OUTPUT FILES ==="
    ls -1 "$dir"/*.txt 2>/dev/null | sed 's/^/  /'
    echo ""
    echo "=== MANUAL TESTING ORDER ==="
    echo "  1. subdomains_new.txt + interesting_ports.txt + takeover_candidates.txt"
    echo "  2. nuclei_critical.txt → confirm each"
    echo "  3. js_endpoints.txt + secrets.txt"
    echo "  3. sensitive_paths.txt + dir_fuzz_results.txt + api_fuzz_results.txt"
    echo "  4. params_ssrf.txt + params_redirect.txt + params_sqli.txt"
    echo "  5. sensitive_urls.txt → import to Burp"
    echo "  6. priority_hosts.txt → auth/API testing"
    echo "  7. urls.txt full review"
    echo "  8. nmap_results.txt unusual services"
    echo "================================================================"
  } >"$report"
}

run_target() {
  local target="$1"
  target="$(echo "$target" | tr '[:upper:]' '[:lower:]' | xargs)"
  [ -n "$target" ] || return 0

  local dir="${OUTPUT_BASE}/${target}"
  mkdir -p "$dir/.tmp"

  if should_skip "$dir"; then
    log "[$target] Skipping — scanned <24h ago (drop --resume to force)"
    return 0
  fi

  log "========== START: $target → $dir =========="
  local start; start=$(date +%s)

  phase_subdomains "$target" "$dir"
  phase_scope_filter "$target" "$dir"
  phase_dnsx "$target" "$dir"
  phase_permutations "$target" "$dir"
  phase_dnsx "$target" "$dir"
  phase_live_and_ports "$target" "$dir"
  phase_urls "$target" "$dir"
  phase_js_mining "$target" "$dir"
  phase_cloud_buckets "$target" "$dir"
  phase_params "$target" "$dir"
  phase_ffuf "$target" "$dir"
  phase_cewl "$target" "$dir"
  phase_recursive_ffuf "$target" "$dir"
  phase_lfi_probe "$target" "$dir"
  phase_sensitive_paths "$target" "$dir"
  phase_takeover "$target" "$dir"
  phase_nuclei "$target" "$dir"
  phase_secrets "$target" "$dir"
  write_report "$target" "$dir"

  local elapsed=$(( $(date +%s) - start ))
  log "========== DONE: $target (${elapsed}s) → $dir/REPORT_${target}.txt =========="
  rm -rf "$dir/.tmp" 2>/dev/null || true
}

run_cycle() {
  log "=== Cycle: ${#TARGETS[@]} target(s) ==="
  for t in "${TARGETS[@]}"; do
    run_target "$t"
    sleep "$SLEEP_BETWEEN_TARGETS"
  done
  log "=== Cycle complete ==="
}

parse_args "$@"
mkdir -p "$OUTPUT_BASE" "$WORDLISTS_DIR"

if [ "$DAEMON" -eq 1 ]; then
  log "Daemon — loop every ${LOOP_HOURS}h | Targets: ${TARGETS[*]}"
  while true; do
    run_cycle
    log "Sleeping ${LOOP_HOURS}h..."
    sleep "$(( LOOP_HOURS * 3600 ))"
  done
else
  run_cycle
fi
