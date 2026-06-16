# Autonomous Recon Automation — Spec

**Goal:** Run against a domain → produce structured output that gives a human or AI enough context to test for vulnerabilities and write working PoCs. No manual steps.

**Output philosophy:** Every finding includes raw HTTP request + response sample where possible. AI needs real data, not summaries.

---

## Architecture

```
INPUT: domain / scope file
    │
    ├── Phase 1: Asset Discovery          → subdomains.txt, ips.txt, asns.txt
    ├── Phase 2: HTTP Probe + Fingerprint → assets.jsonl, screenshots/
    ├── Phase 3: URL Harvesting           → urls_raw.txt, urls_clean.txt
    ├── Phase 4: JS Analysis + Secrets    → js_endpoints.jsonl, secrets.jsonl
    ├── Phase 5: Parameter Discovery      → params_classified.jsonl
    ├── Phase 6: Vulnerability Scan       → nuclei_findings.jsonl, takeovers.txt
    ├── Phase 7: Auth + API Surface       → api_surface.jsonl, auth_endpoints.jsonl
    │
    └── SYNTHESIS: DUMP.md + dump.jsonl   ← paste this to Claude
```

All phases run sequentially. Within each phase, tools run in parallel where output is independent.

---

## Config

```yaml
# recon.config.yaml
target: ""                    # single domain OR path to scope file
scope_file: ""                # one domain per line
out_dir: "./recon-{TARGET}-{DATE}"
threads: 50
rate_limit: 150               # requests/sec global cap
resolvers: "./resolvers.txt"  # public DNS resolvers list
wordlist_subdomains: "./wordlists/subdomains-top1m.txt"
auth_cookies: ""              # "Cookie: session=abc123" — for authenticated crawl
burp_collab: ""               # interactsh or burp collab URL for OOB
tools_path: "~/.pdtm/go/bin"

# Scope rules
in_scope_regex: []            # whitelist regex patterns
out_of_scope_regex:           # auto-exclude these
  - ".*\\.s3\\.amazonaws\\.com"
  - ".*\\.cloudfront\\.net"
  - ".*stripe\\.com"
  - ".*salesforce\\.com"

# Phase toggles (skip phases you don't need)
phases:
  asset_discovery: true
  http_probe: true
  url_harvest: true
  js_analysis: true
  param_discovery: true
  vuln_scan: true
  auth_surface: true
  screenshots: true
```

---

## Phase 1 — Asset Discovery

**Goal:** Enumerate every subdomain. Resolve to IPs. Expand via permutations. Filter wildcards.

### Tools & Commands

```bash
# 1a. Passive subdomain enum (run all in parallel)
subfinder -d $TARGET -all -recursive -silent -o passive/subfinder.txt
amass enum -passive -d $TARGET -o passive/amass.txt
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > passive/crtsh.txt
curl -s "https://api.hackertarget.com/hostsearch/?q=${TARGET}" | cut -d',' -f1 > passive/hackertarget.txt
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns" | jq -r '.passive_dns[].hostname' > passive/otx.txt

# 1b. Merge + dedup
cat passive/*.txt | sort -u | grep -E "\.${TARGET}$" > subdomains_raw.txt

# 1c. Permutation expansion
cat subdomains_raw.txt | alterx -enrich -o permutations.txt

# 1d. DNS resolution + wildcard filter
puredns resolve permutations.txt -r $RESOLVERS --wildcard-tests 5 -o subdomains_resolved.txt -w wildcards.txt

# 1e. Final merge
cat subdomains_raw.txt subdomains_resolved.txt | sort -u > subdomains.txt

# 1f. IP extraction + ASN lookup
cat subdomains.txt | dnsx -a -resp-only -silent | sort -u > ips.txt
# For each IP: curl ipinfo.io/$IP/org >> asns.txt
```

### Output Schema

```
subdomains.txt      — one subdomain per line, resolved
ips.txt             — unique IPs
asns.txt            — IP | ASN | Org
wildcards.txt       — wildcard domains (flag — subdomain takeover irrelevant here)
```

### Commonly Missed

- `*.internal.target.com` wildcard catching real subdomains — always test wildcard domains separately
- `_dmarc`, `_acme-challenge` TXT records → reveal cloud providers and subdomains in use

---

## Phase 2 — HTTP Probe + Fingerprint

**Goal:** For every live host: status, title, tech stack, open ports, CDN presence, redirect chain, favicon hash, WAF detection.

### Tools & Commands

```bash
# 2a. Port scan (top 1000 + common app ports)
cat subdomains.txt | naabu -p 80,443,8080,8443,3000,3001,4000,4443,5000,8000,8008,8888,9000,9090,9200,9443 -silent -json -o ports.jsonl

# 2b. Build URL list from port scan output
cat ports.jsonl | jq -r '"http://\(.ip):\(.port)"' >> urls_to_probe.txt
cat subdomains.txt | httpx -probe -silent | grep "^http" >> urls_to_probe.txt

# 2c. Full HTTP fingerprint
cat urls_to_probe.txt | httpx \
  -title -status-code -tech-detect \
  -ip -cdn -location -server \
  -favicon -hash sha256 \
  -ports 80,443,8080,8443,3000,8000 \
  -follow-redirects -max-redirects 5 \
  -response-size-limit 2mb \
  -json -o assets.jsonl

# 2d. Screenshots
gowitness file -f urls_to_probe.txt -P screenshots/ --timeout 10

# 2e. WAF detection (nmap scripts or wafw00f)
cat subdomains.txt | while read h; do wafw00f https://$h 2>/dev/null; done > waf_detection.txt
```

### Output Schema — assets.jsonl (one object per host)

```jsonc
{
  "url": "https://admin.target.com",
  "status_code": 200,
  "title": "Admin Dashboard",
  "tech": ["React", "Nginx", "Cloudflare"],
  "ip": "1.2.3.4",
  "cdn": true,
  "cdn_name": "Cloudflare",
  "server": "nginx/1.18.0",
  "location": "",                    // redirect target if 3xx
  "redirect_chain": [],
  "favicon_hash": "-1234567890",     // use in Shodan: http.favicon.hash:-1234567890
  "waf": "Cloudflare",
  "screenshot": "screenshots/admin.target.com.png",
  "response_headers": {},            // full headers map
  "interesting": true,               // flag if: admin/dashboard/internal in URL, non-200 on sensitive path
  "notes": ""
}
```

### Interesting Host Signals (auto-flag these)

- URL contains: `admin`, `dashboard`, `internal`, `staging`, `dev`, `test`, `beta`, `api`, `portal`, `vpn`, `sso`, `auth`, `login`, `console`, `manage`, `backoffice`
- Status 403 on root — likely gated but exists
- Server header leaks version (e.g., `Apache/2.2.34`)
- No WAF detected on subdomain while main domain has WAF
- CDN = false on subdomains (direct IP, no WAF protection)
- Non-standard port (not 80/443) with web app running

---

## Phase 3 — URL Harvesting

**Goal:** Collect every URL ever associated with target — historical + live. This is the attack surface map.

### Tools & Commands

```bash
# 3a. Archive sources
gauplus --threads 10 --subs --blacklist ttf,woff,woff2,svg,png,jpg,jpeg,gif,ico,css --o urls_gau.txt -- $TARGET
waymore -i $TARGET -mode U -oU urls_waymore.txt

# 3b. Live crawl (with and without auth)
cat assets.jsonl | jq -r '.url' | katana \
  -jc -jsl -kf all \
  -d 5 -c 50 \
  -xhr -ef css,png,jpg,gif,ico,svg,woff,ttf \
  -json -o katana_crawl.jsonl

# Authenticated crawl (if auth_cookies set)
cat assets.jsonl | jq -r '.url' | katana \
  -jc -jsl -kf all \
  -d 5 -c 50 \
  -H "Cookie: ${AUTH_COOKIES}" \
  -json -o katana_auth_crawl.jsonl

# 3c. Merge + dedup + clean
cat urls_gau.txt urls_waymore.txt <(cat katana_crawl.jsonl | jq -r '.request.endpoint') | \
  sort -u | \
  grep -E "^https?://" | \
  grep -v -E "\.(css|png|jpg|jpeg|gif|ico|svg|woff|ttf|eot|mp4|mp3|pdf)$" | \
  uro > urls_clean.txt

# 3d. Alive check + status
cat urls_clean.txt | httpx -status-code -silent -json -o urls_with_status.jsonl
```

### Output Schema

```
urls_raw.txt              — all harvested URLs
urls_clean.txt            — deduped, filtered, uro-cleaned
urls_with_status.jsonl    — url | status | content-type | size
katana_crawl.jsonl        — full crawl data: request + response per URL
```

### What to Capture Per URL

```jsonc
{
  "url": "https://api.target.com/v1/users?id=123",
  "status": 200,
  "content_type": "application/json",
  "size": 2048,
  "source": "wayback",             // wayback | katana | gau
  "params": ["id"],
  "method": "GET",
  "auth_required": false,          // inferred from 401/403 on unauthed request
  "interesting": true
}
```

---

## Phase 4 — JS Analysis + Secret Scanning

**Goal:** Extract API endpoints, hardcoded secrets, auth tokens, internal URLs from JS bundles and source maps.

### Tools & Commands

```bash
# 4a. Extract JS file URLs from crawl data
cat katana_crawl.jsonl | jq -r 'select(.request.endpoint | endswith(".js")) | .request.endpoint' | sort -u > js_files.txt
cat urls_clean.txt | grep "\.js$" | sort -u >> js_files.txt
sort -u js_files.txt -o js_files.txt

# 4b. Check for source maps
cat js_files.txt | while read url; do
  map_url="${url}.map"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$status" = "200" ]; then
    echo "$map_url" >> source_maps_found.txt
  fi
done

# 4c. Endpoint + secret extraction from JS
cat js_files.txt | jsluice urls | jq . >> js_endpoints.jsonl
cat js_files.txt | jsluice secrets | jq . >> js_secrets_raw.jsonl

# 4d. Entropy-based secret scan via trufflehog
trufflehog github --org=$(echo $TARGET | cut -d'.' -f1) --only-verified --json > trufflehog_github.jsonl
# Also scan any downloaded JS files
trufflehog filesystem ./downloaded_js/ --json >> trufflehog_local.jsonl

# 4e. Nuclei secret pattern scan
nuclei -l js_files.txt -t exposures/tokens/ -t exposures/apis/ -json -o nuclei_js.jsonl

# 4f. Source map download + full source recovery
# If source_maps_found.txt non-empty: download + reconstruct with source-map-js or unwebpack
```

### Output Schema — secrets.jsonl

```jsonc
{
  "source_url": "https://app.target.com/static/js/main.abc123.js",
  "type": "AWS_ACCESS_KEY",          // type of secret
  "value": "AKIA...",                // raw value
  "verified": true,                  // trufflehog verified = credential works
  "detector": "AWSKeyID",
  "line": 4521,
  "context": "...apiKey: 'AKIA...'" // surrounding code snippet
}
```

### Output Schema — js_endpoints.jsonl

```jsonc
{
  "url": "/api/v2/admin/users",
  "source_file": "https://app.target.com/static/js/main.js",
  "kind": "endpoint",
  "method": "GET",                   // if determinable
  "params": ["page", "limit", "role"]
}
```

### Source Map Signal

If source map found → flag as CRITICAL INFO. Source maps expose:
- All route definitions
- Auth middleware location
- Business logic
- Hardcoded feature flags / admin endpoints
- Comment with internal tool names

---

## Phase 5 — Parameter Discovery

**Goal:** Classify every parameter by vulnerability type. Find hidden params not in any URL.

### Tools & Commands

```bash
# 5a. Classify harvested URLs by vuln type (gf patterns)
cat urls_clean.txt | gf sqli    | sort -u > params/sqli.txt
cat urls_clean.txt | gf ssrf    | sort -u > params/ssrf.txt
cat urls_clean.txt | gf idor    | sort -u > params/idor.txt
cat urls_clean.txt | gf xss     | sort -u > params/xss.txt
cat urls_clean.txt | gf lfi     | sort -u > params/lfi.txt
cat urls_clean.txt | gf rce     | sort -u > params/rce.txt
cat urls_clean.txt | gf ssti    | sort -u > params/ssti.txt
cat urls_clean.txt | gf redirect| sort -u > params/redirect.txt

# 5b. Hidden parameter discovery on interesting endpoints
# Take top endpoints from assets + crawl (avoid running on every URL — too slow)
cat assets.jsonl | jq -r 'select(.interesting == true) | .url' > endpoints_for_arjun.txt
cat endpoints_for_arjun.txt | while read url; do
  arjun -u "$url" -oJ "params/arjun_$(echo $url | md5sum | cut -c1-8).json" -t 20 -d 2
done

# 5c. Historical parameterized URLs from Wayback
curl -s "https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200" | \
  grep "?" | sort -u > params/wayback_params.txt

# 5d. Merge classified params
cat params/*.txt | sort -u > params_all.txt
```

### Output Schema — params_classified.jsonl

```jsonc
{
  "url": "https://app.target.com/search?q=test&redirect=/home",
  "params": [
    { "name": "q",        "vuln_class": "sqli",     "value_sample": "test" },
    { "name": "redirect", "vuln_class": "redirect",  "value_sample": "/home" }
  ],
  "source": "wayback",
  "status": 200,
  "id_type": null,         // "sequential" | "uuid" | "hash" | null
  "auth_required": false
}
```

### ID Type Detection

For any param named: `id`, `user_id`, `account_id`, `order_id`, `doc_id`, `uid`:
- Extract sample values from URLs
- Sequential integers → `"id_type": "sequential"` → high IDOR risk
- UUID format → `"id_type": "uuid"` → lower IDOR risk
- Encoded/hashed → `"id_type": "hash"` → medium (try decode)

---

## Phase 6 — Vulnerability Scan

**Goal:** Run nuclei against all live hosts. Find CNAME takeover candidates. Check default credentials. Flag known CVEs for detected tech.

### Tools & Commands

```bash
# 6a. Nuclei — broad scan
nuclei -l urls_to_probe.txt \
  -t cves/ \
  -t exposures/ \
  -t misconfigurations/ \
  -t takeovers/ \
  -t technologies/ \
  -t default-logins/ \
  -t network/ \
  -severity critical,high,medium \
  -rate-limit 100 \
  -bulk-size 25 \
  -c 25 \
  -json -o nuclei_findings.jsonl

# 6b. DAST fuzzing (only on params with user input — use gf output)
nuclei -l params/xss.txt  -t fuzzing/xss-reflected.yaml  -json >> nuclei_findings.jsonl
nuclei -l params/sqli.txt -t fuzzing/sqli.yaml            -json >> nuclei_findings.jsonl
nuclei -l params/ssrf.txt -t fuzzing/ssrf.yaml -interactsh-server $BURP_COLLAB -json >> nuclei_findings.jsonl

# 6c. CNAME takeover
subzy run --targets subdomains.txt --concurrency 50 --output takeovers.txt

# 6d. CVE mapping for detected tech
# Parse assets.jsonl for tech stack → lookup CPE → fetch recent CVEs
# For each tech found: query NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={TECH}
cat assets.jsonl | jq -r '.tech[]?' | sort -u | while read tech; do
  curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${tech}&resultsPerPage=5" >> cve_intel.jsonl
done

# 6e. Spring Boot actuator check
cat assets.jsonl | jq -r '.url' | while read url; do
  for ep in /actuator /actuator/env /actuator/heapdump /actuator/trace /actuator/mappings; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${url}${ep}")
    [ "$status" != "404" ] && echo "${url}${ep} → $status" >> actuator_exposed.txt
  done
done
```

### Output Schema — nuclei_findings.jsonl

```jsonc
{
  "template-id": "CVE-2021-44228",
  "info": {
    "name": "Apache Log4j RCE",
    "severity": "critical",
    "tags": ["cve", "rce", "log4j"]
  },
  "host": "https://app.target.com",
  "matched-at": "https://app.target.com/login",
  "extracted-results": ["10.0.0.1"],   // what nuclei pulled from response
  "request": "GET /login HTTP/1.1\n...",
  "response": "HTTP/1.1 200 OK\n...",
  "timestamp": "2025-06-16T10:00:00Z",
  "matcher-status": true
}
```

---

## Phase 7 — Auth + API Surface

**Goal:** Map every auth endpoint, OAuth flow, SSO provider, API version, and GraphQL schema. This is what attackers target first.

### Tools & Commands

```bash
# 7a. Extract API endpoints from all sources
cat katana_crawl.jsonl urls_with_status.jsonl js_endpoints.jsonl | \
  jq -r 'select(.url | test("/api/|/graphql|/v[0-9]+/|/rest/|/rpc")) | .url' | \
  sort -u > api_endpoints.txt

# 7b. Probe versioned APIs (v1 coexistence pattern)
cat api_endpoints.txt | grep "/v2/" | sed 's|/v2/|/v1/|g' | sort -u > api_v1_candidates.txt
cat api_v1_candidates.txt | httpx -status-code -json -o api_v1_probe.jsonl

# 7c. GraphQL introspection
cat api_endpoints.txt | grep -i "graphql" | while read url; do
  curl -s -X POST "$url" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name fields{name}}}}"}' >> graphql_introspection.jsonl
done

# 7d. OpenAPI / Swagger discovery
for path in /swagger.json /swagger-ui.html /api-docs /openapi.json /openapi.yaml /api/swagger /v2/api-docs; do
  cat assets.jsonl | jq -r '.url' | while read url; do
    status=$(curl -s -o swagger_found/"$(echo ${url}${path} | md5sum | cut -c1-8).json" -w "%{http_code}" "${url}${path}")
    [ "$status" = "200" ] && echo "${url}${path}" >> swagger_endpoints.txt
  done
done

# 7e. Auth endpoint mapping
cat urls_clean.txt | grep -iE "login|signin|oauth|token|auth|sso|saml|callback|authorize|logout|register|signup|reset|forgot" | \
  sort -u > auth_endpoints.txt

# 7f. CORS check on API endpoints
cat api_endpoints.txt | while read url; do
  result=$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: https://evil.com" "$url")
  acao=$(curl -s -I -H "Origin: https://evil.com" "$url" | grep -i "access-control-allow-origin")
  echo "$url | $result | $acao" >> cors_check.txt
done

# 7g. 403 header bypass on interesting endpoints
cat assets.jsonl | jq -r 'select(.status_code == 403) | .url' | while read url; do
  for header in "X-Original-URL: /" "X-Forwarded-For: 127.0.0.1" "X-Custom-IP-Authorization: 127.0.0.1" "X-Rewrite-URL: /" "X-Host: localhost"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -H "$header" "$url")
    [ "$status" != "403" ] && echo "BYPASS: $url via $header → $status" >> bypass_found.txt
  done
done
```

### Output Schema — api_surface.jsonl

```jsonc
{
  "url": "https://api.target.com/v1/users",
  "method": "GET",
  "auth_required": false,
  "status": 200,
  "content_type": "application/json",
  "params": ["page", "limit", "role"],
  "response_sample": "{\"users\":[{\"id\":1,\"email\":\"...\"",  // first 500 chars
  "id_type": "sequential",
  "version": "v1",
  "v2_exists": true,          // true if /v2/ equivalent found
  "cors_wildcard": false,
  "swagger_available": false
}
```

---

## Final Synthesis — DUMP.md

This file is what you paste to Claude (or any AI). Generated last, after all phases complete.

### DUMP.md Structure

```markdown
# Recon Dump: {TARGET}
Generated: {DATE} | Scope: {DOMAINS}

---

## 1. Target Overview

| Property | Value |
|----------|-------|
| Base domain | target.com |
| Total subdomains found | 142 |
| Live hosts | 87 |
| Total URLs | 14,832 |
| JS files | 234 |
| Open ports (non-standard) | 8080, 9090, 3000 |
| CDN | Cloudflare (most), direct IP on 3 subdomains |
| WAF | Cloudflare (main), none on staging.* |

## 2. Tech Stack (per host)

| Host | Framework | Server | CDN | WAF | Notes |
|------|-----------|--------|-----|-----|-------|
| app.target.com | React, Next.js | Nginx | Cloudflare | Yes | |
| api.target.com | Express, Node 18 | Nginx | No | No | Direct IP |
| admin.target.com | Django 3.2 | Gunicorn | No | No | 403 on root |
| staging.target.com | Rails 6.1 | Puma | No | No | No auth on /api/ |

## 3. Critical / High Findings

[Auto-populate from nuclei_findings.jsonl where severity = critical or high]

| Host | Finding | Template | Severity | Matched-At | PoC Request |
|------|---------|----------|----------|------------|-------------|
| api.target.com | Spring Boot Actuator Exposed | spring-actuator | HIGH | /actuator/env | `GET /actuator/env HTTP/1.1` |

## 4. Attack Surface — Interesting Endpoints

[Endpoints flagged as interesting from all phases]

| URL | Status | Auth? | Notes |
|-----|--------|-------|-------|
| https://admin.target.com/ | 403 | Yes | Header bypass candidates |
| https://api.target.com/v1/users | 200 | No | Sequential IDs, v2 auth missing in v1 |
| https://app.target.com/graphql | 200 | No | Introspection enabled |

## 5. Parameters by Vulnerability Class

### IDOR Candidates (sequential IDs)
[From params_classified.jsonl where id_type = sequential]

### SSRF Candidates
[From params/ssrf.txt]

### SQLi Candidates
[From params/sqli.txt]

### Open Redirect Candidates
[From params/redirect.txt]

## 6. Secrets Found

| Type | Value (partial) | Verified | Source File |
|------|----------------|----------|-------------|
| AWS Access Key | AKIA...XXXX | YES | main.abc123.js |

## 7. API Versions

| v2 Endpoint | v1 Exists? | v1 Auth Required? |
|-------------|-----------|------------------|
| /api/v2/users | YES | NO ← flag |

## 8. CORS Issues

| Endpoint | Origin: evil.com Accepted? | ACAO Header |
|----------|---------------------------|-------------|
| /api/v1/profile | YES | * |

## 9. CNAME Takeover Candidates

[From takeovers.txt]

## 10. Source Maps

[From source_maps_found.txt — these expose full source]

## 11. Auth Surface

| Endpoint | Provider | MFA? | Notes |
|----------|----------|------|-------|
| /oauth/authorize | Auth0 | Unknown | |
| /api/token | Custom JWT | No | |

## 12. Raw HTTP Samples (for PoC authoring)

[For each finding: include raw request + response]

### Sample: Admin Panel 403 Bypass Attempt
```http
GET /admin/ HTTP/1.1
Host: admin.target.com
X-Forwarded-For: 127.0.0.1

HTTP/1.1 403 Forbidden
```

### Sample: v1 API Unauthenticated
```http
GET /api/v1/users HTTP/1.1
Host: api.target.com

HTTP/1.1 200 OK
Content-Type: application/json
{"users":[{"id":1,"email":"user@target.com",...}]}
```

---

## Ask Claude

Paste this file and say:

> "Here is recon output for [target]. For each finding, write a working PoC HTTP request. Classify by severity. Identify any vulnerability chains. Flag what needs manual verification."
```

---

## Output File Map

```
recon-target-YYYYMMDD/
├── recon.config.yaml
├── DUMP.md                        ← paste this to Claude
├── dump.jsonl                     ← machine-readable version of DUMP.md
│
├── phase1_assets/
│   ├── subdomains.txt
│   ├── ips.txt
│   ├── asns.txt
│   └── wildcards.txt
│
├── phase2_http/
│   ├── assets.jsonl
│   ├── ports.jsonl
│   ├── waf_detection.txt
│   └── screenshots/
│
├── phase3_urls/
│   ├── urls_raw.txt
│   ├── urls_clean.txt
│   └── urls_with_status.jsonl
│
├── phase4_js/
│   ├── js_files.txt
│   ├── source_maps_found.txt
│   ├── js_endpoints.jsonl
│   └── secrets.jsonl
│
├── phase5_params/
│   ├── sqli.txt
│   ├── ssrf.txt
│   ├── idor.txt
│   ├── xss.txt
│   ├── lfi.txt
│   ├── rce.txt
│   ├── ssti.txt
│   ├── redirect.txt
│   ├── wayback_params.txt
│   └── params_classified.jsonl
│
├── phase6_vulns/
│   ├── nuclei_findings.jsonl
│   ├── takeovers.txt
│   ├── actuator_exposed.txt
│   ├── cve_intel.jsonl
│   └── bypass_found.txt
│
└── phase7_auth/
    ├── api_endpoints.txt
    ├── api_v1_probe.jsonl
    ├── api_surface.jsonl
    ├── graphql_introspection.jsonl
    ├── swagger_endpoints.txt
    ├── auth_endpoints.txt
    ├── cors_check.txt
    └── bypass_found.txt
```

---

## Dependencies

```bash
# ProjectDiscovery suite (most tools)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -ia -ip   # installs: subfinder, httpx, nuclei, naabu, katana, alterx, dnsx, etc.

# Others
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
pip3 install waymore
go install github.com/003random/getJS@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/ameenmaali/urldedupe@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
pip3 install arjun
pip3 install paramspider
go install github.com/LukaSikic/subzy@latest
go install github.com/sensepost/gowitness@latest
pip3 install wafw00f

# gf patterns
go install github.com/tomnomnom/gf@latest
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/

# Resolvers
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt

# Wordlists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt
```

---

## Gaps Checklist (implement these — commonly missed)

- [ ] **Authenticated crawl** — re-run katana with `-H "Cookie: ..."` for logged-in surface
- [ ] **v1/v2 diff check** — auto-probe `/api/v1/` when `/api/v2/` found; compare auth requirements
- [ ] **Favicon hash → Shodan** — use `httpx -favicon` hash to find same-org assets via Shodan `http.favicon.hash:`
- [ ] **Source map reconstruction** — if `.js.map` found, reconstruct original source with `source-map` npm package
- [ ] **CORS full check** — test both `Origin: https://evil.com` AND `Origin: null` AND `Origin: https://target.com.evil.com`
- [ ] **Rate limit probe** — test bulk requests on API endpoints (10 req/sec, no auth) — reveals unprotected endpoints
- [ ] **Cloud metadata via SSRF params** — for `?url=` / `?src=` params, auto-probe: `http://169.254.169.254/latest/meta-data/`
- [ ] **OAuth flow capture** — spider OAuth flows, capture `state` parameter, test for CSRF
- [ ] **HTTP request smuggling probe** — nuclei has templates for this: `-t http/request-smuggling/`
- [ ] **Host header injection** — test `Host: evil.com` on all endpoints; flag password reset endpoints
- [ ] **Cache poisoning probe** — add `X-Forwarded-Host: evil.com` to cacheable responses
- [ ] **Typosquat appspot domains** — for GAE targets, generate domain typos and probe `.appspot.com`

---

## Claude Prompt Template (paste with DUMP.md)

```
I'm doing authorized bug bounty testing on [TARGET]. Below is automated recon output.

For each finding:
1. Write exact PoC HTTP request (curl or raw HTTP)
2. Explain impact and CVSS score
3. Identify any vulnerability chain (e.g., IDOR → ATO)
4. Flag what needs manual verification to confirm exploitability

Focus on: [paste DUMP.md here]
```
