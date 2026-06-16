# Autonomous Recon Automation

Multi-phase security reconnaissance orchestrator. Runs external recon tools sequentially and produces `DUMP.md` — structured output for vulnerability testing and PoC authoring.

## Quick Start

```bash
# Create virtualenv and install Python deps
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Install recon tools (ProjectDiscovery suite + others)
./scripts/install-tools.sh

# Configure target
cp recon.config.yaml my-target.yaml
# Edit: set target: "example.com"

# Run
python -m recon --config my-target.yaml
```

## Output

Results land in `recon-{target}-{date}/`:

- `DUMP.md` — paste this to Claude for PoC generation
- `dump.jsonl` — machine-readable summary
- `phase1_assets/` through `phase7_auth/` — per-phase artifacts

## Phases

| Phase | What it does |
|-------|----------------|
| 1 | Passive subdomain enum, DNS resolution, IP/ASN lookup, cloud buckets |
| 2 | Port scan, httpx fingerprint, screenshots, WAF detection |
| 3 | URL harvest (gau, waymore, katana), alive check |
| 4 | JS analysis, source maps, secrets (jsluice, trufflehog, nuclei) |
| 5 | Parameter classification (gf), arjun, wayback params |
| 6 | Nuclei scan, subzy takeover, actuator, header bypass |
| 7 | API surface, GraphQL, Swagger, CORS, auth endpoints |

## Config

See `recon.config.yaml` for all options. Key fields:

- `target` — single domain
- `scope_file` — one domain per line
- `auth_cookies` — enables authenticated katana crawl
- `shodan_api_key` — favicon hash → Shodan host search
- `webhook_url` — Slack/webhook notification on completion
- `resume: true` — skip phases in `.recon_state.json` (use `--no-resume` to restart)
- `phases.*` — toggle individual phases
- `out_of_scope_regex` — auto-exclude third-party hosts

## CLI

```bash
python -m recon --config recon.config.yaml
python -m recon -t example.com -v   # override target, verbose
```

## Requirements

External tools are invoked when present on `PATH` or in `tools_path`. Missing tools are skipped with a warning — phases degrade gracefully.

Install via `./scripts/install-tools.sh` or manually per `recon-automation-spec.md`.
