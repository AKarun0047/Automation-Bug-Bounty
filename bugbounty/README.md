# Bug Bounty Program Registry

One folder per program. Fail-closed scope — only `scope.txt` roots + subdomains are probed.

## Layout

```
bugbounty/
├── programs/
│   └── justeat/
│       ├── program.yaml
│       ├── scope.txt
│       ├── out-of-scope.txt
│       └── runs/20260616/    # recon output per date
├── resolvers.txt
└── wordlists/
```

## Run one program

```bash
python -m recon --config bugbounty/programs/justeat/program.yaml  # legacy path
# OR via registry loader:
python -c "
from pathlib import Path
from recon.program import load_program
from recon.runner import run_program
p = load_program(Path('bugbounty/programs/justeat'))
run_program(p)
"
```

## Run all programs (max 2 parallel)

```bash
python run-all.py --programs-dir bugbounty/programs --parallel 2
```

## Refresh scope weekly

```bash
export BUGCROWD_TOKEN=...
export HACKERONE_TOKEN=...
./scripts/refresh-scope.sh
```

## Scope safety

- `strict_scope: true` automatically for all `program.yaml` loads
- `assert_in_scope()` raises `ScopeViolation` on any non-provable host
- Rejected subdomains logged to `phase1_assets/scope_rejected.txt`
- Set `mode: passive` per program; use `forbid_active: true` as hard kill-switch

## Scaling path

1. **Now**: one folder per program + fail-closed gate
2. **5+ programs**: `refresh-scope.sh` + `run-all.py`
3. **20+ programs**: VPS + cron + webhook + diff mode (`DUMP.md` NEW section)
