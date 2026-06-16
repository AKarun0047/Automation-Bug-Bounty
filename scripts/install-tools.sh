#!/usr/bin/env bash
# Install recon tool dependencies per recon-automation-spec.md
set -euo pipefail

echo "==> Installing ProjectDiscovery tools via pdtm..."
if ! command -v pdtm &>/dev/null; then
  go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
  export PATH="${PATH}:$(go env GOPATH)/bin"
fi
# -ia = install all PD tools; -ip = append ~/.pdtm/go/bin to PATH
pdtm -install-all -install-path

echo "==> Installing additional Go tools..."
go install github.com/bp0lr/gauplus@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# gauplus is not managed by pdtm — symlink into tools_path for recon to find it
PDTM_BIN="${HOME}/.pdtm/go/bin"
mkdir -p "$PDTM_BIN"
if command -v gauplus &>/dev/null && [ ! -x "$PDTM_BIN/gauplus" ]; then
  ln -sf "$(command -v gauplus)" "$PDTM_BIN/gauplus"
fi
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/LukaSikic/subzy@latest
go install github.com/sensepost/gowitness@latest
go install github.com/tomnomnom/gf@latest

echo "==> Installing Python tools..."
pip3 install waymore arjun wafw00f

echo "==> Setting up gf patterns..."
if [ ! -d "$HOME/.gf" ]; then
  git clone https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf/"
fi

echo "==> Downloading resolvers..."
mkdir -p wordlists
curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o resolvers.txt

echo "==> Downloading subdomain wordlist..."
curl -fsSL \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
  -o wordlists/subdomains-top1m.txt

echo "==> Installing Python package deps..."
pip3 install -r requirements.txt

echo "Done. Ensure ~/.pdtm/go/bin is on your PATH."
