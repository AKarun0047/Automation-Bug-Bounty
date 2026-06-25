#!/usr/bin/env bash
# Install all tools for recon-all.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
PDTM_BIN="${HOME}/.pdtm/go/bin"
GO_BIN="$(go env GOPATH)/bin"
export PATH="${PATH}:${GO_BIN}:${PDTM_BIN}:${HOME}/.local/bin}"

mkdir -p "$PDTM_BIN" "$WORDLISTS_DIR"

echo "==> ProjectDiscovery (pdtm)..."
if ! command -v pdtm &>/dev/null; then
  go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
fi
pdtm -install subfinder httpx nuclei naabu katana uncover dnsx 2>/dev/null || pdtm -install-all

echo "==> Go tools..."
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/PentestPad/subzy@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/jaeles-project/gospider@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/Josue87/gotator@latest

echo "==> LinkFinder (JS endpoints)..."
mkdir -p "${SCRIPT_DIR}/tools"
if [ ! -d "${SCRIPT_DIR}/tools/LinkFinder" ]; then
  git clone --depth 1 https://github.com/GerbenJavado/LinkFinder "${SCRIPT_DIR}/tools/LinkFinder" 2>/dev/null || true
  pip3 install --user -r "${SCRIPT_DIR}/tools/LinkFinder/requirements.txt" 2>/dev/null || true
fi

echo "==> S3Scanner (cloud buckets, no AWS keys needed for probe)..."
if command -v pipx &>/dev/null; then
  pipx install 'git+https://github.com/sa7mon/S3Scanner.git' 2>/dev/null \
    || pipx upgrade s3scanner 2>/dev/null || true
else
  pip3 install --user 'git+https://github.com/sa7mon/S3Scanner.git' 2>/dev/null || true
fi

echo "==> gf patterns..."
if [ ! -d "${HOME}/.gf" ]; then
  git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "${HOME}/.gf"
fi

echo "==> Python tools..."
install_py() {
  if command -v pipx &>/dev/null; then
    pipx install "$1" 2>/dev/null || pipx upgrade "$1" 2>/dev/null || true
  else
    pip3 install --user "$1" 2>/dev/null || true
  fi
}
install_py waymore
install_py arjun
install_py uro

if command -v pipx &>/dev/null; then
  pipx install 'git+https://github.com/devanshbatham/ParamSpider.git' 2>/dev/null \
    || pipx upgrade paramspider 2>/dev/null || true
else
  pip3 install --user 'git+https://github.com/devanshbatham/ParamSpider.git' 2>/dev/null || true
fi

echo "==> Wordlists..."
SECLISTS="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
fetch_wl() {
  local url="$1" dest="$2"
  [ -f "$dest" ] && echo "  skip: $(basename "$dest")" && return
  echo "  fetch: $(basename "$dest")"
  curl -fsSL "$url" -o "$dest" || echo "  WARN: failed $(basename "$dest")"
}
# coffsec article: https://medium.com/@coffsec/10-recon-wordlists-every-pentester-must-know-484499d2ce9c
fetch_wl "${SECLISTS}/Discovery/Web-Content/common.txt" "${WORDLISTS_DIR}/dirs-common.txt"
fetch_wl "${SECLISTS}/Discovery/Web-Content/raft-large-directories.txt" "${WORDLISTS_DIR}/dirs-raft-large.txt"
fetch_wl "${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt" "${WORDLISTS_DIR}/vhost-5k.txt"
fetch_wl "${SECLISTS}/Discovery/DNS/dns-Jhaddix.txt" "${WORDLISTS_DIR}/permute-words.txt"
fetch_wl "${SECLISTS}/Discovery/DNS/subdomains-top1million-20000.txt" "${WORDLISTS_DIR}/vhost-subdomains-top100k.txt"
fetch_wl "${SECLISTS}/Discovery/DNS/subdomains-top1million-110000.txt" "${WORDLISTS_DIR}/subdomains-top110k.txt"
fetch_wl "${SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt" "${WORDLISTS_DIR}/api-endpoints.txt"
fetch_wl "${SECLISTS}/Fuzzing/LFI/LFI-Jhaddix.txt" "${WORDLISTS_DIR}/lfi-jhaddix.txt"
fetch_wl "${SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt" "${WORDLISTS_DIR}/params-burp.txt"
# #9 OneListForAll (short variant — full list is ~80MB)
fetch_wl "https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallshort.txt" "${WORDLISTS_DIR}/dirs-onelist.txt"

echo "==> System packages..."
if command -v apt &>/dev/null; then
  sudo apt install -y nmap jq cewl 2>/dev/null || true
fi

echo ""
echo "Done. Add to ~/.bashrc:"
echo "  export PATH=\"\${PATH}:${PDTM_BIN}:${GO_BIN}:\${HOME}/.local/bin\""
echo ""
echo "Run:  cd ${SCRIPT_DIR} && ./recon-all.sh target.com"
