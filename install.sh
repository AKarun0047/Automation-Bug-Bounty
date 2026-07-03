#!/usr/bin/env bash
# Install all tools for recon-all.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
PDTM_BIN="${HOME}/.pdtm/go/bin"
GO_BIN="$(go env GOPATH)/bin"
export PATH="${PATH}:${GO_BIN}:${PDTM_BIN}:${HOME}/.local/bin"

mkdir -p "$PDTM_BIN" "$WORDLISTS_DIR"

echo "==> ProjectDiscovery (pdtm)..."
if ! command -v pdtm &>/dev/null; then
  go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
fi
pdtm -install subfinder httpx nuclei naabu katana uncover dnsx notify mapcidr asnmap chaos 2>/dev/null || pdtm -install-all

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
go install github.com/sensepost/gowitness@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/g0ldencybersec/gungnir@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/tomnomnom/anew@latest

echo "==> LinkFinder (JS endpoints)..."
mkdir -p "${SCRIPT_DIR}/tools"
if [ ! -d "${SCRIPT_DIR}/tools/LinkFinder" ]; then
  git clone --depth 1 https://github.com/GerbenJavado/LinkFinder "${SCRIPT_DIR}/tools/LinkFinder" 2>/dev/null || true
  pip3 install --user -r "${SCRIPT_DIR}/tools/LinkFinder/requirements.txt" 2>/dev/null || true
fi

echo "==> Kiterunner (Swagger-aware API fuzzer)..."
if ! command -v kr &>/dev/null; then
  KR_VERSION="2.0.2"
  KR_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  KR_ARCH="$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
  curl -fsSL "https://github.com/assetnote/kiterunner/releases/download/v${KR_VERSION}/kiterunner_${KR_VERSION}_${KR_OS}_${KR_ARCH}.tar.gz" \
    -o /tmp/kr.tar.gz && tar xzf /tmp/kr.tar.gz -C "${GO_BIN}" kr && rm /tmp/kr.tar.gz 2>/dev/null || echo "  WARN: kiterunner install failed — install manually"
fi

echo "==> Kiterunner wordlist..."
fetch_wl "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz" "${WORDLISTS_DIR}/routes-large.kite.tar.gz"
[ -f "${WORDLISTS_DIR}/routes-large.kite.tar.gz" ] && [ ! -f "${WORDLISTS_DIR}/routes-large.kite" ] \
  && tar xzf "${WORDLISTS_DIR}/routes-large.kite.tar.gz" -C "${WORDLISTS_DIR}" 2>/dev/null || true

echo "==> TruffleHog + Gitleaks (GitHub secret scanning)..."
go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null || echo "  WARN: trufflehog install failed"
go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null || echo "  WARN: gitleaks install failed"

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
