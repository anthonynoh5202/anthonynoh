#!/usr/bin/env bash
# =============================================================================
# 분석 워크스테이션 설치 스크립트 (Ubuntu 24.04 LTS 기준)
#
# 《취약점, 발견에서 조치까지》 제2편 기초 6장 "분석 환경 구축"과 함께 쓴다.
# 모듈별로 골라 설치한다. 여러 번 실행해도 안전하다(멱등).
#
#   sudo ./tools/setup-analyst.sh --base --web --binary --static     # 분석가 기본 세트
#   sudo ./tools/setup-analyst.sh --all                              # 전부
#   ./tools/setup-analyst.sh --check                                 # 설치 확인(권한 불필요)
#
# 모듈: --base --web --binary --static --mobile --cloud --firmware
# 옵션: --codeql (CodeQL CLI 번들, 약 1GB) --user <이름> (도구를 설치할 일반 사용자, 기본: SUDO_USER)
#
# 원칙
#  - 패키지 관리자(apt) → pipx → 공식 GitHub 릴리스 순서로 설치한다. 출처 불명 스크립트는 쓰지 않는다.
#  - GUI 도구(Burp Suite, Ghidra, ZAP)는 다운로드 위치만 안내하거나 공식 릴리스를 받는다.
#  - 네트워크는 HTTPS만 쓴다. 프록시가 있으면 https_proxy 환경변수를 존중한다.
# =============================================================================
set -euo pipefail
# 다운로드 실패는 경고만 내고 계속한다(각 다운로드는 || warn 으로 감싼다)

TARGET_USER="${SUDO_USER:-${USER:-root}}"
MODS=()
WITH_CODEQL=0
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
  a="$1"; shift
  case "$a" in
    --all) MODS=(base web binary static mobile cloud firmware) ;;
    --base|--web|--binary|--static|--mobile|--cloud|--firmware) MODS+=("${a#--}") ;;
    --codeql) WITH_CODEQL=1 ;;
    --check) CHECK_ONLY=1 ;;
    --user) TARGET_USER="$1"; shift ;;
    --user=*) TARGET_USER="${a#--user=}" ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션: $a"; exit 2 ;;
  esac
done

HOME_DIR=$(getent passwd "$TARGET_USER" | cut -d: -f6)
TOOLS_DIR="$HOME_DIR/tools"          # 릴리스 바이너리·Ghidra·jadx 등
VENV_DIR="$HOME_DIR/.venvs/analysis"  # pwntools 등 파이썬 라이브러리
BIN_DIR="$HOME_DIR/.local/bin"
log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '   \033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[1;33m!\033[0m %s\n' "$*"; }
as_user() { sudo -u "$TARGET_USER" -H env PATH="$BIN_DIR:$PATH" "$@"; }
need_root() { [[ $EUID -eq 0 ]] || { echo "설치는 sudo로 실행한다: sudo $0 ..."; exit 1; }; }
gh_latest_asset() {  # gh_latest_asset <owner/repo> <정규식>  → 다운로드 URL (실패 시 빈 문자열)
  curl -fsSL --max-time 30 "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
    | grep -oE '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 | grep -E "$2" | head -1 || true
}

# ---------------------------------------------------------------- check
if [[ $CHECK_ONLY -eq 1 ]]; then
  export PATH="$BIN_DIR:$HOME_DIR/tools/bin:$PATH"
  chk() { if command -v "$1" >/dev/null 2>&1; then ok "$1  $("$@" 2>&1 | head -1 | cut -c1-70)"; else warn "$1 없음"; fi; }
  log "기본";   chk git --version; chk docker --version; chk python3 --version; chk pipx --version; chk jq --version
  log "웹";     chk mitmproxy --version; chk sqlmap --version; chk ffuf -V; chk nuclei -version; chk httpx -version; chk nmap --version
  log "바이너리"; chk gdb --version; chk gcc --version; chk clang --version; chk afl-fuzz -h; chk radare2 -v; chk ROPgadget --version; chk ropper --version
  [[ -x "$VENV_DIR/bin/python" ]] && ok "pwntools  $("$VENV_DIR/bin/python" -c 'import pwn,sys;print(pwn.__version__)' 2>/dev/null)" || warn "pwntools venv 없음"
  [[ -d "$HOME_DIR/pwndbg" ]] && ok "pwndbg  $HOME_DIR/pwndbg" || warn "pwndbg 없음"
  ls -d "$TOOLS_DIR"/ghidra_* >/dev/null 2>&1 && ok "Ghidra  $(ls -d "$TOOLS_DIR"/ghidra_* | head -1)" || warn "Ghidra 없음"
  log "정적";   chk semgrep --version; chk codeql version
  log "모바일"; chk adb --version; chk apktool --version; chk jadx --version; chk frida --version; chk objection version
  log "클라우드"; chk aws --version; chk trivy --version; chk checkov --version
  log "펌웨어"; chk binwalk --help; chk unsquashfs -v; chk qemu-system-arm --version
  exit 0
fi

need_root
[[ ${#MODS[@]} -gt 0 ]] || { echo "모듈을 하나 이상 지정한다. --help 참고"; exit 2; }
export DEBIAN_FRONTEND=noninteractive
has() { printf '%s\n' "${MODS[@]}" | grep -qx "$1"; }
mkdir -p "$TOOLS_DIR/bin" "$BIN_DIR"; chown -R "$TARGET_USER" "$TOOLS_DIR" "$HOME_DIR/.local" 2>/dev/null || true

# ---------------------------------------------------------------- base
if has base; then
  log "base: 빌드 도구, Python, pipx, Docker"
  apt-get update -qq
  apt-get install -y -qq build-essential git curl wget unzip zip jq tmux vim file tree \
    python3 python3-pip python3-venv pipx net-tools dnsutils openssl ca-certificates >/dev/null
  if ! command -v docker >/dev/null; then
    apt-get install -y -qq docker.io docker-compose-v2 >/dev/null
  fi
  usermod -aG docker "$TARGET_USER" 2>/dev/null && ok "$TARGET_USER 를 docker 그룹에 추가 (재로그인 필요)"
  as_user pipx ensurepath >/dev/null 2>&1 || true
  ok "base 완료"
fi

# ---------------------------------------------------------------- web
if has web; then
  log "web: 프록시, 스캐너, 퍼저"
  apt-get update -qq
  apt-get install -y -qq nmap sqlmap ffuf nikto whatweb >/dev/null
  as_user pipx install --force mitmproxy >/dev/null 2>&1 && ok "mitmproxy (pipx)"
  for t in nuclei httpx; do
    url=$(gh_latest_asset "projectdiscovery/$t" "${t}_[0-9.]+_linux_amd64\.zip$")
    [[ -n "$url" ]] && { curl -fsSL "$url" -o "/tmp/$t.zip" && unzip -oq "/tmp/$t.zip" "$t" -d "$TOOLS_DIR/bin" && chmod +x "$TOOLS_DIR/bin/$t" && ok "$t ($url)"; } || warn "$t 다운로드 실패"
  done
  warn "Burp Suite Community: https://portswigger.net/burp/communitydownload 에서 설치 파일을 받아 실행한다"
  warn "OWASP ZAP: https://www.zaproxy.org/download/ (또는 docker: ghcr.io/zaproxy/zaproxy:stable)"
  ok "web 완료"
fi

# ---------------------------------------------------------------- binary
if has binary; then
  log "binary: 컴파일러, 디버거, pwndbg, pwntools, AFL++, radare2, Ghidra"
  apt-get update -qq
  apt-get install -y -qq gdb gdb-multiarch gcc g++ clang lld lldb make cmake nasm \
    binutils elfutils patchelf strace ltrace hexedit xxd \
    afl++ radare2 qemu-user qemu-user-static qemu-system-x86 \
    openjdk-21-jdk >/dev/null
  # pwndbg: 공식 저장소 + setup.sh
  if [[ ! -d "$HOME_DIR/pwndbg" ]]; then
    as_user git clone -q https://github.com/pwndbg/pwndbg "$HOME_DIR/pwndbg"
    (cd "$HOME_DIR/pwndbg" && as_user ./setup.sh >/dev/null 2>&1) && ok "pwndbg 설치 (~/.gdbinit 갱신)" || warn "pwndbg setup.sh 실패: $HOME_DIR/pwndbg 에서 직접 실행"
  else ok "pwndbg 이미 있음"; fi
  # pwntools 등 파이썬 라이브러리는 전용 venv
  as_user python3 -m venv "$VENV_DIR"
  as_user "$VENV_DIR/bin/pip" install -q --upgrade pip pwntools ropper ROPgadget capstone unicorn keystone-engine >/dev/null 2>&1 \
    && ok "pwntools/ropper/ROPgadget → $VENV_DIR (source $VENV_DIR/bin/activate)"
  for b in pwn ROPgadget ropper checksec; do ln -sf "$VENV_DIR/bin/$b" "$BIN_DIR/$b" 2>/dev/null || true; done
  # Ghidra: 공식 GitHub 릴리스 zip
  if ! ls -d "$TOOLS_DIR"/ghidra_* >/dev/null 2>&1; then
    url=$(gh_latest_asset "NationalSecurityAgency/ghidra" 'ghidra_[0-9.]+_PUBLIC_[0-9]+\.zip$')
    if [[ -n "$url" ]]; then
      curl -fsSL "$url" -o /tmp/ghidra.zip && as_user unzip -oq /tmp/ghidra.zip -d "$TOOLS_DIR" && ok "Ghidra → $(ls -d "$TOOLS_DIR"/ghidra_*) (실행: ghidraRun). 요구 JDK 버전은 해당 릴리스의 README로 확인"
    else warn "Ghidra 다운로드 실패: https://github.com/NationalSecurityAgency/ghidra/releases"; fi
  else ok "Ghidra 이미 있음"; fi
  ok "binary 완료"
fi

# ---------------------------------------------------------------- static
if has static; then
  log "static: Semgrep, (선택) CodeQL"
  as_user pipx install --force semgrep >/dev/null 2>&1 && ok "semgrep (pipx)"
  if [[ $WITH_CODEQL -eq 1 ]]; then
    url=$(gh_latest_asset "github/codeql-action" 'codeql-bundle-linux64\.tar\.(gz|zst)$')
    if [[ -n "$url" ]]; then
      curl -fsSL "$url" -o /tmp/codeql-bundle.tar.xx
      case "$url" in *.zst) as_user tar --zstd -xf /tmp/codeql-bundle.tar.xx -C "$TOOLS_DIR" ;; *) as_user tar -xzf /tmp/codeql-bundle.tar.xx -C "$TOOLS_DIR" ;; esac
      ln -sf "$TOOLS_DIR/codeql/codeql" "$BIN_DIR/codeql" && ok "CodeQL CLI 번들 → $TOOLS_DIR/codeql"
    else warn "CodeQL 번들 다운로드 실패"; fi
  else warn "CodeQL CLI는 --codeql 옵션으로 설치(약 1GB)"; fi
  ok "static 완료"
fi

# ---------------------------------------------------------------- mobile
if has mobile; then
  log "mobile: adb, apktool, jadx, Frida, objection"
  apt-get update -qq
  apt-get install -y -qq android-tools-adb android-tools-fastboot apktool openjdk-21-jre >/dev/null
  url=$(gh_latest_asset "skylot/jadx" 'jadx-[0-9.]+\.zip$')
  [[ -n "$url" ]] && { curl -fsSL "$url" -o /tmp/jadx.zip && as_user mkdir -p "$TOOLS_DIR/jadx" && as_user unzip -oq /tmp/jadx.zip -d "$TOOLS_DIR/jadx" && ln -sf "$TOOLS_DIR/jadx/bin/jadx" "$BIN_DIR/jadx" && ln -sf "$TOOLS_DIR/jadx/bin/jadx-gui" "$BIN_DIR/jadx-gui" && ok "jadx → $TOOLS_DIR/jadx"; } || warn "jadx 다운로드 실패"
  as_user pipx install --force frida-tools >/dev/null 2>&1 && ok "frida-tools (pipx)"
  as_user pipx install --force objection >/dev/null 2>&1 && ok "objection (pipx)"
  warn "Android 에뮬레이터는 Android Studio(https://developer.android.com/studio)로 설치한다. 실기기는 개발자 옵션 → USB 디버깅"
  ok "mobile 완료"
fi

# ---------------------------------------------------------------- cloud
if has cloud; then
  log "cloud: AWS CLI, Trivy, Checkov"
  as_user pipx install --force awscli >/dev/null 2>&1 && ok "awscli (pipx)"
  as_user pipx install --force checkov >/dev/null 2>&1 && ok "checkov (pipx)"
  url=$(gh_latest_asset "aquasecurity/trivy" 'trivy_[0-9.]+_Linux-64bit\.deb$')
  [[ -n "$url" ]] && { curl -fsSL "$url" -o /tmp/trivy.deb && apt-get install -y -qq /tmp/trivy.deb >/dev/null && ok "trivy (deb)"; } || warn "trivy 다운로드 실패"
  ok "cloud 완료"
fi

# ---------------------------------------------------------------- firmware
if has firmware; then
  log "firmware: binwalk, squashfs, QEMU 시스템 에뮬레이터"
  apt-get update -qq
  apt-get install -y -qq binwalk squashfs-tools qemu-system-arm qemu-system-mips qemu-utils \
    device-tree-compiler mtd-utils >/dev/null
  warn "EMBA(펌웨어 자동 분석)는 전용 VM 권장: https://github.com/e-m-b-a/emba"
  ok "firmware 완료"
fi

log "완료. 새 셸에서 ./tools/setup-analyst.sh --check 로 확인한다. PATH에 $BIN_DIR 과 $TOOLS_DIR/bin 이 있어야 한다:"
echo "   echo 'export PATH=\"$BIN_DIR:$TOOLS_DIR/bin:\$PATH\"' >> $HOME_DIR/.bashrc"
