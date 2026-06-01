#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PBX Dashboard — однострочная установка с GitHub
#
# Запуск:
#   bash <(curl -fsSL https://raw.githubusercontent.com/ТВОЙ_НИК/pbx-dashboard/main/setup.sh)
# ─────────────────────────────────────────────────────────────────────────────
set -e

# ── Настройки — ЗАМЕНИ на свой GitHub ник ────────────────────────────────────
GITHUB_USER="phragmenth"
GITHUB_REPO="PBX_dashboard"
GITHUB_BRANCH="main"
# ─────────────────────────────────────────────────────────────────────────────

GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}"
TMP="/tmp/pbx-dashboard-setup-$$"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
info() { echo -e "${YELLOW}  ▸${NC} $1"; }
err()  { echo -e "${RED}  ✗${NC} $1"; exit 1; }

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   PBX Dashboard — загрузка с GitHub  ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

[ "$EUID" -eq 0 ] || err "Запустите от root"
command -v curl &>/dev/null || err "curl не найден: apt-get install -y curl"

info "Скачиваем файлы из GitHub..."
mkdir -p "$TMP/static"

FILES=(
    "app.py"
    "install.sh"
    "requirements.txt"
)

for f in "${FILES[@]}"; do
    curl -fsSL "${GITHUB_RAW}/${f}" -o "${TMP}/${f}" \
        || err "Не удалось скачать ${f} — проверь что репозиторий публичный"
done

curl -fsSL "${GITHUB_RAW}/static/index.html" -o "${TMP}/static/index.html" \
    || err "Не удалось скачать static/index.html"

ok "Файлы загружены"

chmod +x "${TMP}/install.sh"
cd "$TMP" && bash install.sh

# Чистим временную папку
rm -rf "$TMP"
