#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PBX Dashboard — установщик
# Запускать от root на сервере с FreePBX (Debian/Ubuntu):
#   bash install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

INSTALL_DIR="/opt/pbx-dashboard"
PORT=8080
SERVICE="pbx-dashboard"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
err()  { echo -e "${RED}  ✗${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}  ▸${NC} $1"; }

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║     PBX Dashboard — установка        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

[ "$EUID" -eq 0 ] || err "Запустите скрипт от root"

# ── 1. Python и pip ───────────────────────────────────────────────────────────
info "Шаг 1/4 — Python-зависимости"

command -v python3 &>/dev/null || err "python3 не найден"
ok "python3: $(python3 --version)"

# Устанавливаем pip через apt если не установлен
python3 -m pip --version &>/dev/null 2>&1 || {
    info "  pip не найден — устанавливаем через apt..."
    apt-get install -y python3-pip -qq 2>/dev/null || true
}

# Используем python3 -m pip — работает всегда независимо от PATH
PIP="python3 -m pip"

$PIP install \
    fastapi \
    "uvicorn[standard]" \
    mysql-connector-python \
    --break-system-packages \
    --quiet 2>/dev/null \
|| $PIP install \
    fastapi \
    "uvicorn[standard]" \
    mysql-connector-python \
    --quiet

ok "Python-пакеты установлены"

# ── 2. Файлы ──────────────────────────────────────────────────────────────────
info "Шаг 2/4 — Копирование файлов в $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/static"
cp app.py            "$INSTALL_DIR/app.py"
cp static/index.html "$INSTALL_DIR/static/index.html"
ok "Файлы скопированы"

# ── 3. Systemd ────────────────────────────────────────────────────────────────
info "Шаг 3/4 — Настройка systemd"

cat > /etc/systemd/system/${SERVICE}.service << EOF
[Unit]
Description=FreePBX Monitoring Dashboard
After=network.target asterisk.service mariadb.service mysql.service
Wants=asterisk.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --quiet $SERVICE
ok "Systemd unit создан"

# ── 4. Запуск ─────────────────────────────────────────────────────────────────
info "Шаг 4/4 — Запуск сервиса"
systemctl restart $SERVICE
sleep 3

if systemctl is-active --quiet $SERVICE; then
    ok "Сервис запущен"
else
    echo "  Лог ошибок:"
    journalctl -u $SERVICE -n 15 --no-pager
    exit 1
fi

IP=$(hostname -I | awk '{print $1}')
echo ""
echo "  ╔════════════════════════════════════════════════╗"
echo "  ║  Установка завершена!                          ║"
echo "  ║                                                ║"
echo "  ║  Dashboard: http://${IP}:${PORT}        ║"
echo "  ╚════════════════════════════════════════════════╝"
echo ""
echo "  journalctl -u $SERVICE -f   — логи в реальном времени"
echo ""
