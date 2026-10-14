#!/usr/bin/env bash
# Provisiona la VM atacante: sirve las paginas de ataque en :9000 y deja
# hijack.sh disponible. Idempotente.
set -euo pipefail

SRC="/vagrant"

echo "[attacker] instalando paquetes..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 curl >/dev/null

echo "[attacker] desplegando paginas de ataque..."
rm -rf /opt/attacker
cp -r "$SRC/attacker" /opt/attacker
chmod +x /opt/attacker/hijack.sh

echo "[attacker] instalando servicio web (:9000)..."
cat > /etc/systemd/system/attacker.service <<'EOF'
[Unit]
Description=Sitio del atacante (CSRF)
After=network.target

[Service]
WorkingDirectory=/opt/attacker
ExecStart=/usr/bin/python3 -m http.server 9000
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now attacker >/dev/null 2>&1
systemctl restart attacker

echo "[attacker] listo."
echo "           sitio del atacante: http://192.168.56.11:9000"
echo "           robo de sesion:     cd /opt/attacker && ./hijack.sh <sid>"
