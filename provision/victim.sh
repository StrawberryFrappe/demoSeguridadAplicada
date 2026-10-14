#!/usr/bin/env bash
# Provisiona la VM victima: Python + Flask, certificado autofirmado, ambas apps
# como servicios systemd. Idempotente.
set -euo pipefail

VICTIM_IP="192.168.56.10"
SRC="/vagrant"               # carpeta del proyecto sincronizada por Vagrant
TLS_DIR="/opt/lab"

echo "[victim] instalando paquetes..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-flask openssl >/dev/null

echo "[victim] creando usuario de servicio 'demo'..."
id -u demo >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin demo

echo "[victim] generando certificado autofirmado para $VICTIM_IP..."
mkdir -p "$TLS_DIR"
if [ ! -f "$TLS_DIR/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
    -subj "/CN=$VICTIM_IP" -addext "subjectAltName=IP:$VICTIM_IP" >/dev/null 2>&1
fi
# la clave privada solo la lee el usuario de servicio
chown demo:demo "$TLS_DIR/key.pem" "$TLS_DIR/cert.pem"
chmod 600 "$TLS_DIR/key.pem"
chmod 644 "$TLS_DIR/cert.pem"

echo "[victim] desplegando apps..."
rm -rf /opt/cola /opt/penguin
cp -r "$SRC/cola" /opt/cola
cp -r "$SRC/penguin" /opt/penguin
# bases de datos frescas en cada aprovisionamiento
rm -f /opt/cola/cola.db /opt/penguin/penguin.db
# las apps corren como 'demo' y escriben su SQLite en estas carpetas
chown -R demo:demo /opt/cola /opt/penguin

echo "[victim] escribiendo /etc/demo.env..."
cat > /etc/demo.env <<EOF
DEMO_MODE=vuln
TLS_CERT=$TLS_DIR/cert.pem
TLS_KEY=$TLS_DIR/key.pem
EOF

echo "[victim] instalando servicios systemd..."
cp "$SRC/cola/cola.service" /etc/systemd/system/cola.service
cp "$SRC/penguin/penguin.service" /etc/systemd/system/penguin.service
cp "$SRC/scripts/toggle-mode.sh" /usr/local/bin/toggle-mode
chmod +x /usr/local/bin/toggle-mode
systemctl daemon-reload
systemctl enable --now cola penguin >/dev/null 2>&1
systemctl restart cola penguin

echo "[victim] listo."
echo "         cola (Broken Auth):  https://$VICTIM_IP:8000"
echo "         penguin (CSRF):      https://$VICTIM_IP:8001"
echo "         cambiar modo:        sudo toggle-mode vuln|fixed"
