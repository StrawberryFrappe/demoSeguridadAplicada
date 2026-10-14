#!/usr/bin/env bash
# Cambia el modo de la demo entre 'vuln' y 'fixed' y reinicia las apps.
# Se instala en la VM victima como /usr/local/bin/toggle-mode.
set -euo pipefail

MODE="${1:-}"
if [ "$MODE" != "vuln" ] && [ "$MODE" != "fixed" ]; then
  echo "uso: toggle-mode vuln|fixed"
  exit 1
fi

sed -i "s/^DEMO_MODE=.*/DEMO_MODE=$MODE/" /etc/demo.env
systemctl restart cola penguin
echo "modo actual: $MODE  (cola + penguin reiniciados)"
