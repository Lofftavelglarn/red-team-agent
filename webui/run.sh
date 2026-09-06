#!/usr/bin/env bash
# Запуск веб-консоли red-team-agent через venv проекта (нужен пакет redteam для каталога).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
PY="$REPO/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
PORT="${1:-8700}"
echo "→ http://127.0.0.1:$PORT"
exec "$PY" "$HERE/server.py" --port "$PORT"
