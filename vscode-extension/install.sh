#!/usr/bin/env bash
# Устанавливает расширение Gemini (Cloudflare Worker) в VS Code без vsix:
# копирует распакованную папку в ~/.vscode/extensions и просит перезагрузить окно.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/gemini-worker-chat"
EXT_DIR="${VSCODE_EXTENSIONS_DIR:-$HOME/.vscode/extensions}"

PUBLISHER="$(python3 -c "import json;print(json.load(open('$SRC/package.json'))['publisher'])")"
NAME="$(python3 -c "import json;print(json.load(open('$SRC/package.json'))['name'])")"
VERSION="$(python3 -c "import json;print(json.load(open('$SRC/package.json'))['version'])")"
DEST="$EXT_DIR/$PUBLISHER.$NAME-$VERSION"

rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SRC"/. "$DEST"/

echo "✅ Установлено: $DEST"
echo "   Дальше: Command Palette → «Developer: Reload Window»"
echo "   Затем в списке моделей чата появится «Gemini (Cloudflare)»."
