#!/usr/bin/env bash
set -Eeuo pipefail
REPO=fckmachines/RealiTLScannerXXL
BASE="https://github.com/$REPO/releases/download"
DEST="${INSTALL_DIR:-/usr/local/bin}"
BIN=realitlscanner
fail(){ echo "Ошибка: $*" >&2; exit 1; }
command -v curl >/dev/null || fail "Требуется curl"
command -v sha256sum >/dev/null || fail "Требуется sha256sum"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) asset=realitlscanner-linux-amd64 ;;
  Linux:aarch64) asset=realitlscanner-linux-arm64 ;;
  *) fail "Поддерживается Linux x86_64/aarch64" ;;
esac
if (( EUID == 0 )); then sudo_cmd=(); else command -v sudo >/dev/null || fail "Требуется sudo"; sudo_cmd=(sudo); fi
case "${1:---update}" in
  --version) if [[ -x "$DEST/$BIN" ]]; then "$DEST/$BIN" --version; else echo "Не установлен"; fi; exit 0 ;;
  --uninstall) "${sudo_cmd[@]}" rm -f -- "$DEST/$BIN"; echo "Удалён $DEST/$BIN"; exit 0 ;;
  --update|--install) ;;
  *) fail "Использование: bash install.sh [--install|--update|--version|--uninstall]" ;;
esac
tmp="$(mktemp -d)"; trap 'rm -rf -- "$tmp"' EXIT
curl -fsSL --retry 3 "https://api.github.com/repos/$REPO/releases/latest" -o "$tmp/release.json"
tag="$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/release.json" | head -n 1)"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Не удалось определить опубликованный релиз"
current=""
[[ ! -x "$DEST/$BIN" ]] || current="$("$DEST/$BIN" --version 2>/dev/null | awk '{print $NF}')"
if [[ "$current" == "${tag#v}" ]]; then echo "Уже установлена актуальная версия $current"; exit 0; fi
echo "Загружаем $tag ($asset)..."
curl -fL --retry 3 "$BASE/$tag/$asset" -o "$tmp/$asset"
curl -fL --retry 3 "$BASE/$tag/SHA256SUMS" -o "$tmp/SHA256SUMS"
(cd "$tmp" && grep -E "^[0-9a-fA-F]{64}  $asset$" SHA256SUMS | sha256sum -c -) || fail "Ошибка SHA-256"
chmod 755 "$tmp/$asset"
"$tmp/$asset" --version
"${sudo_cmd[@]}" install -d -m 755 "$DEST"
"${sudo_cmd[@]}" install -m 755 "$tmp/$asset" "$DEST/$BIN"
echo "Установлено: $DEST/$BIN ($tag)"
