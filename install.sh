#!/usr/bin/env bash
# RealiTLScannerXXL installer, updater, and optional source builder.
# Supported binary target: Linux x86_64 (AMD64).
set -Eeuo pipefail

REPO="fckmachines/RealiTLScannerXXL"
BASE="https://github.com/$REPO/releases/download"
API="https://api.github.com/repos/$REPO/releases/latest"
DEST="${INSTALL_DIR:-/usr/local/bin}"
BIN="realitlscanner"
ASSET="realitlscanner-linux-amd64"
MODE="${1:---install}"

info() { printf '[RealiTLScannerXXL] %s\n' "$*"; }
fail() { printf '[RealiTLScannerXXL] ОШИБКА: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
RealiTLScannerXXL — Linux AMD64 installer
  bash install.sh                Установить последний релиз (или ничего не делать)
  bash install.sh --update       Обновить до последнего релиза
  bash install.sh --version      Показать установленную версию
  bash install.sh --uninstall    Удалить бинарник
  bash install.sh --build        Собрать из main (с сохранением Cargo cache)
  bash install.sh --help         Справка
Переменная INSTALL_DIR задаёт другой каталог установки (по умолчанию /usr/local/bin).
USAGE
}

(( $# <= 1 )) || fail "Слишком много аргументов. Используй --help."
case "$MODE" in
  --help|-h) usage; exit 0 ;;
  --install|--update|--version|--uninstall|--build) ;;
  *) usage; fail "Неизвестный аргумент: $MODE" ;;
esac
[[ "$(uname -s):$(uname -m)" == "Linux:x86_64" ]] ||
  fail "Поддерживается только Linux x86_64 (AMD64)."
[[ "$DEST" == /* && "$DEST" != "/" ]] ||
  fail "INSTALL_DIR должен быть абсолютным путём к каталогу."

if [[ -x "$DEST/$BIN" ]]; then
  current="$("$DEST/$BIN" --version 2>/dev/null | awk '{print $NF}' || true)"
else
  current=""
fi

if [[ "$MODE" == --version ]]; then
  if [[ -n "$current" ]]; then info "Установлено: $current ($DEST/$BIN)"; else info "Не установлен."; fi
  exit 0
fi

sudo_cmd=()
if (( EUID != 0 )); then
  command -v sudo >/dev/null || fail "Для установки требуется sudo."
  sudo_cmd=(sudo)
fi

if [[ "$MODE" == --uninstall ]]; then
  "${sudo_cmd[@]}" rm -f -- "$DEST/$BIN"
  info "Удалён $DEST/$BIN"
  exit 0
fi

install_binary() {
  local source="$1"
  local staged="$DEST/.$BIN.new.$$"
  "${sudo_cmd[@]}" install -d -m 755 -- "$DEST"
  "${sudo_cmd[@]}" install -m 755 -- "$source" "$staged"
  "${sudo_cmd[@]}" mv -f -- "$staged" "$DEST/$BIN"
}

if [[ "$MODE" == --build ]]; then
  command -v apt-get >/dev/null || fail "Сборка поддерживается только на Debian/Ubuntu."
  command -v curl >/dev/null || fail "Для установки Rust нужен curl."
  info "Устанавливаем зависимости для сборки..."
  "${sudo_cmd[@]}" apt-get update
  "${sudo_cmd[@]}" apt-get install -y --no-install-recommends \
    ca-certificates curl git build-essential pkg-config libssl-dev
  export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
  export PATH="$CARGO_HOME/bin:$PATH"
  if ! command -v rustup >/dev/null; then
    info "Устанавливаем rustup..."
    tmp_rustup="$(mktemp)"
    trap 'rm -f -- "$tmp_rustup"' EXIT
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$tmp_rustup" ||
      fail "Не удалось скачать rustup."
    sh "$tmp_rustup" -y --profile minimal --default-toolchain stable
    rm -f -- "$tmp_rustup"
    trap - EXIT
  else
    rustup toolchain install stable --profile minimal
  fi

  cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/realitlscannerxxl"
  src="$cache_root/source"
  mkdir -p -- "$cache_root"
  if [[ -d "$src/.git" ]]; then
    info "Обновляем исходники в $src..."
    git -C "$src" fetch --depth 1 origin main
    git -C "$src" checkout -f -B main FETCH_HEAD
  else
    info "Клонируем исходники..."
    git clone --depth 1 --branch main "https://github.com/$REPO.git" "$src"
  fi
  info "Сборка из исходников (Cargo cache сохранится)..."
  (cd "$src" && cargo +stable build --release --locked)
  [[ -x "$src/target/release/$BIN" ]] || fail "Компиляция не создала бинарник."
  install_binary "$src/target/release/$BIN"
  info "Готово: $DEST/$BIN ($("$DEST/$BIN" --version))"
  exit 0
fi

command -v curl >/dev/null || fail "Требуется curl."
command -v sha256sum >/dev/null || fail "Требуется sha256sum."
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

info "Проверяем последнюю опубликованную версию..."
curl -fLsS --retry 3 --connect-timeout 15 "$API" -o "$tmp/release.json" ||
  fail "Не удалось получить информацию о релизах. Проверь GitHub Releases."
tag="$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/release.json")"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "Нет опубликованного стабильного релиза или некорректный ответ GitHub API."
version="${tag#v}"
if [[ "$current" == "$version" ]]; then
  info "Версия $version уже установлена — скачивание и компиляция не нужны."
  exit 0
fi
if [[ "$current" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] &&
   [[ "$(printf '%s\n' "$current" "$version" | sort -V | tail -n 1)" == "$current" ]]; then
  fail "Установленная версия $current новее релиза $version. Откат автоматически не выполняется."
fi

info "Скачиваем $tag (Linux AMD64)..."
curl -fLsS --retry 3 --connect-timeout 15 "$BASE/$tag/$ASSET" -o "$tmp/$ASSET" ||
  fail "Не удалось скачать бинарник релиза $tag."
curl -fLsS --retry 3 --connect-timeout 15 "$BASE/$tag/SHA256SUMS" -o "$tmp/SHA256SUMS" ||
  fail "Не удалось скачать SHA256SUMS."
line="$(awk -v file="$ASSET" '$2 == file { print; n++ } END { if (n != 1) exit 1 }' "$tmp/SHA256SUMS")" ||
  fail "SHA256SUMS не содержит ровно одну запись для $ASSET."
(cd "$tmp" && printf '%s\n' "$line" | sha256sum -c -) ||
  fail "Проверка SHA-256 завершилась ошибкой. Установка отменена."

chmod 755 "$tmp/$ASSET"
actual="$("$tmp/$ASSET" --version 2>/dev/null | awk '{print $NF}' || true)"
[[ "$actual" == "$version" ]] ||
  fail "Версия загруженного файла ($actual) не соответствует релизу ($version)."

install_binary "$tmp/$ASSET"
info "Установлено: $DEST/$BIN ($version). Компиляция не выполнялась."
