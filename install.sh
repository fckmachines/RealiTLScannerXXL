#!/usr/bin/env bash
# RealiTLScannerXXL installer for Debian/Ubuntu (amd64/arm64).
set -Eeuo pipefail

REPO="fckmachines/RealiTLScannerXXL"
REF="${REALITLS_REF:-feature/terminal-banner}"
BIN_NAME="realitlscanner"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

say() { printf '\n[RealiTLScannerXXL] %s\n' "$*"; }
die() { printf '[RealiTLScannerXXL] ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || die "Поддерживается только Linux."
[[ -r /etc/os-release ]] || die "Не удалось определить дистрибутив."
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *debian*|*ubuntu*) ;;
  *) die "Автоматическая установка поддерживает Debian/Ubuntu." ;;
esac
command -v apt-get >/dev/null || die "apt-get не найден."

if (( EUID == 0 )); then
  SUDO=()
else
  command -v sudo >/dev/null || die "Требуется sudo (либо запуск от root)."
  SUDO=(sudo)
fi

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf -- "$tmp_dir"; }
trap cleanup EXIT
trap 'die "Установка прервана на строке $LINENO."' ERR

say "Устанавливаем системные зависимости..."
"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y --no-install-recommends \
  ca-certificates curl build-essential pkg-config libssl-dev tar gzip

case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) die "Поддерживаются только x86_64 и aarch64." ;;
esac

# Rust belongs to the invoking user, not to root.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"
if ! command -v rustup >/dev/null 2>&1; then
  say "Устанавливаем Rust (rustup, stable)..."
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    -o "$tmp_dir/rustup-init.sh"
  sh "$tmp_dir/rustup-init.sh" -y --profile minimal --default-toolchain stable
else
  say "Обновляем Rust stable..."
  rustup toolchain install stable --profile minimal
fi

command -v cargo >/dev/null || die "Cargo не найден после установки Rust."
say "Скачиваем исходники $REPO ($REF)..."
curl --proto '=https' --tlsv1.2 -fL --retry 3 \
  "https://github.com/$REPO/archive/refs/heads/$REF.tar.gz" \
  -o "$tmp_dir/source.tar.gz"
mkdir -p "$tmp_dir/src"
tar -xzf "$tmp_dir/source.tar.gz" -C "$tmp_dir/src" --strip-components=1
[[ -f "$tmp_dir/src/Cargo.toml" && -f "$tmp_dir/src/Cargo.lock" ]] || die "Архив исходников повреждён."

say "Компилируем release-сборку (cargo --locked)..."
(cd "$tmp_dir/src" && cargo +stable build --release --locked)
[[ -x "$tmp_dir/src/target/release/$BIN_NAME" ]] || die "Бинарник после сборки не найден."

say "Устанавливаем $INSTALL_DIR/$BIN_NAME..."
"${SUDO[@]}" install -d -m 755 "$INSTALL_DIR"
"${SUDO[@]}" install -m 755 "$tmp_dir/src/target/release/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"

say "Готово: $INSTALL_DIR/$BIN_NAME"
"$INSTALL_DIR/$BIN_NAME" --version
printf 'Запуск: %s --help\n' "$BIN_NAME"
