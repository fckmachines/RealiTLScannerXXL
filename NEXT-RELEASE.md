# Next Release — v0.4.1 (planned)

## Fix: terminal SCAN MENU frame alignment

**Status:** planned, not implemented.

Observed in v0.4.0 screenshot (2026-10-31): the right border of the SCAN MENU is misaligned and one of the rows extends beyond the frame. The first (longest) menu entry is a likely culprit. Current `src/menu.rs` renders each border/row using manually padded static strings.

### Required changes

- Centralize menu rendering: a single visible width for top/bottom borders, separator, and all rows.
- Compute padding from **display-cell width**, not UTF-8 byte count; Cyrillic and box-drawing glyphs must be handled correctly.
- No extra/missing `│` on the right, including the longest `[1] Сканировать IP / CIDR / несколько диапазонов` label.
- Handle narrow terminal widths gracefully (fit, wrap, or truncate) rather than rendering outside the border.
- Exclude ANSI colors/escapes from visible width; preserve existing hotkeys [1], [2], [3], [0] and navigation.
- Add tests for all menu rows and constrained widths.
- Confirm layout visually on Linux terminals.

### Acceptance criteria

1. Each frame row has equal display width; the right border is in the same column.
2. All labels fit in a regular 80-column terminal with no clipping.
3. `cargo test --locked` and release build pass in CI.
4. Publish Linux AMD64 v0.4.1 and upgrade with the existing `bash install.sh --update`; no compilation on the VPS.

**Scope:** UI-only patch. Do not alter scanning, ASN discovery, IP checks, or CLI behavior.
