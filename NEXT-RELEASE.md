# Next Release — v0.4.1 (planned)

Two fixes are scheduled: terminal menu frame alignment and ASN scan preflight.

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

## Fix: ASN scan should validate scope *before* starting

**Status:** planned, not implemented.

Observed on 2026-10-31 with menu option [2] and the detected ASN `AS14618`: the program printed
`SCAN | threads: 32` and `Результаты сохраняются в: out.csv`, then exited with
`AS содержит не менее 7168 IPv4-адресов (лимит 4096)`.

The 4096-IP safeguard is intentional and must remain, but discovering an oversized ASN
**after** starting workers/output is incorrect UX. In particular, the writer creates/truncates
`out.csv` before the producer validates the prefix set.

### Required changes

- Implement an ASN *preflight*: fetch RIPEstat observed IPv4 prefixes, normalize/dedupe
  overlapping ranges, calculate the full unique IPv4 address count, and prepare a
  reusable scan plan **before** starting workers, progress or opening output files.
- Present network holder, ASN, number of IPv4 prefixes and total unique IPv4 addresses
  in the interactive menu. State that RIPEstat is observation-based and may lag.
- If total exceeds default limit `4096`, do **not** start scanning. Provide
  an interactive option to change the limit and explicitly confirm the expanded scope,
  or return to menu. Never implicitly enlarge the default limit.
- For noninteractive `--asn`, require a sufficient explicit `--max-ips`; fail with
  exact calculated totals and an actionable message before creating/truncating CSV.
- Ensure DNS/API failures and invalid ASN values are reported within menu flow,
  not as a misleading completed/started scan.
- Keep prior valid results intact on preflight failure. Use the one fetched scan plan
  for execution; avoid a second RIPEstat lookup between confirmation and start.
- Tests: large ASN rejected before output side effects, no double counting overlapping
  CIDRs, confirmed selection and cancellation in menu, and noninteractive limit behavior.

### Acceptance criteria

1. Menu previews ASN scope before any `SCAN` message.
2. Exceeding `4096` without explicit user confirmation cannot initiate a probe.
3. A rejected/cancelled ASN scan neither starts workers nor truncates `out.csv`.
4. Exact unique IPv4 count is displayed, including any overlapping prefixes.
5. Existing `--addr`, `--in`, `--url` modes and normal authorized ASN scans remain functional.
6. Rust tests, AMD64 release build, and smoke checks pass in GitHub Actions.

**Scope:** terminal UI and ASN preflight. No changes to TLS/HTTP probe logic. Both fixes
are planned for Linux AMD64 v0.4.1. Release only after successful CI.
