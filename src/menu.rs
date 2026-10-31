//! Interactive entry point. Does not affect CLI scripted invocations.
use crate::cli::Cli;
use crate::network::{self, Identity, ScanPlan};
use anyhow::{bail, Result};
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::process::{Command, Stdio};

pub struct Choice {
    pub cli: Cli,
    pub plan: Option<ScanPlan>,
}

fn prompt(message: &str) -> Result<Option<String>> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 { return Ok(None) }
    Ok(Some(line.trim().to_string()))
}

/// Terminal display columns, not the byte count of UTF-8 strings.
fn cell_width(s: &str) -> usize {
    s.chars().map(|c| match c as u32 {
        0..=31 | 127..=159 => 0,
        // Common combining marks.
        0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff | 0x20d0..=0x20ff | 0xfe20..=0xfe2f => 0,
        // East Asian wide/fullwidth and most emoji.
        0x1100..=0x115f | 0x2329..=0x232a | 0x2e80..=0xa4cf |
        0xac00..=0xd7a3 | 0xf900..=0xfaff | 0xfe10..=0xfe19 |
        0xfe30..=0xfe6f | 0xff01..=0xff60 | 0xffe0..=0xffe6 |
        0x1f300..=0x1faff | 0x20000..=0x3fffd => 2,
        _ => 1,
    }).sum()
}

fn terminal_columns() -> usize {
    let from_stty = Command::new("stty").arg("size")
        .stdin(Stdio::inherit()).stderr(Stdio::null()).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<usize>().ok());
    from_stty.or_else(|| std::env::var("COLUMNS").ok()?.parse().ok())
        .unwrap_or(80)
}

fn truncate_to(s: &str, limit: usize) -> String {
    if cell_width(s) <= limit { return s.to_owned() }
    if limit == 0 { return String::new() }
    let mut shortened = String::new();
    let mut used = 0;
    for c in s.chars() {
        let n = cell_width(&c.to_string());
        if used + n + 1 > limit { break; }
        shortened.push(c);
        used += n;
    }
    shortened.push('…');
    shortened
}

fn render_menu(width: usize) -> String {
    const ENTRIES: [&str; 4] = [
        "[1] Сканировать IP / CIDR / несколько диапазонов",
        "[2] Сканировать сети по ASN (RIPEstat)",
        "[3] Сканировать IP/CIDR из файла",
        "[0] Выход",
    ];
    // Total frame width includes two borders plus one padding column on
    // either side of its contents.
    let full_width = width.max(24);
    let inner = full_width - 4;
    let mut lines = Vec::new();
    lines.push(format!("┌{}┐", "─".repeat(full_width - 2)));
    for (idx, text) in std::iter::once("SCAN MENU")
        .chain(ENTRIES.iter().copied()).enumerate()
    {
        if idx == 1 {
            lines.push(format!("├{}┤", "─".repeat(full_width - 2)));
        }
        let fitted = truncate_to(text, inner);
        let padding = inner - cell_width(&fitted);
        lines.push(format!("│ {fitted}{} │", " ".repeat(padding)));
    }
    lines.push(format!("└{}┘", "─".repeat(full_width - 2)));
    lines.into_iter().map(|line| format!("   {line}")).collect::<Vec<_>>().join("\n")
}

fn args_for_asn(asn: u32, limit: u64, all: bool) -> Result<Cli> {
    let mut args = vec![
        "realitlscanner".to_string(),
        "--asn".to_string(), format!("AS{asn}"),
        "--reality-sni".to_string(),
    ];
    if all {
        args.push("--all".into());
    } else {
        args.push("--max-ips".into());
        args.push(limit.to_string());
    }
    Ok(Cli::try_parse_from(args)?)
}

fn parse_limit(s: &str) -> Option<u64> {
    s.parse::<u64>().ok().filter(|n| *n > 0)
}

async fn choose_asn(identity: &Identity) -> Result<Option<Choice>> {
    let detected = identity.asns.first().map(|n| format!("AS{n}"));
    let message = detected.as_ref()
        .map(|s| format!("   ASN [{s}]: "))
        .unwrap_or_else(|| "   ASN (например, AS3333): ".to_string());
    let Some(value) = prompt(&message)? else { return Ok(None) };
    let target = if value.is_empty() {
        let Some(known) = detected else {
            eprintln!("   ASN не определён. Укажите номер вручную.");
            return Ok(None);
        };
        known
    } else { value };

    println!("   Получаем IPv4-префиксы RIPEstat для {target}...");
    let plan = match network::fetch_plan(&target).await {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("   Ошибка определения ASN: {e:#}");
            return Ok(None);
        }
    };
    let mut limit = 4_096;
    loop {
        println!("\n{}", plan.preview(plan.selected(limit, false)));
        println!("   [1] Сканировать до {limit} IP (выборка по всем сетям)");
        println!("   [2] Весь ASN — {} IP (с подтверждением)", plan.total);
        println!("   [3] Указать другое количество IP");
        println!("   [0] Назад в меню");
        let Some(option) = prompt("   Выбор: ")? else { return Ok(None) };
        match option.as_str() {
            "0" => return Ok(None),
            "1" => {
                let cli = args_for_asn(plan.asn, limit, false)?;
                return Ok(Some(Choice { cli, plan: Some(plan) }));
            }
            "2" => {
                println!("   ВНИМАНИЕ: будет проверено {} IPv4-адресов!",plan.total);
                let Some(answer) = prompt("   Для подтверждения введите ДА: ")? else { return Ok(None) };
                if answer != "ДА" {
                    println!("   Полное сканирование отменено.");
                    continue;
                }
                let cli = args_for_asn(plan.asn, limit, true)?;
                return Ok(Some(Choice { cli, plan: Some(plan) }));
            }
            "3" => {
                let Some(value) = prompt("   Максимум IPv4 (>0): ")? else { return Ok(None) };
                if let Some(n) = parse_limit(&value) {
                    limit = n;
                    let selected = plan.selected(limit,false);
                    println!("   Будет проверено: {selected} из {} IPv4.",plan.total);
                    let Some(answer) = prompt("   Начать сканирование? [д/Н]: ")? else { return Ok(None) };
                    if answer.eq_ignore_ascii_case("д") || answer.eq_ignore_ascii_case("да")
                        || answer.eq_ignore_ascii_case("y") {
                        let cli = args_for_asn(plan.asn,limit,false)?;
                        return Ok(Some(Choice {cli,plan:Some(plan)}));
                    }
                } else {
                    eprintln!("   Некорректное количество IP.");
                }
            }
            _ => eprintln!("   Неизвестный пункт меню."),
        }
    }
}

pub async fn choose(identity: &Identity) -> Result<Option<Choice>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("Для пакетного запуска укажите --addr, --asn, --in или --url");
    }
    loop {
        // Leave 3 columns for left indentation and one for terminal safety.
        let width = terminal_columns().saturating_sub(4).min(68);
        println!("\n{}", render_menu(width));
        let Some(choice) = prompt("   Выбор: ")? else { return Ok(None) };
        if matches!(choice.as_str(), "0" | "q" | "Q") { return Ok(None) };
        if choice == "2" {
            if let Some(selected) = choose_asn(identity).await? { return Ok(Some(selected)) }
            continue;
        }
        let mut args = vec!["realitlscanner".to_owned()];
        match choice.as_str() {
            "1" => {
                let Some(value) = prompt("   IP/CIDR (можно через запятую): ")? else { return Ok(None) };
                if value.is_empty() { continue }
                args.extend(["--addr".into(),value]);
            }
            "3" => {
                let Some(value) = prompt("   Файл IP/CIDR: ")? else { return Ok(None) };
                if value.is_empty() { continue }
                args.extend(["--in".into(),value]);
            }
            _ => { eprintln!("   Неизвестный пункт меню."); continue }
        }
        args.push("--reality-sni".to_string());
        match Cli::try_parse_from(args) {
            Ok(cli) => return Ok(Some(Choice {cli,plan:None})),
            Err(e) => eprintln!("   {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_menu_borders_have_same_column_width() {
        for width in [24,32,48,60,68] {
            let output=render_menu(width);
            let cols:Vec<usize>=output.lines().map(cell_width).collect();
            assert_eq!(cols.len(),8);
            assert!(cols.iter().all(|n| *n==width+3), "{cols:?}");
            for line in output.lines() {
                assert!(line.ends_with(['┐','┤','│','┘']));
            }
        }
    }
    #[test]
    fn standard_width_preserves_longest_option() {
        assert!(render_menu(68).contains("[1] Сканировать IP / CIDR / несколько диапазонов"));
    }
    #[test]
    fn unicode_width_counts_cyrillic_and_wide_glyphs() {
        assert_eq!(cell_width("│ Привет │"),10);
        assert_eq!(cell_width("日本"),4);
        assert_eq!(cell_width("a\u{0301}"),1);
    }
    #[test]
    fn numeric_limit_and_asn_cli_selection() {
        assert_eq!(parse_limit("4096"),Some(4096));
        assert_eq!(parse_limit("0"),None);
        assert_eq!(parse_limit("bad"),None);
        assert_eq!(args_for_asn(14618,10000,false).unwrap().max_ips,10000);
        assert!(args_for_asn(14618,4096,true).unwrap().all);
    }
}
