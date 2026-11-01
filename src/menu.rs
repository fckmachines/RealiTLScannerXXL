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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanSpeed { syn_pps: u32, deep_per_sec: u32 }

impl Default for ScanSpeed {
    fn default() -> Self { Self { syn_pps: 100, deep_per_sec: 10 } }
}
impl ScanSpeed {
    fn append_args(self, args: &mut Vec<String>) {
        args.extend(["--fast-rate".to_owned(), self.syn_pps.to_string(),
                     "--deep-rate".to_owned(), self.deep_per_sec.to_string()]);
    }
}
fn valid_rate(text: &str, max: u32) -> Option<u32> {
    text.trim().parse::<u32>().ok().filter(|v| *v >= 1 && *v <= max)
}
/// Ordered from lightest to heaviest. These are throughput ceilings,
/// not guarantees of permission or of a fixed total packet rate.
const SPEED_PRESETS: [(&str, ScanSpeed); 9] = [
    ("Минимальная", ScanSpeed { syn_pps: 5, deep_per_sec: 1 }),
    ("Очень тихая", ScanSpeed { syn_pps: 10, deep_per_sec: 1 }),
    ("Тихая", ScanSpeed { syn_pps: 25, deep_per_sec: 2 }),
    ("Осторожная", ScanSpeed { syn_pps: 50, deep_per_sec: 5 }),
    ("Стандартная", ScanSpeed { syn_pps: 100, deep_per_sec: 10 }),
    ("Умеренно быстрая", ScanSpeed { syn_pps: 250, deep_per_sec: 20 }),
    ("Быстрая", ScanSpeed { syn_pps: 500, deep_per_sec: 40 }),
    ("Высокая", ScanSpeed { syn_pps: 1000, deep_per_sec: 80 }),
    ("Очень высокая", ScanSpeed { syn_pps: 2000, deep_per_sec: 100 }),
];

fn speed_preset(choice: &str) -> Option<ScanSpeed> {
    let index = choice.parse::<usize>().ok()?.checked_sub(1)?;
    SPEED_PRESETS.get(index).map(|(_, speed)| *speed)
}

fn choose_speed(current: ScanSpeed) -> Result<ScanSpeed> {
    println!("   Текущая скорость: {} SYN/с; {} DEEP/с", current.syn_pps, current.deep_per_sec);
    for (index, (name, speed)) in SPEED_PRESETS.iter().enumerate() {
        let selected = if *speed == current { " (текущая)" } else { "" };
        println!("   [{}] {:<18} {:>5} SYN/с | {:>3} DEEP/с{}",
            index + 1, name, speed.syn_pps, speed.deep_per_sec, selected);
    }
    println!("   [10] Свои значения");
    println!("   [0] Назад");
    println!("   Примечание: высокие скорости — только для разрешённых диапазонов;");
    println!("   ограничения хостера действуют независимо от выбранного профиля.");
    let Some(choice) = prompt("   Выбор: ")? else { return Ok(current) };
    if let Some(speed) = speed_preset(&choice) {
        return Ok(speed);
    }
    match choice.as_str() {
        "10" => {
            let Some(a) = prompt("   FAST SYN пакетов/с [1..100000]: ")?
                else { return Ok(current) };
            let Some(b) = prompt("   DEEP новых проверок/с [1..1000]: ")?
                else { return Ok(current) };
            match (valid_rate(&a, 100_000), valid_rate(&b, 1_000)) {
                (Some(syn_pps), Some(deep_per_sec)) =>
                    Ok(ScanSpeed { syn_pps, deep_per_sec }),
                _ => {
                    eprintln!("   Некорректная скорость; настройки не изменены.");
                    Ok(current)
                }
            }
        }
        "0" => Ok(current),
        _ => {
            eprintln!("   Неизвестный пункт.");
            Ok(current)
        }
    }
}

/// Actions after a *first* Ctrl+C. A second signal while prompting
/// returns Forced, which the caller checkpoints before process exit.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PauseAction { Continue, Save, Exit, Forced }

fn parse_pause_choice(choice: &str, has_pending: bool, default: PauseAction) -> PauseAction {
    match choice.trim() {
        "" => default,
        "1" if has_pending => PauseAction::Continue,
        "2" => PauseAction::Save,
        _ => PauseAction::Exit,
    }
}

async fn prompt_pause(has_pending: bool, default: PauseAction) -> Result<PauseAction> {
    // Reading from a terminal is blocking. Use a separate thread so that a
    // second Ctrl+C can still be observed by the Tokio signal handler.
    let handle = tokio::task::spawn_blocking(move || prompt("   Choice: "));
    tokio::select! {
        line = handle => Ok(parse_pause_choice(
            line.context("Ошибка чтения выбора")?.as_deref().unwrap_or("0"),
            has_pending, default
        )),
        _ = tokio::signal::ctrl_c() => {
            eprintln!("   Second Ctrl+C: сохраняем найденное и завершаем.");
            Ok(PauseAction::Forced)
        }
    }
}

pub async fn pause_fast(found: usize) -> Result<PauseAction> {
    eprintln!("\nFAST SCAN paused (Ctrl+C): найдено {found} IP с TCP/443.");
    if found == 0 {
        eprintln!("   Нет найденных IP для DEEP-проверки.");
        return Ok(PauseAction::Exit);
    }
    eprintln!("   [1] DEEP SCAN — проверить найденные {found} IP");
    eprintln!("   [2] Сохранить IP в отдельный файл и выйти");
    eprintln!("   [0] Завершить, сохранив найденные IP");
    eprintln!("   Выбор по умолчанию: [1]");
    prompt_pause(true, PauseAction::Continue).await
}

pub async fn pause_deep(checked: u64, accepted: u64, remaining: usize) -> Result<PauseAction> {
    eprintln!("\nDEEP SCAN paused (Ctrl+C).");
    eprintln!("   Проверено: {checked} | кандидатов: {accepted} | осталось: {remaining}");
    if remaining == 0 {
        eprintln!("   Все оставшиеся цели уже обработаны.");
        return Ok(PauseAction::Exit);
    }
    eprintln!("   [1] Продолжить DEEP для {remaining} оставшихся целей");
    eprintln!("   [2] Сохранить оставшиеся цели в файл и выйти");
    eprintln!("   [0] Завершить и сохранить оставшиеся цели");
    eprintln!("   Выбор по умолчанию: [0]");
    prompt_pause(true, PauseAction::Exit).await
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

fn render_menu(width: usize, max_domain_length: usize, speed: ScanSpeed) -> String {
    let entries = [
        "[1] Сканировать IP / CIDR / несколько диапазонов".to_owned(),
        "[2] Сканировать сети по ASN (RIPEstat)".to_owned(),
        "[3] Сканировать IP/CIDR из файла".to_owned(),
        format!("[4] Макс. длина домена: {}",
            if max_domain_length == 0 { "без ограничения".to_owned() }
            else { max_domain_length.to_string() }),
        format!("[5] Скорость: {} SYN/с · {} DEEP/с", speed.syn_pps, speed.deep_per_sec),
        "[0] Выход".to_owned(),
    ];
    // Total frame width includes two borders plus one padding column on
    // either side of its contents.
    let full_width = width.max(24);
    let inner = full_width - 4;
    let mut lines = Vec::new();
    lines.push(format!("┌{}┐", "─".repeat(full_width - 2)));
    for (idx, text) in std::iter::once("SCAN MENU")
        .chain(entries.iter().map(String::as_str)).enumerate()
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

fn args_for_asn(asn: u32, limit: u64, all: bool, max_domain_length: usize, speed: ScanSpeed) -> Result<Cli> {
    let mut args = vec![
        "realitlscanner".to_string(),
        "--asn".to_string(), format!("AS{asn}"),
        "--reality-sni".to_string(),
        "--fast".to_string(),
        "--max-domain-length".to_string(), max_domain_length.to_string(),
    ];
    if all {
        args.push("--all".into());
    } else {
        args.push("--max-ips".into());
        args.push(limit.to_string());
    }
    speed.append_args(&mut args);
    Ok(Cli::try_parse_from(args)?)
}

fn parse_limit(s: &str) -> Option<u64> {
    s.parse::<u64>().ok().filter(|n| *n > 0)
}

fn parse_domain_limit(s: &str) -> Option<usize> {
    s.trim().parse::<usize>().ok()
}

fn confirms_yes(answer: &str) -> bool {
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

fn confirms_full_scan(answer: &str) -> bool {
    answer.eq_ignore_ascii_case("YES")
}

async fn choose_asn(identity: &Identity, max_domain_length: usize, speed: ScanSpeed) -> Result<Option<Choice>> {
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
                let cli = args_for_asn(plan.asn, limit, false, max_domain_length, speed)?;
                return Ok(Some(Choice { cli, plan: Some(plan) }));
            }
            "2" => {
                println!("   ВНИМАНИЕ: будет проверено {} IPv4-адресов!",plan.total);
                let Some(answer) = prompt("   Type YES to confirm full scan: ")? else { return Ok(None) };
                if !confirms_full_scan(&answer) {
                    println!("   Full scan cancelled.");
                    continue;
                }
                let cli = args_for_asn(plan.asn, limit, true, max_domain_length, speed)?;
                return Ok(Some(Choice { cli, plan: Some(plan) }));
            }
            "3" => {
                let Some(value) = prompt("   Максимум IPv4 (>0): ")? else { return Ok(None) };
                if let Some(n) = parse_limit(&value) {
                    limit = n;
                    let selected = plan.selected(limit,false);
                    println!("   Будет проверено: {selected} из {} IPv4.",plan.total);
                    let Some(answer) = prompt("   Start scan? [y/N]: ")? else { return Ok(None) };
                    if confirms_yes(&answer) {
                        let cli = args_for_asn(plan.asn,limit,false,max_domain_length,speed)?;
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
    let mut max_domain_length = 20usize;
    let mut speed = ScanSpeed::default();
    loop {
        // Leave 3 columns for left indentation and one for terminal safety.
        let width = terminal_columns().saturating_sub(4).min(68);
        println!("\n{}", render_menu(width, max_domain_length, speed));
        let Some(choice) = prompt("   Выбор: ")? else { return Ok(None) };
        if matches!(choice.as_str(), "0" | "q" | "Q") { return Ok(None) };
        if choice == "2" {
            if let Some(selected) = choose_asn(identity, max_domain_length, speed).await? { return Ok(Some(selected)) }
            continue;
        }
        if choice == "5" {
            speed = choose_speed(speed)?;
            continue;
        }
        if choice == "4" {
            let Some(value) = prompt("   Max domain length in characters [0 = unlimited]: ")?
                else { return Ok(None) };
            match parse_domain_limit(&value) {
                Some(n) => {
                    max_domain_length = n;
                    println!("   Domain limit updated: {}",
                        if n == 0 { "unlimited".to_owned() } else { n.to_string() });
                }
                None => eprintln!("   Invalid length: enter a nonnegative integer."),
            }
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
        args.extend(["--max-domain-length".to_owned(), max_domain_length.to_string()]);
        speed.append_args(&mut args);
        // A lone bare IP retains legacy deep-scan infinite walk; other finite
        // IPv4/CIDR lists use the fast SYN discovery stage by default.
        if choice == "3" || args.get(2).is_some_and(|value| value.contains('/') || value.contains(',')) {
            args.push("--fast".to_string());
        }
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
    fn pause_choices_are_safe() {
        assert_eq!(parse_pause_choice("1", true, PauseAction::Exit), PauseAction::Continue);
        assert_eq!(parse_pause_choice("1", false, PauseAction::Exit), PauseAction::Exit);
        assert_eq!(parse_pause_choice("", true, PauseAction::Continue), PauseAction::Continue);
        assert_eq!(parse_pause_choice("2", true, PauseAction::Exit), PauseAction::Save);
        assert_eq!(parse_pause_choice("0", true, PauseAction::Continue), PauseAction::Exit);
    }
    #[test]
    fn all_menu_borders_have_same_column_width() {
        for width in [24,32,48,60,68] {
            let output=render_menu(width, 20, ScanSpeed::default());
            let cols:Vec<usize>=output.lines().map(cell_width).collect();
            assert_eq!(cols.len(),10);
            assert!(cols.iter().all(|n| *n==width+3), "{cols:?}");
            for line in output.lines() {
                assert!(matches!(line.chars().last(), Some('┐' | '┤' | '│' | '┘')));
            }
        }
    }
    #[test]
    fn standard_width_preserves_longest_option() {
        assert!(render_menu(68, 20, ScanSpeed::default()).contains("[1] Сканировать IP / CIDR / несколько диапазонов"));
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
        assert_eq!(args_for_asn(14618,10000,false,25,ScanSpeed::default()).unwrap().max_ips,10000);
        assert!(args_for_asn(14618,4096,true,20,ScanSpeed::default()).unwrap().all);
        assert!(args_for_asn(14618,4096,false,20,ScanSpeed::default()).unwrap().fast);
        assert_eq!(args_for_asn(14618,10000,false,25,ScanSpeed::default()).unwrap().max_domain_length,25);
        assert!(render_menu(68,0,ScanSpeed::default()).contains("без ограничения"));
        assert_eq!(parse_domain_limit("0"), Some(0));
        assert_eq!(parse_domain_limit(" 25 "), Some(25));
        assert_eq!(parse_domain_limit("-1"), None);
        assert!(confirms_yes("y") && confirms_yes("YES"));
        assert!(!confirms_yes("д") && !confirms_yes("") && !confirms_yes("n"));
        assert!(confirms_full_scan("YES") && confirms_full_scan("yes"));
        assert!(!confirms_full_scan("y") && !confirms_full_scan("ДА"));
        assert_eq!(ScanSpeed::default(), ScanSpeed{syn_pps:100,deep_per_sec:10});
        assert_eq!(valid_rate("1",1000),Some(1));
        assert_eq!(valid_rate("1001",1000),None);
        assert_eq!(valid_rate("0",1000),None);
        assert_eq!(valid_rate("bad",1000),None);
        let custom=args_for_asn(14618,4096,false,20,
            ScanSpeed{syn_pps:25,deep_per_sec:2}).unwrap();
        assert_eq!(custom.fast_rate,25);
        assert_eq!(custom.deep_rate,2);
        assert!(render_menu(68,20,ScanSpeed::default()).contains("[5] Скорость: 100 SYN/с"));
    }
    #[test]
    fn nine_speed_presets_are_ordered_and_compatible_with_cli() {
        assert_eq!(SPEED_PRESETS.len(), 9);
        let mut last = ScanSpeed { syn_pps: 0, deep_per_sec: 0 };
        for (i, (_, expected)) in SPEED_PRESETS.iter().enumerate() {
            let actual = speed_preset(&(i+1).to_string()).unwrap();
            assert_eq!(actual, *expected);
            assert!(actual.syn_pps > last.syn_pps);
            assert!(actual.deep_per_sec >= last.deep_per_sec);
            assert!((1..=100_000).contains(&actual.syn_pps));
            assert!((1..=1_000).contains(&actual.deep_per_sec));
            let cli = args_for_asn(14618, 4096, false, 20, actual).unwrap();
            assert_eq!(cli.fast_rate, actual.syn_pps);
            assert_eq!(cli.deep_rate, actual.deep_per_sec);
            last = actual;
        }
        assert_eq!(speed_preset("5"), Some(ScanSpeed::default()));
        for invalid in ["0", "10", "-1", "foobar"] {
            assert!(speed_preset(invalid).is_none());
        }
        assert_eq!(speed_preset("9"), Some(ScanSpeed {
            syn_pps: 2000, deep_per_sec: 100,
        }));
    }
}
