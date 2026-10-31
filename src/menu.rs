//! Interactive entry point. Scripted invocations keep the existing CLI.
use crate::cli::Cli;
use anyhow::{bail, Result};
use clap::Parser;
use std::io::{self, IsTerminal, Write};

fn prompt(message: &str) -> Result<Option<String>> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_string()))
}

pub fn choose() -> Result<Option<Cli>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("Для запуска без терминала укажите --addr, --asn, --in или --url (см. --help)");
    }
    loop {
        println!("   ┌────────────────────────────────────────────────┐");
        println!("   │ SCAN MENU                                      │");
        println!("   ├────────────────────────────────────────────────┤");
        println!("   │ [1] Сканировать IP / CIDR / несколько диапазонов│");
        println!("   │ [2] Сканировать сети по ASN (RIPEstat)          │");
        println!("   │ [3] Сканировать IP/CIDR из файла                │");
        println!("   │ [0] Выход                                      │");
        println!("   └────────────────────────────────────────────────┘");
        let Some(choice) = prompt("   Выбор: ")? else { return Ok(None) };
        let mut args = vec!["realitlscanner".to_string()];
        match choice.as_str() {
            "0" | "q" | "Q" => return Ok(None),
            "1" => {
                let Some(value) = prompt("   IP/CIDR (через запятую для нескольких): ")? else { return Ok(None) };
                if value.is_empty() { continue; }
                args.extend(["--addr".into(), value]);
            }
            "2" => {
                let Some(value) = prompt("   ASN (например, AS3333): ")? else { return Ok(None) };
                if value.is_empty() { continue; }
                args.extend(["--asn".into(), value]);
                let Some(limit) = prompt("   Максимум IPv4-адресов [4096]: ")? else { return Ok(None) };
                let limit = if limit.is_empty() { "4096".to_string() } else { limit };
                args.extend(["--max-ips".into(), limit]);
            }
            "3" => {
                let Some(value) = prompt("   Путь к файлу со списком IP/CIDR: ")? else { return Ok(None) };
                if value.is_empty() { continue; }
                args.extend(["--in".into(), value]);
            }
            _ => {
                eprintln!("   Неизвестный пункт меню.");
                continue;
            }
        }
        args.push("--reality-sni".to_string());
        match Cli::try_parse_from(args) {
            Ok(cli) => return Ok(Some(cli)),
            Err(e) => eprintln!("   {e}"),
        }
    }
}
