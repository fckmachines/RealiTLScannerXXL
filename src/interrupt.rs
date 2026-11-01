//! Safe interactive interruption and private checkpoints.
use crate::host::Host;
use anyhow::{Context, Result};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision { Process, Save, Finish }

pub fn can_prompt(domains_only: bool) -> bool {
    !domains_only && io::stdin().is_terminal() && io::stderr().is_terminal()
}

fn parse_choice(text: &str, default: Decision) -> Decision {
    match text.trim() {
        "1" => Decision::Process,
        "2" => Decision::Save,
        "0" => Decision::Finish,
        "" => default,
        _ => Decision::Finish,
    }
}

/// Called only after no writers are running, so a second signal can exit
/// without losing buffered verified CSV rows.
pub async fn prompt(stage: &str, pending: usize, processed: u64, accepted: u64) -> Decision {
    eprintln!("\n{stage} SCAN paused (Ctrl+C)");
    if stage == "FAST" {
        eprintln!("Найдено уникальных IP с открытым TCP: {pending}");
        eprintln!("[1] DEEP SCAN — проверить найденные IP");
        eprintln!("[2] Сохранить найденные IP в файл и выйти");
        eprintln!("[0] Выйти, автоматически сохранив найденные IP");
    } else {
        eprintln!("DEEP завершено: {processed} | принято: {accepted} | осталось: {pending}");
        eprintln!("[1] Продолжить DEEP на оставшихся IP");
        eprintln!("[2] Сохранить оставшиеся IP в файл и выйти");
        eprintln!("[0] Завершить с сохранением проверенных и непроверенных");
    }
    eprint!("Choice [{}]: ", if stage == "FAST" {"1"} else {"0"});
    let _ = io::stderr().flush();
    let choice=tokio::task::spawn_blocking(|| {
        let mut line=String::new();
        if io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            return String::new();
        }
        line
    });
    tokio::select! {
        answer = choice => match answer {
            Ok(answer) => parse_choice(&answer, if stage == "FAST" {Decision::Process} else {Decision::Finish}),
            Err(_) => Decision::Finish,
        },
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\nПовторный Ctrl+C: безопасные файлы уже закрыты.");
            std::process::exit(130);
        }
    }
}

/// Explicit, non-overwriting 0600 checkpoint in the results directory.
/// Supports both IP targets and unresolved hostnames from --in/--url.
pub fn checkpoint(hosts: &[Host], output_path: &str) -> Result<Option<PathBuf>> {
    if hosts.is_empty() { return Ok(None); }
    let path=if output_path.is_empty() {Path::new("out.csv")} else {Path::new(output_path)};
    let parent=path.parent().filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(||Path::new("."));
    let stem=path.file_name().and_then(|x|x.to_str()).unwrap_or("scan");
    let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    for attempt in 0..20 {
        let dest=parent.join(format!("{stem}.pending-{}-{nonce}-{attempt}.txt",std::process::id()));
        let file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&dest);
        match file {
            Ok(mut file) => {
                for host in hosts {
                    if let Some(ip)=host.ip {
                        writeln!(file,"{ip}")?;
                    } else {
                        writeln!(file,"{}",host.origin)?;
                    }
                }
                file.flush()?;
                file.sync_all()?;
                return Ok(Some(dest));
            }
            Err(e) if e.kind()==io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(||format!("Не удалось создать резервный список в {}",parent.display())),
        }
    }
    anyhow::bail!("Не удалось выбрать безопасное имя резервного списка")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostType;
    #[test]
    fn choices_default_safely() {
        assert_eq!(parse_choice("",Decision::Finish),Decision::Finish);
        assert_eq!(parse_choice("",Decision::Process),Decision::Process);
        assert_eq!(parse_choice("2",Decision::Process),Decision::Save);
        assert_eq!(parse_choice("garbage",Decision::Process),Decision::Finish);
    }
    #[test]
    fn checkpoint_file_is_private_and_never_clobbered() {
        use std::os::unix::fs::PermissionsExt;
        let dir=std::env::temp_dir().join(format!("realitlscanner-ckpt-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let orig=dir.join("out.csv");
        std::fs::write(&orig,"ORIGINAL").unwrap();
        let hosts=vec![Host {ip:Some("192.0.2.4".parse().unwrap()), origin:"x".into(),kind:HostType::Ip}];
        let path=checkpoint(&hosts,&orig.to_string_lossy()).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(),"192.0.2.4\n");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,0o600);
        assert_eq!(std::fs::read_to_string(&orig).unwrap(),"ORIGINAL");
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&orig).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
