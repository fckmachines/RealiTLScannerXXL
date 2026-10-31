//! Controlled TCP SYN discovery via an external Masscan process.
//! FAST never performs TLS checks; accepted IPv4 candidates are handed to
//! the existing Rust/Tokio deep-probe pipeline only after Masscan exits.
use crate::host::Host;
use anyhow::{bail, Context, Result};
use async_channel::Receiver;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::Command;

pub const MAX_FAST_TARGETS: u64 = 5_000_000;
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// Secure ephemeral files are always deleted, including on error/cancellation.
pub struct Workspace {
    dir: PathBuf,
    pub targets: u64,
}

impl Workspace {
    fn create() -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::temp_dir();
        for _ in 0..32 {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_default().as_nanos();
            let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("realitlscanner-fast-{}-{nanos}-{n}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&dir) {
                Ok(()) => return Ok(Self { dir, targets: 0 }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e).context("Не удалось создать временный каталог"),
            }
        }
        bail!("Не удалось выделить уникальный временный каталог");
    }
    fn input(&self) -> PathBuf { self.dir.join("targets.txt") }
    fn output(&self) -> PathBuf { self.dir.join("open.txt") }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Stream target IPs to a private input file. This avoids allocating a giant
/// address vector for CIDRs and ASN scans. Domains, IPv6, and infinite sources
/// are not valid for Masscan's FAST stage.
pub async fn spool(receiver: Receiver<Host>) -> Result<Workspace> {
    let mut workspace = Workspace::create()?;
    let file = tokio::fs::File::create(workspace.input()).await
        .context("Не удалось создать временный список IP")?;
    let mut writer = BufWriter::new(file);
    while let Ok(host) = receiver.recv().await {
        let ip = match host.ip {
            Some(IpAddr::V4(ip)) => ip,
            _ => bail!("FAST SCAN принимает только IPv4/CIDR. Для доменов и IPv6 используйте обычное сканирование."),
        };
        workspace.targets += 1;
        if workspace.targets > MAX_FAST_TARGETS {
            bail!("FAST SCAN ограничен {MAX_FAST_TARGETS} IP за запуск. Уменьшите --max-ips или используйте меньший CIDR.");
        }
        writer.write_all(ip.to_string().as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    writer.flush().await?;
    if workspace.targets == 0 { bail!("Для FAST SCAN не найдено ни одного IPv4-адреса"); }
    Ok(workspace)
}

fn parse_open(line: &str, expected_port: u16) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = line.split_ascii_whitespace().collect();
    if parts.len() < 4 || parts[0] != "open" || parts[1] != "tcp" {
        return None;
    }
    if parts[2].parse::<u16>().ok()? != expected_port {
        return None;
    }
    parts[3].parse::<Ipv4Addr>().ok()
}

/// Run only the known Masscan executable and strict, typed arguments.
/// Never run via a shell, never accept user-generated extra flags.
pub async fn discover(workspace: &Workspace, port: u16, rate: u32, wait: u32) -> Result<Vec<Ipv4Addr>> {
    discover_with(Path::new("masscan"), workspace, port, rate, wait).await
}

async fn discover_with(
    executable: &Path, workspace: &Workspace, port: u16, rate: u32, wait: u32
) -> Result<Vec<Ipv4Addr>> {
    if rate == 0 || rate > 100_000 { bail!("FAST SCAN: скорость должна быть 1..100000 пакетов/с"); }
    if wait == 0 || wait > 60 { bail!("FAST SCAN: ожидание ответов должно быть 1..60 секунд"); }

    eprintln!("[FAST] Masscan: {} IPv4 | TCP/{port} | до {rate} пакетов/с | ожидание {wait} с", workspace.targets);
    let mut cmd = Command::new(executable);
    cmd.arg("-iL").arg(workspace.input())
       .arg("-p").arg(port.to_string())
       .arg("--rate").arg(rate.to_string())
       .arg("--wait").arg(wait.to_string())
       .arg("-oL").arg(workspace.output())
       .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit())
       .kill_on_drop(true);

    let status = cmd.status().await.context(
        "Masscan не запускается. Debian 13: sudo apt install masscan. Для SYN-сканирования нужны сетевые привилегии (например, запуск от root)."
    )?;
    if !status.success() {
        bail!("Masscan завершился с ошибкой ({status}). Проверьте права CAP_NET_RAW/root, сетевой интерфейс, firewall и ограничения VPS.");
    }
    let file = tokio::fs::File::open(workspace.output()).await
        .context("Masscan не создал файл результатов")?;
    let mut lines = BufReader::new(file).lines();
    let mut found = HashSet::new();
    while let Some(line) = lines.next_line().await? {
        if let Some(ip) = parse_open(&line, port) {
            found.insert(ip);
        }
    }
    let mut addresses: Vec<_> = found.into_iter().collect();
    addresses.sort_unstable();
    eprintln!("[FAST] Готово: найдено {} IP с TCP/{port}; передаём в DEEP SCAN.",addresses.len());
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_masscan_list_strictly() {
        assert_eq!(parse_open("open tcp 443 192.0.2.10 1730000000",443),
                   Some(Ipv4Addr::new(192,0,2,10)));
        for line in ["# masscan", "closed tcp 443 192.0.2.10 1",
                     "open udp 443 192.0.2.10 1", "open tcp 80 192.0.2.10 1",
                     "open tcp 443 domain.example 1", "garbage"] {
            assert_eq!(parse_open(line,443),None);
        }
    }
    #[tokio::test]
    async fn spool_rejects_dns_and_keeps_private_workspace() {
        use crate::host::HostType;
        let (tx,rx)=async_channel::bounded(4);
        tx.send(Host{ip:None,origin:"example.com".into(),kind:HostType::Domain}).await.unwrap();
        drop(tx);
        assert!(spool(rx).await.is_err());
    }
    #[tokio::test]
    async fn spool_accepts_ipv4() {
        use crate::host::HostType;
        let (tx,rx)=async_channel::bounded(4);
        tx.send(Host{ip:Some("192.0.2.1".parse().unwrap()),
                     origin:"192.0.2.1".into(),kind:HostType::Ip}).await.unwrap();
        drop(tx);
        let workspace=spool(rx).await.unwrap();
        assert_eq!(workspace.targets,1);
        assert_eq!(tokio::fs::read_to_string(workspace.input()).await.unwrap(),"192.0.2.1\n");
    }
}
