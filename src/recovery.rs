//! Persist a recoverable IP/domain queue on interruption without replacing
//! existing CSV results. Recovery files are private (0600) and create_new.
use crate::host::Host;
use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn save_pending(hosts: &[Host], out_path: &str) -> Result<Option<PathBuf>> {
    if hosts.is_empty() {
        return Ok(None);
    }
    let dir = if out_path.is_empty() {
        Path::new(".")
    } else {
        let p = Path::new(out_path).parent().unwrap_or(Path::new("."));
        if p.as_os_str().is_empty() { Path::new(".") } else { p }
    };
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default().as_nanos();
    for n in 0..100 {
        let path = dir.join(format!(
            "realitlscanner-pending-{}-{stamp}-{n}.txt",std::process::id()
        ));
        let file = match OpenOptions::new().write(true).create_new(true)
            .mode(0o600).open(&path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e).context("Не удалось сохранить список необработанных целей"),
            };
        let mut writer = BufWriter::new(file);
        for host in hosts {
            let name = host.ip.map(|ip| ip.to_string())
                .unwrap_or_else(|| host.origin.clone());
            writeln!(writer,"{name}")?;
        }
        writer.flush().context("Не удалось записать список целей")?;
        writer.get_ref().sync_all().context("Не удалось сохранить список целей на диск")?;
        return Ok(Some(path));
    }
    anyhow::bail!("Не удалось выбрать уникальное имя списка целей")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Host,HostType};
    #[test]
    fn recovery_file_does_not_overwrite_and_has_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("realitl-recover-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out=dir.join("out.csv");
        std::fs::write(&out,"EXISTING").unwrap();
        let targets=vec![Host{ip:Some("192.0.2.2".parse().unwrap()),
            origin:"192.0.2.0/24".into(),kind:HostType::Cidr}];
        let p=save_pending(&targets,out.to_str().unwrap()).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(),"192.0.2.2\n");
        assert_eq!(std::fs::read_to_string(&out).unwrap(),"EXISTING");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,0o600);
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_file(&out).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
    #[test]
    fn empty_pending_does_not_create_anything() {
        assert!(save_pending(&[],"out.csv").unwrap().is_none());
    }
}
