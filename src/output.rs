use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWriteExt, AsyncReadExt, AsyncSeekExt, BufWriter, SeekFrom};

#[derive(Debug, Clone)]
pub struct Record {
    pub ip: IpAddr,
    pub origin: String,
    pub cert_domain: String,
    pub cert_issuer: String,
    pub geo: String,
    pub tls_ms: u32,
    pub san_count: u16,
    pub via_san: bool,
    pub verified_http: bool,
}

impl Record {
    /// Advisory score for sorting, NOT a pass/fail test or uptime guarantee.
    fn score(&self) -> u8 {
        60 + if self.via_san { 10 } else { 0 }
            + if self.verified_http { 10 } else { 0 }
            + if self.tls_ms < 200 {15} else if self.tls_ms < 500 {8} else if self.tls_ms < 1000 {3} else {0}
    }
}

const HTML_HEAD: &str = r##"<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>RealiTLScannerXXL — результаты</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#111827;color:#e5e7eb}
body{max-width:1200px;margin:35px auto;padding:0 20px}
h1{font-size:1.65rem}p,.note{color:#9ca3af}input,select{background:#1f2937;color:#e5e7eb;border:1px solid #4b5563;padding:12px;border-radius:7px;font:inherit}
.toolbar{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
table{width:100%;border-collapse:collapse;font-size:.93rem}
th,td{padding:10px;border-bottom:1px solid #374151;text-align:left;overflow-wrap:anywhere}
th{background:#1f2937;cursor:pointer;position:sticky;top:0}
tbody tr:hover{background:#1f2937}
tr[hidden]{display:none}
.score{font-weight:700;color:#86efac}
a{color:#93c5fd}small{color:#9ca3af}
@media(max-width:750px){body{padding:0 8px}th,td{padding:6px;font-size:.82rem}}
</style></head><body>
<h1>RealiTLScannerXXL · Кандидаты REALITY</h1>
<p>Открывается локально, без сервера и сторонних библиотек. Это технические кандидаты, не гарантия работы Xray.</p>
<div class="toolbar"><input id="search" type="search" placeholder="Поиск: IP, домен, страна, CA…" aria-label="Поиск">
<select id="minimum" aria-label="Минимальный балл"><option value="0">Все кандидаты</option><option value="80">Балл ≥ 80</option><option value="90">Балл ≥ 90</option></select>
<span id="count"></span></div>
<p class="note">Балл ориентировочный: SAN, успешная HTTPS-проверка и задержка TLS. Не измеряет доступность из других стран, стабильность, репутацию и ASN. Нажмите заголовок для сортировки.</p>
<table><thead><tr><th data-key="0">Балл</th><th data-key="1">Домен / SNI</th><th data-key="2">IP</th><th data-key="3">GEO</th><th data-key="4">TLS, мс</th><th data-key="5">SAN</th><th data-key="6">Источник</th><th data-key="7">CA</th></tr></thead><tbody id="results">
"##;
const HTML_FOOT: &str = r##"</tbody></table>
<script>
(()=>{'use strict';
const tbody=document.getElementById('results'),rows=Array.from(tbody.rows);
const query=document.getElementById('search'),min=document.getElementById('minimum');
const count=document.getElementById('count');
let column=0,ascending=false;
function refresh(){
 const needle=query.value.toLocaleLowerCase().trim(),floor=Number(min.value);
 let visible=0;
 for(const row of rows){
  const ok=Number(row.dataset.score)>=floor&&row.textContent.toLocaleLowerCase().includes(needle);
  row.hidden=!ok;if(ok)visible++;
 }
 count.textContent='Показано '+visible+' из '+rows.length;
}
function sort(){
 rows.sort((a,b)=>{
  let x=a.cells[column].textContent.trim(),y=b.cells[column].textContent.trim();
  const numeric=[0,4,5].includes(column);
  let result=numeric?(Number(x)-Number(y)):x.localeCompare(y,'ru',{numeric:true});
  return ascending?result:-result;
 });
 const fragment=document.createDocumentFragment();
 for(const row of rows)fragment.appendChild(row);
 tbody.appendChild(fragment);refresh();
}
for(const th of document.querySelectorAll('th[data-key]')){
 th.addEventListener('click',()=>{
  const next=Number(th.dataset.key);
  ascending=column===next?!ascending:![0,4,5].includes(next);
  column=next;sort();
 });
}
query.addEventListener('input',refresh);min.addEventListener('change',refresh);
sort();
})();
</script></body></html>
"##;

fn html_escape(s: &str) -> String {
    s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;")
     .replace('"',"&quot;").replace('\'',"&#39;")
}

fn html_row(r: &Record) -> String {
    let score=r.score();
    let via=if r.via_san {"SAN"} else {"CN"};
    format!("<tr data-score=\"{score}\"><td class=\"score\">{score}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{via}</td><td>{}</td></tr>\n",
        html_escape(&r.cert_domain), r.ip, html_escape(&r.geo), r.tls_ms,
        r.san_count, html_escape(&r.cert_issuer))
}

/// Reserve a CSV and its HTML companion atomically with respect to existing
/// filenames. We never open an old user result with truncate/create.
pub fn reserve_pair(requested: &str) -> anyhow::Result<Option<(String,String)>> {
    if requested.is_empty() {return Ok(None);}
    let input=Path::new(requested);
    let name=input.file_stem().filter(|s|!s.is_empty()).ok_or_else(
        || anyhow::anyhow!("Некорректный путь результата: {requested}"))?
        .to_string_lossy();
    let parent=input.parent().filter(|s|!s.as_os_str().is_empty())
        .unwrap_or_else(||Path::new("."));
    let stamp=SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default().as_secs();
    for suffix in 0..1000u32 {
        let root=format!("{name}-{stamp}-{}-{suffix}",std::process::id());
        let csv=parent.join(format!("{root}.csv"));
        let html=parent.join(format!("{root}.html"));
        let file=std::fs::OpenOptions::new().write(true).create_new(true).open(&csv);
        match file {
            Ok(_) => {
                match std::fs::OpenOptions::new().write(true).create_new(true).open(&html) {
                    Ok(_) => return Ok(Some((
                        csv.to_string_lossy().to_string(),
                        html.to_string_lossy().to_string()))),
                    Err(err) => {
                        // This fresh file belongs to this reservation.
                        std::fs::remove_file(&csv)?;
                        if err.kind()==std::io::ErrorKind::AlreadyExists {continue;}
                        return Err(err.into());
                    }
                }
            }
            Err(err) if err.kind()==std::io::ErrorKind::AlreadyExists =>continue,
            Err(err)=>return Err(err.into()),
        }
    }
    anyhow::bail!("Нет свободного имени для CSV/HTML в {}",parent.display())
}

async fn open_html(path: &str, append: bool) -> anyhow::Result<BufWriter<tokio::fs::File>> {
    if !append {
        let file=tokio::fs::OpenOptions::new().write(true).truncate(true).open(path).await?;
        let mut writer=BufWriter::new(file);
        writer.write_all(HTML_HEAD.as_bytes()).await?;
        return Ok(writer);
    }
    let mut file=tokio::fs::OpenOptions::new().read(true).write(true).open(path).await?;
    let len=file.metadata().await?.len();
    let tail=HTML_FOOT.len() as u64;
    anyhow::ensure!(len>=tail,"Повреждён HTML, дописывание остановлено: {path}");
    file.seek(SeekFrom::Start(len-tail)).await?;
    let mut actual=vec![0;tail as usize];
    file.read_exact(&mut actual).await?;
    anyhow::ensure!(actual==HTML_FOOT.as_bytes(),"HTML не завершён корректно: {path}");
    file.set_len(len-tail).await?;
    file.seek(SeekFrom::Start(len-tail)).await?;
    Ok(BufWriter::new(file))
}

/// Pure formatter for a single CSV row. Extracted so it can be unit-tested
/// without spinning up the async writer task and its file handle. The issuer
/// is quoted (matching Go) because it commonly contains commas, e.g.
/// `Let's Encrypt, Inc.`.
pub fn format_record(r: &Record) -> String {
    format!(
        "{},{},{},\"{}\",{}\n",
        r.ip, r.origin, r.cert_domain, r.cert_issuer, r.geo
    )
}

/// Writer task: consumes `Record`s from `rx`, optionally appending a CSV row to
/// `out_path` (empty string disables file output, matching Go's `io.Discard`),
/// and optionally echoing `cert_domain` to stdout when `--domains-only` is set.
pub async fn writer(
    rx: async_channel::Receiver<Record>,
    out_path: String,
    domains_only: bool,
    append: bool,
    html_path: Option<String>,
) -> anyhow::Result<()> {
    // Wrap the output file in a BufWriter: every raw `write_all` on a
    // `tokio::fs::File` is dispatched to the blocking-fs pool, so at high
    // feasible rates we were paying one syscall hop per record. BufWriter
    // coalesces small CSV rows into page-sized flushes.
    let mut file = if out_path.is_empty() {
        None
    } else {
        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).write(true);
        if append { options.append(true); } else { options.truncate(true); }
        let f = options.open(&out_path).await?;
        let mut f = BufWriter::new(f);
        if !append {
            f.write_all(b"IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n").await?;
        }
        Some(f)
    };

    let mut html = match html_path {
        Some(ref path) => Some(open_html(path,append).await?),
        None => None,
    };

    // Hoist the stdout handle out of the loop: constructing a fresh
    // `tokio::io::stdout()` each iteration re-entered the lock/init path.
    // Kept unbuffered with a per-record flush so downstream `grep` etc. do
    // not deadlock when `--domains-only` is piped.
    let mut stdout = if domains_only {
        Some(tokio::io::stdout())
    } else {
        None
    };

    let mut printed_header = false;
    while let Ok(rec) = rx.recv().await {
        if !domains_only {
            if !printed_header {
                println!("\n{:<40} {:<42} {:<6} {}", "IP", "CERTIFICATE DOMAIN", "GEO", "ISSUER");
                println!("{}", "-".repeat(105));
                printed_header = true;
            }
            println!(
                "{:<40} {:<42} {:<6} {}",
                rec.ip, rec.cert_domain, rec.geo, rec.cert_issuer
            );
        }
        if let Some(f) = file.as_mut() {
            let line = format_record(&rec);
            f.write_all(line.as_bytes()).await?;
        }
        if let Some(f) = html.as_mut() {
            f.write_all(html_row(&rec).as_bytes()).await?;
        }
        if let Some(stdout) = stdout.as_mut() {
            stdout.write_all(rec.cert_domain.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    if let Some(mut f) = file {
        f.flush().await?;
    }
    if let Some(mut f) = html {
        f.write_all(HTML_FOOT.as_bytes()).await?;
        f.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resumed_deep_appends_without_overwriting_previous_results() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "realitl-output-test-{}-{nonce}.csv",std::process::id()
        ));
        let target=Record {
            ip:"192.0.2.1".parse().unwrap(), origin:"192.0.2.1".into(),
            cert_domain:"example.com".into(), cert_issuer:"Example CA".into(), geo:"ZZ".into(),tls_ms:100,san_count:2,via_san:true,verified_http:true,
        };
        for append in [false,true] {
            let (tx,rx)=async_channel::bounded(2);
            tx.send(target.clone()).await.unwrap();
            drop(tx);
            writer(rx,path.to_str().unwrap().to_owned(),false,append,None).await.unwrap();
        }
        let text=tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(text.matches("IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE").count(),1);
        assert_eq!(text.matches("192.0.2.1,192.0.2.1,example.com").count(),2);
        tokio::fs::remove_file(path).await.unwrap();
    }
    #[test]
    fn html_escape_defeats_embedded_markup_and_offline_scoring() {
        assert_eq!(html_escape("<script>'&\""),"&lt;script&gt;&#39;&amp;&quot;");
        let rec=Record {ip:"192.0.2.10".parse().unwrap(),
            origin:"x".into(),cert_domain:"safe.example".into(),
            cert_issuer:"<script>alert(1)</script>".into(),geo:"US".into(),
            tls_ms:100,san_count:2,via_san:true,verified_http:true};
        let html=html_row(&rec);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert_eq!(rec.score(),95);
    }
    #[tokio::test]
    async fn unique_csv_html_pair_and_resume_html() {
        let dir=std::env::temp_dir().join(format!("realitl-report-test-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original=dir.join("out.csv");
        std::fs::write(&original,"UNTOUCHED").unwrap();
        let first=reserve_pair(original.to_str().unwrap()).unwrap().unwrap();
        let second=reserve_pair(original.to_str().unwrap()).unwrap().unwrap();
        assert_ne!(first,second);
        assert_eq!(std::fs::read_to_string(&original).unwrap(),"UNTOUCHED");
        for append in [false,true] {
            let (tx,rx)=async_channel::bounded(2);
            tx.send(Record {
                ip:"192.0.2.1".parse().unwrap(),origin:"scope".into(),
                cert_domain:"example.org".into(),cert_issuer:"An issuer".into(),geo:"ZZ".into(),
                tls_ms:200,san_count:3,via_san:true,verified_http:true
            }).await.unwrap();
            drop(tx);
            writer(rx,first.0.clone(),false,append,Some(first.1.clone())).await.unwrap();
        }
        let csv=std::fs::read_to_string(&first.0).unwrap();
        let html=std::fs::read_to_string(&first.1).unwrap();
        assert_eq!(csv.matches("IP,ORIGIN,CERT_DOMAIN").count(),1);
        assert_eq!(csv.matches("example.org").count(),2);
        assert_eq!(html.matches("</html>").count(),1);
        assert_eq!(html.matches("<tr data-score=").count(),2);
        assert!(html.contains("id=\"search\""));
        for p in [first.0,first.1,second.0,second.1] {
            std::fs::remove_file(p).unwrap();
        }
        std::fs::remove_file(original).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn format_record_basic_row() {
        let rec = Record {
            ip: "1.2.3.4".parse().unwrap(),
            origin: "example.com".to_string(),
            cert_domain: "example.com".to_string(),
            cert_issuer: "Let's Encrypt".to_string(),
            geo: "US".to_string(), tls_ms: 95, san_count: 1, via_san: false, verified_http: true,
        };
        assert_eq!(
            format_record(&rec),
            "1.2.3.4,example.com,example.com,\"Let's Encrypt\",US\n"
        );
    }

    #[test]
    fn format_record_quotes_issuer_with_commas() {
        // Issuers with commas (`Let's Encrypt, Inc.`) rely on the surrounding
        // quotes to keep the CSV well-formed. This is why the inner format
        // hard-codes quotes around the issuer only.
        let rec = Record {
            ip: "10.0.0.1".parse().unwrap(),
            origin: "10.0.0.1".to_string(),
            cert_domain: "foo.example".to_string(),
            cert_issuer: "Let's Encrypt, Inc.".to_string(),
            geo: "N/A".to_string(), tls_ms: 95, san_count: 1, via_san: false, verified_http: true,
        };
        assert_eq!(
            format_record(&rec),
            "10.0.0.1,10.0.0.1,foo.example,\"Let's Encrypt, Inc.\",N/A\n"
        );
    }

    #[test]
    fn format_record_ipv6_row() {
        let rec = Record {
            ip: "::1".parse().unwrap(),
            origin: "::1".to_string(),
            cert_domain: "localhost".to_string(),
            cert_issuer: "Self".to_string(),
            geo: "N/A".to_string(), tls_ms: 95, san_count: 1, via_san: false, verified_http: true,
        };
        assert_eq!(
            format_record(&rec),
            "::1,::1,localhost,\"Self\",N/A\n"
        );
    }

    #[test]
    fn format_record_ends_with_newline() {
        let rec = Record {
            ip: "8.8.8.8".parse().unwrap(),
            origin: "dns.google".to_string(),
            cert_domain: "dns.google".to_string(),
            cert_issuer: "Google".to_string(),
            geo: "US".to_string(), tls_ms: 95, san_count: 1, via_san: false, verified_http: true,
        };
        let s = format_record(&rec);
        assert!(s.ends_with('\n'));
    }
}
