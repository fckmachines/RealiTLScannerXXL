use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use crate::stats::Stats;
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

/// Immutable scan context, captured before targets are handed to FAST/DEEP.
/// ASN operator comes from RIPEstat; RDAP block ownership is NOT inferred.
#[derive(Debug, Clone)]
pub struct ReportMeta {
    pub source: String,
    pub planned: Option<u64>,
    pub asn: Option<u32>,
    pub operator: Option<String>,
    pub prefixes: Option<usize>,
    pub asn_total: Option<u64>,
    pub fast: bool,
    pub fast_rate: u32,
    pub deep_rate: u32,
    pub reality_sni: bool,
    pub check_http: bool,
    pub max_domain_length: usize,
    pub started_unix: u64,
}

impl ReportMeta {
    fn header(&self) -> String {
        let src=html_escape(&self.source);
        let info=match (self.asn,self.asn_total,self.prefixes) {
            (Some(asn), Some(total), Some(prefixes))=>{
                let operator=self.operator.as_deref().unwrap_or("не определён");
                let planned=self.planned.unwrap_or(0);
                let scope=if planned < total {"выборка"} else {"все выбранные адреса"};
                format!("AS{asn} · {} · {prefixes} преф. · {total} IPv4 · {scope}",
                    html_escape(operator))
            },
            _=>src.clone()
        };
        let selected=self.planned.map(|x|x.to_string()).unwrap_or_else(||"неизвестно".into());
        let fast=if self.fast {format!("FAST {} SYN/с · ",self.fast_rate)} else {String::new()};
        let policy=if self.reality_sni {"REALITY SNI + HTTPS"} else if self.check_http {"HTTPS"} else {"TLS/ALPN"};
        let length=if self.max_domain_length==0 {"без ограничения".into()}
            else {self.max_domain_length.to_string()};
        format!(r#"<section class="summary" aria-label="Сведения о сканировании">
<div><b>Источник:</b> {info} <span class="muted">· RDAP: не проверено</span></div>
<div><b>Выбрано:</b> {selected} · <b>Проверено:</b> <span id="scan-checked">            </span>
 · <b>Найдено:</b> <span id="scan-found">            </span>
 · <b>Время:</b> <time id="scan-time" data-unix="{}">{}</time></div>
<div class="muted">{fast}DEEP {}/с · {policy} · лимит имени: {length}</div>
</section>"#,self.started_unix,self.started_unix,self.deep_rate)
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
.summary{background:#1f2937;border:1px solid #374151;border-radius:9px;padding:12px 16px;margin:16px 0;line-height:1.8;font-size:.9rem}
.muted{color:#9ca3af}
.domain-cell{white-space:nowrap}.row-actions{display:inline-flex;vertical-align:middle;margin-left:6px;gap:3px}
.action-icon{padding:4px;background:transparent;color:#93c5fd;border:1px solid transparent;border-radius:5px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center}
.action-icon:hover,.action-icon:focus-visible{background:#374151;border-color:#6b7280}
.action-icon svg{width:17px;height:17px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
#copy-status{font-size:.85rem;color:#86efac;margin-left:8px}
details{margin:20px 0;border:1px solid #374151;border-radius:8px;padding:11px 14px;font-size:.9rem}
summary{cursor:pointer;font-weight:600}details p{margin:8px 0}

tr[hidden]{display:none}
.score{font-weight:700;color:#86efac}
a{color:#93c5fd}small{color:#9ca3af}
@media(max-width:750px){body{padding:0 8px}th,td{padding:6px;font-size:.82rem}}
</style></head><body>
<h1>RealiTLScannerXXL · Кандидаты REALITY</h1>
<p>Офлайн-отчёт · технические кандидаты, не гарантия работы Xray.</p>
<!--SCAN_SUMMARY-->
<div class="toolbar"><input id="search" type="search" placeholder="Поиск: IP, домен, страна, CA…" aria-label="Поиск">
<select id="minimum" aria-label="Минимальный балл"><option value="0">Все кандидаты</option><option value="80">Балл ≥ 80</option><option value="90">Балл ≥ 90</option></select>
<span id="count"></span><span id="copy-status" role="status" aria-live="polite"></span></div>
<p class="note">Балл — ориентир для сортировки, а не фильтр пригодности. Нажмите заголовок столбца для сортировки.</p>
<table><thead><tr><th data-key="0">Балл</th><th data-key="1">Домен / SNI</th><th data-key="2">IP</th><th data-key="3">GEO</th><th data-key="4">TLS, мс</th><th data-key="5">SAN</th><th data-key="6">Источник</th><th data-key="7">CA</th></tr></thead><tbody id="results">
"##;
const HTML_FOOT: &str = r##"</tbody></table>
<details id="methodology"><summary>Рейтинг: методика и базовые 60 баллов</summary>
<p><b>+60 за базовый отбор:</b> завершённый TLS 1.3 (клиент предлагает X25519), согласован HTTP/2 (h2), получен сертификат с издателем и найдено имя CN/SAN в заданном лимите. Это единая фиксированная оценка, а не сумма.</p>
<p>В режиме <code>--reality-sni</code> дополнительно обязательны: конкретное имя без wildcard, отсутствие известного CDN-суффикса, DNS содержит проверенный IP, а HTTPS на этом IP (с SNI/Host и обычной проверкой сертификата) возвращает 200/301/302 и не выглядит как парковка. При <code>--check-http</code> HTTPS проверяется отдельно. В обычном режиме без этих флагов DNS/HTTPS и ограничения CDN не обязательны. Исключение стран — только при включённой настройке.</p>
<p><b>Дополнительные баллы:</b> +10 за выбранное SAN-имя, +10 за включённую и пройденную HTTPS-проверку; за время первого TCP/TLS: +15 при &lt;200 мс, +8 при 200–499 мс, +3 при 500–999 мс, иначе +0. Максимум — <b>95</b>, не 100.</p>
<p class="muted">Первоначальное TLS-соединение не проверяет доверие к цепочке сертификатов; при HTTPS такая проверка выполняется. Бонус SAN условный: SAN не надёжнее CN. Оценка не подтверждает стабильность, доступность из других стран, безопасность сайта или работу Xray REALITY и не исключает кандидатов.</p>
</details>
<script>
(()=>{'use strict';
const tbody=document.getElementById('results'),rows=Array.from(tbody.rows);
const query=document.getElementById('search'),min=document.getElementById('minimum');
const count=document.getElementById('count');
const stamp=document.getElementById('scan-time');
if(stamp) {
 const date=new Date(Number(stamp.dataset.unix)*1000);
 if(!Number.isNaN(date.getTime()))stamp.textContent=date.toLocaleString('ru-RU');
}
const copyStatus=document.getElementById('copy-status');
async function copyDomain(domain) {
 // Clipboard may be inaccessible on file:// or restricted browser profiles.
 if(navigator.clipboard && typeof navigator.clipboard.writeText==='function'){
  try {await navigator.clipboard.writeText(domain);return true;} catch(_){}
 }
 const input=document.createElement('textarea');
 input.value=domain;input.readOnly=true;input.setAttribute('aria-hidden','true');
 input.style.position='fixed';input.style.opacity='0';
 document.body.appendChild(input);
 input.focus();input.select();
 let ok=false;
 try {ok=document.execCommand('copy')===true;} catch(_){}
 input.remove();
 return ok;
}
tbody.addEventListener('click',async event=>{
 const button=event.target.closest('button[data-domain]');
 if(!button || !tbody.contains(button))return;
 const domain=button.dataset.domain;
 if(!domain)return;
 const success=await copyDomain(domain);
 copyStatus.textContent=success?'Скопировано: '+domain:'Не удалось скопировать. Выделите домен вручную.';
});
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


const ICON_OPEN: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3h7v7M10 14 21 3"/><path d="M21 13v7a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h7"/></svg>"#;
const ICON_COPY: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>"#;

/// URLs are a *presentation* feature. Reject questionable hostnames in
/// clickable actions without removing the accepted scan candidate.
fn safe_link_domain(name: &str) -> Option<String> {
    if name.len()>253 || name.len()<3 || !name.is_ascii() || !name.contains('.') ||
        name.parse::<IpAddr>().is_ok() {return None;}
    let name=name.strip_suffix('.').unwrap_or(name);
    if name.len()<3 || name.split('.').any(|label| {
        label.is_empty() || label.len()>63 ||
        label.starts_with('-') || label.ends_with('-') ||
        !label.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'-')
    }) {return None;}
    Some(name.to_ascii_lowercase())
}

fn html_row(r: &Record) -> String {
    let score=r.score();
    let via=if r.via_san {"SAN"} else {"CN"};
    let domain=html_escape(&r.cert_domain);
    let actions=if let Some(target)=safe_link_domain(&r.cert_domain) {
        let value=html_escape(&target);
        format!(r#"<span class="row-actions"><a class="action-icon" title="Открыть сайт" aria-label="Открыть сайт: {value}" href="https://{value}/" target="_blank" rel="noopener noreferrer">{ICON_OPEN}</a><button type="button" class="action-icon" title="Скопировать домен" aria-label="Скопировать домен: {value}" data-domain="{value}">{ICON_COPY}</button></span>"#)
    } else {String::new()};
    format!("<tr data-score=\"{score}\"><td class=\"score\">{score}</td><td class=\"domain-cell\">{domain}{actions}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{via}</td><td>{}</td></tr>\n",
        r.ip, html_escape(&r.geo), r.tls_ms,r.san_count,html_escape(&r.cert_issuer))
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

async fn open_html(path: &str, append: bool, meta: Option<&ReportMeta>) -> anyhow::Result<BufWriter<tokio::fs::File>> {
    if !append {
        let file=tokio::fs::OpenOptions::new().write(true).truncate(true).open(path).await?;
        let mut writer=BufWriter::new(file);
        let header=HTML_HEAD.replace("<!--SCAN_SUMMARY-->", &meta.map(ReportMeta::header).unwrap_or_default());
        writer.write_all(header.as_bytes()).await?;
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

/// Update two fixed-width numeric placeholders without rewriting potentially
/// massive HTML or disturbing the exact footer required for Ctrl+C resume.
/// Width is fixed, ASCII-only, and can be patched after BufWriter is closed.
async fn patch_html_counts(path: &str, checked: u64, found: u64) -> anyhow::Result<()> {
    let mut file=tokio::fs::OpenOptions::new().read(true).write(true).open(path).await?;
    let size=file.metadata().await?.len().min(16_384) as usize;
    let mut start=vec![0u8;size];
    file.read_exact(&mut start).await?;
    for (id,amount) in [("scan-checked",checked),("scan-found",found)] {
        let marker=format!("id=\"{id}\">");
        if let Some(index)=start.windows(marker.len()).position(|window| window==marker.as_bytes()) {
            anyhow::ensure!(amount<1_000_000_000_000,"Слишком большой счётчик");
            let offset=(index+marker.len()) as u64;
            file.seek(SeekFrom::Start(offset)).await?;
            file.write_all(format!("{amount:>12}").as_bytes()).await?;
        } else {
            // Legacy test calls without metadata leave the header absent.
            continue;
        }
    }
    file.flush().await?;
    Ok(())
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
    meta: Option<Arc<ReportMeta>>,
    stats: Option<Arc<Stats>>,
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
        Some(ref path) => Some(open_html(path,append,meta.as_deref()).await?),
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
    let mut saved_rows = 0u64;
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
            saved_rows += 1;
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
        drop(f);
        if meta.is_some() {
            if let Some(path)=html_path.as_deref() {
                let (checked,found)=if let Some(stats)=stats.as_ref() {
                    let snapshot=stats.snapshot();
                    (snapshot.processed(),snapshot.accepted())
                } else {(saved_rows,saved_rows)};
                patch_html_counts(path,checked,found).await?;
            }
        }
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
            writer(rx,path.to_str().unwrap().to_owned(),false,append,None,None,None).await.unwrap();
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
            writer(rx,first.0.clone(),false,append,Some(first.1.clone()),None,None).await.unwrap();
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
    fn domain_actions_are_icons_only_and_safe() {
        let good=Record {ip:"192.0.2.1".parse().unwrap(),origin:"a".into(),
            cert_domain:"WWW.Example.org".into(),cert_issuer:"Let's Encrypt".into(),
            geo:"US".into(),tls_ms:27,san_count:2,via_san:false,verified_http:true};
        let html=html_row(&good);
        assert!(html.contains("href=\"https://www.example.org/\""));
        assert!(html.contains("data-domain=\"www.example.org\""));
        assert!(html.contains("title=\"Скопировать домен\""));
        assert!(html.contains("title=\"Открыть сайт\""));
        assert!(!html.contains(">Открыть<"));
        assert!(!html.contains(">Копировать<"));
        assert_eq!(safe_link_domain("javascript:alert(1)"),None);
        assert_eq!(safe_link_domain("evil.example/\"onclick=\"hack"),None);
        assert_eq!(safe_link_domain("bad..example"),None);
        assert_eq!(safe_link_domain("bad_example.org"),None);
        assert_eq!(safe_link_domain("evil.example<script>"),None);
        let mut malicious=good.clone();
        malicious.cert_domain="https://evil.example/<script>".into();
        let markup=html_row(&malicious);
        assert!(!markup.contains("href="));
        assert!(!markup.contains("data-domain="));
        assert!(markup.contains("&lt;script&gt;"));
    }
    #[test]
    fn compact_metadata_cannot_inject_markup_and_does_not_invent_rdap() {
        let meta=ReportMeta {source:"AS123".into(),planned:Some(4096),asn:Some(123),
            operator:Some("<script>alert(1)</script>".into()),prefixes:Some(7),
            asn_total:Some(50_000),fast:true,fast_rate:100,deep_rate:10,
            reality_sni:true,check_http:true,max_domain_length:20,started_unix:1793491200};
        let rendered=meta.header();
        assert!(rendered.contains("AS123"));
        assert!(rendered.contains("4096"));
        assert!(rendered.contains("&lt;script&gt;"));
        assert!(!rendered.contains("<script>"));
        assert!(rendered.contains("RDAP: не проверено"));
        assert!(rendered.contains("выборка"));
        let plain=ReportMeta{source:"192.0.2.0/24".into(),asn:None,operator:None,
            prefixes:None,asn_total:None,..meta};
        assert!(plain.header().contains("192.0.2.0/24"));
        assert!(!plain.header().contains("AS123"));
    }
    #[tokio::test]
    async fn metadata_counts_updated_after_writer_exit() {
        let dir=std::env::temp_dir();
        let name=format!("realitl-metadata-{}-{}.html",std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let path=dir.join(name);
        tokio::fs::File::create(&path).await.unwrap();
        let meta=ReportMeta {source:"192.0.2.0/24".into(),planned:Some(256),
            asn:None,operator:None,prefixes:None,asn_total:None,fast:false,
            fast_rate:100,deep_rate:10,reality_sni:false,check_http:false,
            max_domain_length:20,started_unix:1793491200};
        let (tx,rx)=async_channel::bounded(1);
        tx.send(Record {ip:"192.0.2.1".parse().unwrap(),origin:"x".into(),
            cert_domain:"example.org".into(),cert_issuer:"Test CA".into(),geo:"ZZ".into(),
            tls_ms:150,san_count:1,via_san:false,verified_http:false}).await.unwrap();
        drop(tx);
        writer(rx,String::new(),true,false,Some(path.to_string_lossy().to_string()),
            Some(Arc::new(meta)),None).await.unwrap();
        let html=tokio::fs::read_to_string(&path).await.unwrap();
        assert!(html.contains("id=\"scan-checked\">           1</span>"));
        assert!(html.contains("id=\"scan-found\">           1</span>"));
        assert!(html.contains("<details id=\"methodology\">"));
        assert!(html.contains("navigator.clipboard"));
        assert!(html.contains("execCommand('copy')"));
        tokio::fs::remove_file(path).await.unwrap();
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
