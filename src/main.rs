mod banner;
mod cli;
mod filter;
mod geo;
mod host;
mod iterate;
mod interrupt;
mod masscan;
mod menu;
mod network;
mod output;
mod progress;
mod resolver;
mod scanner;
mod stats;

use crate::cli::Cli;
use crate::geo::Geo;
use crate::host::{Host, HostType};
use crate::output::Record;
use crate::resolver::DnsResolver;
use crate::stats::Stats;
use anyhow::Result;
use clap::Parser;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io::IsTerminal;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tracing_subscriber::EnvFilter;

/// Insecure `ServerCertVerifier` that accepts any presented certificate. This
/// mirrors Go's `InsecureSkipVerify: true`. Forced TLS 1.3 means the
/// `verify_tls12_signature` arm is never reached at runtime.
#[derive(Debug)]
struct NoVerifier {
    supported: Vec<SignatureScheme>,
}

impl NoVerifier {
    fn new(supported: Vec<SignatureScheme>) -> Self {
        Self { supported }
    }
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only — should never be called.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.clone()
    }
}

fn init_tracing(verbose: bool, domains_only: bool) {
    let level = if verbose { "debug" } else { "warn" };
    // Pin hickory to `warn` so a large domain sweep does not flood stderr with
    // per-query trace lines even if the user cranks `realitlscanner` to debug.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("realitlscanner={level},hickory_resolver=warn,warn"))
    });

    // When --domains-only is set, stdout is reserved for cert domain output,
    // so logs go to stderr. Otherwise, logs go to stdout (matching Go's
    // slog.NewTextHandler(os.Stdout, ...)).
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if domains_only {
        builder.with_writer(std::io::stderr).init();
    } else {
        builder.with_writer(std::io::stdout).init();
    }
}

fn build_client_config() -> Result<Arc<rustls::ClientConfig>> {
    // Start from the ring default provider and restrict kx groups to X25519,
    // matching Go's `tls.CurvePreferences: []tls.CurveID{tls.X25519}`.
    let mut provider = ring_provider::default_provider();
    provider.kx_groups = vec![ring_provider::kx_group::X25519];

    let supported_schemes = provider.signature_verification_algorithms.supported_schemes();

    let provider = Arc::new(provider);

    let cfg_builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?;

    let mut cfg = cfg_builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier::new(supported_schemes)))
        .with_no_client_auth();

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Exact size for simple finite IP/CIDR input. Streaming URLs, files and
/// legacy bare-IP neighbor walks have unknown totals until fully enumerated.
fn finite_addr_total(addr: &str) -> Option<u64> {
    use ipnet::IpNet;
    let mut total=0u64;
    let values:Vec<&str>=if addr.contains(',') {addr.split(',').collect()}
        else if addr.contains('/') {vec![addr]} else {return None};
    for value in values {
        let value=value.trim();
        let count=if let Ok(net)=value.parse::<IpNet>() {
            match net {
                IpNet::V4(v4) => 1u64 << (32-v4.prefix_len()),
                IpNet::V6(v6) => {
                    let exponent=(128-v6.prefix_len()) as u32;
                    1u64.checked_shl(exponent)?
                }
            }
        } else if value.parse::<std::net::IpAddr>().is_ok() || crate::host::validate_domain(value) {
            1
        } else {return None};
        total=total.checked_add(count)?;
    }
    Some(total)
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    #[test]
    fn counts_finite_addr_without_iterating_huge_networks() {
        assert_eq!(finite_addr_total("192.0.2.0/24"),Some(256));
        assert_eq!(finite_addr_total("192.0.2.0/24,198.51.100.1"),Some(257));
        assert_eq!(finite_addr_total("0.0.0.0/0"),Some(4_294_967_296));
        assert_eq!(finite_addr_total("192.0.2.1"),None);
        assert_eq!(finite_addr_total("invalid /bogus"),None);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Match Go's environment hygiene before any HTTP/TLS activity.
    std::env::remove_var("ALL_PROXY");
    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("HTTPS_PROXY");
    std::env::remove_var("NO_PROXY");

    // With no arguments, show an interactive menu rather than clap's
    // "missing required arguments" error. Scripted calls remain unchanged.
    let interactive_menu = std::env::args_os().len() == 1;
    let (cli, preloaded_asn) = if interactive_menu {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            anyhow::bail!("Для пакетного запуска укажите --addr, --asn, --in или --url");
        }
        banner::show();
        let identity = tokio::time::timeout(Duration::from_secs(8), network::discover())
            .await.unwrap_or_default();
        identity.display();
        let Some(choice) = menu::choose(&identity).await? else { return Ok(()); };
        (choice.cli, choice.plan)
    } else {
        let cli = Cli::parse();
        if !cli.domains_only && std::io::stdout().is_terminal() {
            banner::show();
            if !cli.no_network_info {
                let identity = tokio::time::timeout(Duration::from_secs(8), network::discover())
                    .await.unwrap_or_default();
                identity.display();
            }
        }
        (cli, None)
    };
    init_tracing(cli.verbose, cli.domains_only);

    if cli.fast {
        anyhow::ensure!(!cli.ipv6, "FAST SCAN поддерживает только IPv4. Уберите --46 или используйте DEEP SCAN.");
        anyhow::ensure!(cli.url.is_none(), "FAST SCAN не поддерживает --url (домены).");
        if let Some(target) = &cli.addr {
            anyhow::ensure!(
                target.contains('/') || target.contains(','),
                "FAST SCAN требует конечный диапазон: используйте --addr IP/32, CIDR или список через запятую"
            );
        }
    }

    // Preflight before spawning the writer. Invalid ASN/API requests must
    // leave an existing out.csv untouched; the same plan is used for scanning.
    let asn_job = if let Some(asn) = cli.asn.as_ref() {
        let plan = match preloaded_asn {
            Some(plan) => plan,
            None => network::fetch_plan(asn).await?,
        };
        let selected = plan.selected(cli.max_ips, cli.all);
        eprintln!("\n{}", plan.preview(selected));
        if selected < plan.total {
            eprintln!("ВНИМАНИЕ: частичная выборка из ASN, это НЕ полный скан.");
        } else if cli.all {
            eprintln!("ВНИМАНИЕ: выбран полный скан всех {} IPv4!", plan.total);
        }
        Some((plan, selected))
    } else {
        None
    };

    let cfg = build_client_config()?;
    // Build the TlsConnector once; internally Arc-backed, so per-worker
    // clones are cheap (one atomic refcount bump) and keep probe() cleaner.
    let connector = TlsConnector::from(cfg);

    let geo = Arc::new(Geo::load(&cli.mmdb));
    let resolver: Arc<DnsResolver> = resolver::build();

    let thread_count = cli.thread.max(1);
    let timeout_dur = Duration::from_secs(cli.timeout);

    // Strict Reality filtering includes IP-pinned HTTPS verification.
    let check_http = cli.check_http || cli.reality_sni;

    // Build one `ProbeParams` up front; workers clone it per spawn (cheap —
    // `exclude_geo` is an Arc and the rest is Copy).
    let params = scanner::ProbeParams {
        port: cli.port,
        timeout: timeout_dur,
        ipv6: cli.ipv6,
        reality_sni: cli.reality_sni,
        check_http,
        max_domain_length: cli.max_domain_length,
        exclude_geo: Arc::new(
            cli.exclude_geo
                .iter()
                .map(|s| s.to_ascii_uppercase())
                .collect(),
        ),
    };
    // Record channel sized proportional to workers so bursts of feasible
    // hits (e.g. large IP sweeps) do not stall probe tasks on the writer.
    let rec_cap = (thread_count * 2).max(256);
    let (tx_host, rx_host) = async_channel::bounded::<Host>(thread_count * 4);
    let (mut tx_rec, mut rx_rec) = async_channel::bounded::<Record>(rec_cap);
    let stats = Arc::new(Stats::default());

    // --- producer ---
    let source_total = asn_job.as_ref().map(|(_, selected)| *selected)
        .or_else(|| cli.addr.as_deref().and_then(finite_addr_total));
    let ipv6 = cli.ipv6;
    let tx_host_producer = tx_host.clone();
    let producer: tokio::task::JoinHandle<Result<()>> = if let Some(addr) = cli.addr.clone() {
        let resolver_c = resolver.clone();
        tokio::spawn(async move {
            iterate::from_addr(addr, ipv6, resolver_c, tx_host_producer).await
        })
    } else if let Some((plan, selected)) = asn_job {
        tokio::spawn(async move {
            iterate::from_asn(plan, selected, tx_host_producer).await
        })
    } else if let Some(path) = cli.input.clone() {
        tokio::spawn(async move {
            iterate::from_file(&path, ipv6, tx_host_producer).await
        })
    } else if let Some(url) = cli.url.clone() {
        tokio::spawn(async move {
            iterate::from_url(url, ipv6, tx_host_producer).await
        })
    } else {
        unreachable!("clap should enforce exactly one source");
    };
    // Drop the outer sender so workers exit once the producer completes.
    drop(tx_host);

    let mut producer_handle = Some(producer);
    // FAST runs before the CSV writer, so early failure/interruption cannot
    // truncate verified rows from a previous run.
    let mut fast_was_interrupted = false;
    let mut total = source_total;
    let mut rx_host = if cli.fast {
        let workspace = tokio::select! {
            result = masscan::spool(rx_host) => match result {
                Ok(workspace) => workspace,
                Err(err) => {
                    producer_handle.take().expect("producer exists").abort();
                    return Err(err);
                }
            },
            _ = tokio::signal::ctrl_c() => {
                producer_handle.take().expect("producer exists").abort();
                eprintln!("[FAST] Прервано до начала Masscan: открытые IP пока не получены.");
                if !interrupt::can_prompt(cli.domains_only) { std::process::exit(130); }
                return Ok(());
            }
        };
        producer_handle.take().expect("producer exists").await??;
        let discovered = masscan::discover(&workspace, cli.port, cli.fast_rate, cli.fast_wait).await?;
        fast_was_interrupted = discovered.interrupted;
        total = Some(discovered.addresses.len() as u64);
        let found:Vec<Host> = discovered.addresses.into_iter().map(|ip|Host {
            ip:Some(std::net::IpAddr::V4(ip)),
            origin:ip.to_string(),
            kind:HostType::Ip,
        }).collect();
        if fast_was_interrupted {
            let choice = if interrupt::can_prompt(cli.domains_only) {
                interrupt::prompt("FAST", found.len(), 0, 0).await
            } else {
                interrupt::Decision::Finish
            };
            if choice != interrupt::Decision::Process || found.is_empty() {
                if let Some(path)=interrupt::checkpoint(&found,&cli.out)? {
                    eprintln!("[FAST] Сохранено {} IP: {}",found.len(),path.display());
                } else {
                    eprintln!("[FAST] Открытых IP не получено.");
                }
                if !interrupt::can_prompt(cli.domains_only) {std::process::exit(130);}
                return Ok(());
            }
        }
        let (tx, rx) = async_channel::unbounded();
        for host in found { tx.try_send(host)?; }
        drop(tx);
        rx
    } else {
        rx_host
    };

    // Each DEEP round terminates and flushes its writer before presenting
    // interruption choices. Continuation creates a new append-mode writer:
    // previously verified rows are preserved, never overwritten.
    let deep_started = std::time::Instant::now();
    let mut append = false;
    loop {
        let writer_handle = tokio::spawn(output::writer(
            rx_rec, cli.out.clone(), cli.domains_only, append
        ));
        let paused = Arc::new(AtomicBool::new(false));
        let (tx_deferred, rx_deferred) = async_channel::unbounded::<Host>();
        let mut cadence = tokio::time::interval(
            Duration::from_nanos(1_000_000_000 / u64::from(cli.deep_rate))
        );
        cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let deep_pacer = Arc::new(tokio::sync::Mutex::new(cadence));
        let mut workers = JoinSet::new();
        for _ in 0..thread_count {
            let rx = rx_host.clone();
            let connector = connector.clone();
            let resolver = resolver.clone();
            let geo = geo.clone();
            let stats = stats.clone();
            let out = tx_rec.clone();
            let params = params.clone();
            let deep_pacer = deep_pacer.clone();
            let paused = paused.clone();
            let deferred = tx_deferred.clone();
            workers.spawn(async move {
                while let Ok(host) = rx.recv().await {
                    if paused.load(Ordering::SeqCst) {
                        let _ = deferred.try_send(host);
                        break;
                    }
                    deep_pacer.lock().await.tick().await;
                    if paused.load(Ordering::SeqCst) {
                        let _ = deferred.try_send(host);
                        break;
                    }
                    let outcome = scanner::probe(
                        host,
                        connector.clone(),
                        resolver.clone(),
                        geo.clone(),
                        out.clone(),
                        &params,
                    ).await;
                    stats.record(outcome);
                }
            });
        }
        drop(tx_rec);
        drop(tx_deferred);

        let show_progress = std::io::stderr().is_terminal();
        if show_progress {
            eprintln!("SCAN | workers: {thread_count} | port: {} | DEEP: до {} стартов/с | HTTP: {}",
                cli.port,cli.deep_rate, if check_http {"YES"} else {"NO"});
            eprintln!("Результаты: {}",if cli.out.is_empty() {"(выключено)"} else {&cli.out});
            eprintln!("{}",progress::line(
                "DEEP",stats.snapshot().processed(),total,deep_started.elapsed()));
        }
        let progress_handle = if show_progress {
            let stats = stats.clone();
            Some(tokio::spawn(async move {
                let mut tick=tokio::time::interval(Duration::from_secs(2));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    eprintln!("{}",progress::line(
                        "DEEP",stats.snapshot().processed(),total,deep_started.elapsed()));
                }
            }))
        } else {None};

        let mut interrupted = false;
        tokio::select! {
            _ = wait_workers(&mut workers) => {}
            _ = tokio::signal::ctrl_c() => {
                interrupted = true;
                paused.store(true,Ordering::SeqCst);
                if let Some(producer)=producer_handle.take() {
                    producer.abort();
                    let _ = producer.await;
                }
                eprintln!("[DEEP] Ctrl+C: останавливаем новые проверки, завершаем начатые...");
                tokio::select! {
                    _ = wait_workers(&mut workers) => {}
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("[DEEP] Повторный Ctrl+C: завершаем активные задачи.");
                        workers.abort_all();
                        wait_workers(&mut workers).await;
                    }
                }
            }
        }

        let writer_result=writer_handle.await?;
        if let Some(handle)=progress_handle {handle.abort();}
        writer_result?;
        if !interrupted {
            if let Some(producer)=producer_handle.take() {
                producer.await??;
            }
            if !cli.domains_only {
                eprintln!("{}",progress::line(
                    "DEEP",stats.snapshot().processed(),total,deep_started.elapsed()));
                println!("\nИТОГ СКАНИРОВАНИЯ\n{}",stats.snapshot().summary(deep_started.elapsed()));
                if fast_was_interrupted {
                    println!("FAST был прерван: обработаны только ранее найденные IP.");
                }
                println!("Примечание: TLS/HTTPS-кандидат не гарантирует совместимость с Xray REALITY.");
            }
            return Ok(());
        }

        let mut pending=Vec::new();
        while let Ok(host)=rx_deferred.try_recv() {pending.push(host);}
        while let Ok(host)=rx_host.try_recv() {pending.push(host);}
        let snap=stats.snapshot();
        eprintln!("[DEEP] Пауза: завершено {}, кандидатов {}, в очереди {}.",
            snap.processed(),snap.accepted(),pending.len());
        let choice=if interrupt::can_prompt(cli.domains_only) {
            interrupt::prompt("DEEP",pending.len(),snap.processed(),snap.accepted()).await
        } else {interrupt::Decision::Finish};
        if choice == interrupt::Decision::Process && !pending.is_empty() {
            total=Some(snap.processed()+pending.len() as u64);
            let (tx,rx)=async_channel::unbounded();
            for host in pending {tx.try_send(host)?;}
            drop(tx);
            rx_host=rx;
            (tx_rec,rx_rec)=async_channel::bounded::<Record>(rec_cap);
            append=true;
            continue;
        }
        if let Some(path)=interrupt::checkpoint(&pending,&cli.out)? {
            eprintln!("[DEEP] Сохранено {} непроверенных целей: {}",pending.len(),path.display());
        } else {
            eprintln!("[DEEP] Необработанных целей в очереди нет.");
        }
        if !cli.domains_only {
            println!("\nЧАСТИЧНЫЙ ИТОГ\n{}",stats.snapshot().summary(deep_started.elapsed()));
        }
        if !interrupt::can_prompt(cli.domains_only) {
            std::process::exit(130);
        }
        return Ok(());
    }
}

async fn wait_workers(workers: &mut JoinSet<()>) {
    while workers.join_next().await.is_some() {}
}
