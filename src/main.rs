mod banner;
mod cli;
mod filter;
mod geo;
mod host;
mod iterate;
mod masscan;
mod menu;
mod network;
mod output;
mod resolver;
mod scanner;
mod stats;

use crate::cli::Cli;
use crate::geo::Geo;
use crate::host::Host;
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
    let (tx_rec, rx_rec) = async_channel::bounded::<Record>(rec_cap);
    let stats = Arc::new(Stats::default());

    // --- producer ---
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
    // FAST is a distinct, complete discovery stage. Do not open/truncate the
    // result CSV or start TLS workers until the SYN scan has succeeded.
    let rx_host = if cli.fast {
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
                return Ok(());
            }
        };
        // Failure reading an input file is reported *before* any Masscan
        // process runs. The private spool directory is then removed.
        producer_handle.take().expect("producer exists").await??;
        let discovered = tokio::select! {
            result = masscan::discover(&workspace, cli.port, cli.fast_rate, cli.fast_wait) => result?,
            _ = tokio::signal::ctrl_c() => return Ok(()),
        };
        let (tx, rx) = async_channel::unbounded();
        for ip in discovered {
            tx.try_send(Host {
                ip: Some(std::net::IpAddr::V4(ip)),
                origin: ip.to_string(),
                kind: crate::host::HostType::Ip,
            })?;
        }
        drop(tx);
        rx
    } else {
        rx_host
    };

    // --- writer ---
    let out_path = cli.out.clone();
    let domains_only = cli.domains_only;
    let writer_handle = tokio::spawn(output::writer(rx_rec, out_path, domains_only));

    // --- workers ---
    let mut workers = JoinSet::new();
    for _ in 0..thread_count {
        let rx = rx_host.clone();
        let connector = connector.clone();
        let resolver = resolver.clone();
        let geo = geo.clone();
        let stats = stats.clone();
        let out = tx_rec.clone();
        let params = params.clone();
        workers.spawn(async move {
            while let Ok(h) = rx.recv().await {
                let outcome = scanner::probe(
                    h,
                    connector.clone(),
                    resolver.clone(),
                    geo.clone(),
                    out.clone(),
                    &params,
                )
                .await;
                stats.record(outcome);
            }
        });
    }
    // Drop the outer receiver/sender so that the channel closes once all
    // spawned clones finish.
    drop(rx_host);
    drop(tx_rec);

    let started = std::time::Instant::now();
    let show_progress = !cli.domains_only && std::io::stdout().is_terminal();
    if show_progress {
        println!("SCAN | threads: {} | port: {} | HTTP bound to scanned IP: {}",
            thread_count, cli.port, if check_http { "YES" } else { "NO" });
        println!("Результаты сохраняются в: {}", if cli.out.is_empty() { "(выключено)" } else { &cli.out });
    }
    let progress_handle = if show_progress {
        let stats = stats.clone();
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3));
            tick.tick().await;
            loop {
                tick.tick().await;
                let snapshot = stats.snapshot();
                eprintln!("[SCAN] проверено: {} | кандидатов: {} | отклонено: {} | {:.1} IP/с",
                    snapshot.processed(),
                    snapshot.accepted(),
                    snapshot.rejected(),
                    snapshot.processed() as f64 / started.elapsed().as_secs_f64().max(0.001));
            }
        }))
    } else {
        None
    };

    // Coordinated shutdown: watch for ctrl_c; when it fires, abort the
    // producer so it drops its Host sender, which lets workers drain and
    // exit. Matches spec item (11).
    let mut interrupted = false;
    let producer_result = if let Some(producer_handle) = producer_handle {
        // Legacy DEEP-only mode retains its streaming producer and ctrl-c drain.
        tokio::select! {
            _ = wait_workers(&mut workers) => {}
            _ = tokio::signal::ctrl_c() => {
                interrupted = true;
                producer_handle.abort();
                wait_workers(&mut workers).await;
            }
        }
        if interrupted { Ok(()) } else { producer_handle.await? }
    } else {
        // FAST stage has already finished; Deep workers only consume the
        // discovered, finite, and bounded list.
        tokio::select! {
            _ = wait_workers(&mut workers) => {}
            _ = tokio::signal::ctrl_c() => {
                interrupted = true;
                workers.abort_all();
                wait_workers(&mut workers).await;
            }
        }
        Ok(())
    };

    // At this point, workers are done; drop the last Record sender by waiting
    // for the writer.
    let writer_result = writer_handle.await?;
    if let Some(handle) = progress_handle {
        handle.abort();
    }
    producer_result?;
    writer_result?;
    if !cli.domains_only {
        println!("\nИТОГ СКАНИРОВАНИЯ\n{}", stats.snapshot().summary(started.elapsed()));
        println!("Примечание: TLS/HTTPS-кандидат не гарантирует совместимость с Xray REALITY.");
    }

    Ok(())
}

async fn wait_workers(workers: &mut JoinSet<()>) {
    while workers.join_next().await.is_some() {}
}
