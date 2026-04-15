mod cli;
mod filter;
mod geo;
mod host;
mod iterate;
mod output;
mod resolver;
mod scanner;

use crate::cli::Cli;
use crate::geo::Geo;
use crate::host::Host;
use crate::output::Record;
use crate::resolver::DnsResolver;
use anyhow::Result;
use clap::Parser;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
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
    let level = if verbose { "debug" } else { "info" };
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

    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.domains_only);

    let cfg = build_client_config()?;
    // Build the TlsConnector once; internally Arc-backed, so per-worker
    // clones are cheap (one atomic refcount bump) and keep probe() cleaner.
    let connector = TlsConnector::from(cfg);

    let geo = Arc::new(Geo::load(&cli.mmdb));
    let resolver: Arc<DnsResolver> = resolver::build();

    let thread_count = cli.thread.max(1);
    let timeout_dur = Duration::from_secs(cli.timeout);

    // `--reality-sni` implies `--check-http`. Build a shared reqwest client
    // once if either flag asks for HTTP probing, otherwise leave it None.
    let check_http = cli.check_http || cli.reality_sni;
    let http_client: Option<Arc<reqwest::Client>> = if check_http {
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(timeout_dur)
            .timeout(timeout_dur)
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                 AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/120.0.0.0 Safari/537.36",
            )
            .build()?;
        Some(Arc::new(client))
    } else {
        None
    };

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

    // --- producer ---
    let ipv6 = cli.ipv6;
    let tx_host_producer = tx_host.clone();
    let producer: tokio::task::JoinHandle<()> = if let Some(addr) = cli.addr.clone() {
        let resolver_c = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = iterate::from_addr(addr, ipv6, resolver_c, tx_host_producer).await {
                tracing::error!(error = %e, "producer failed");
            }
        })
    } else if let Some(path) = cli.input.clone() {
        tokio::spawn(async move {
            if let Err(e) = iterate::from_file(&path, ipv6, tx_host_producer).await {
                tracing::error!(error = %e, "producer failed");
            }
        })
    } else if let Some(url) = cli.url.clone() {
        tokio::spawn(async move {
            if let Err(e) = iterate::from_url(url, ipv6, tx_host_producer).await {
                tracing::error!(error = %e, "producer failed");
            }
        })
    } else {
        // clap's ArgGroup(required=true) should prevent this branch.
        unreachable!("clap should enforce exactly one of --addr/--in/--url");
    };
    // Drop the outer sender so workers exit once the producer completes.
    drop(tx_host);

    // --- writer ---
    let out_path = cli.out.clone();
    let domains_only = cli.domains_only;
    let writer_handle = tokio::spawn(async move {
        if let Err(e) = output::writer(rx_rec, out_path, domains_only).await {
            tracing::error!(error = %e, "writer failed");
        }
    });

    // --- workers ---
    let mut workers = JoinSet::new();
    for _ in 0..thread_count {
        let rx = rx_host.clone();
        let connector = connector.clone();
        let resolver = resolver.clone();
        let geo = geo.clone();
        let http_client = http_client.clone();
        let out = tx_rec.clone();
        let params = params.clone();
        workers.spawn(async move {
            while let Ok(h) = rx.recv().await {
                scanner::probe(
                    h,
                    connector.clone(),
                    resolver.clone(),
                    geo.clone(),
                    http_client.clone(),
                    out.clone(),
                    &params,
                )
                .await;
            }
        });
    }
    // Drop the outer receiver/sender so that the channel closes once all
    // spawned clones finish.
    drop(rx_host);
    drop(tx_rec);

    let started = std::time::Instant::now();
    tracing::info!("Started all scanning threads");

    // Coordinated shutdown: watch for ctrl_c; when it fires, abort the
    // producer so it drops its Host sender, which lets workers drain and
    // exit. Matches spec item (11).
    let producer_handle = producer;
    tokio::select! {
        _ = wait_workers(&mut workers) => {
            // Natural completion.
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl_c received, shutting down");
            producer_handle.abort();
            wait_workers(&mut workers).await;
        }
    }

    // At this point, workers are done; drop the last Record sender by waiting
    // for the writer.
    let _ = writer_handle.await;

    let elapsed = started.elapsed();
    tracing::info!(elapsed = ?elapsed, "Scanning completed");

    Ok(())
}

async fn wait_workers(workers: &mut JoinSet<()>) {
    while workers.join_next().await.is_some() {}
}
