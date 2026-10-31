//! Lock-free counters shared by scan workers, including rejected candidates.
use std::array;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Outcome {
    Accepted = 0,
    DnsFailed,
    ConnectionFailed,
    TlsIncompatible,
    DomainTooLong,
    WildcardCert,
    SharedCdn,
    ExcludedGeo,
    ForwardDnsFailed,
    HttpFailed,
}

impl Outcome {
    const ALL: [Self; 10] = [
        Self::Accepted,
        Self::DnsFailed,
        Self::ConnectionFailed,
        Self::TlsIncompatible,
        Self::DomainTooLong,
        Self::WildcardCert,
        Self::SharedCdn,
        Self::ExcludedGeo,
        Self::ForwardDnsFailed,
        Self::HttpFailed,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Accepted => "Кандидаты",
            Self::DnsFailed => "DNS не разрешился",
            Self::ConnectionFailed => "Нет TCP/TLS ответа",
            Self::TlsIncompatible => "TLS/ALPN/сертификат",
            Self::DomainTooLong => "Слишком длинный домен",
            Self::WildcardCert => "Wildcard-сертификат",
            Self::SharedCdn => "Общий CDN-сертификат",
            Self::ExcludedGeo => "Исключённая страна",
            Self::ForwardDnsFailed => "DNS не совпал с IP",
            Self::HttpFailed => "HTTPS на IP не прошёл",
        }
    }
}

pub struct Stats {
    counts: [AtomicU64; 10],
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            counts: array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    counts: [u64; 10],
}

impl Snapshot {
    pub fn processed(&self) -> u64 {
        self.counts.iter().sum()
    }

    pub fn accepted(&self) -> u64 {
        self.counts[Outcome::Accepted as usize]
    }

    pub fn rejected(&self) -> u64 {
        self.processed().saturating_sub(self.accepted())
    }

    pub fn summary(&self, elapsed: Duration) -> String {
        let secs = elapsed.as_secs_f64().max(0.001);
        let mut lines = vec![format!(
            "Проверено: {} | кандидатов: {} | отклонено: {} | {:.1} IP/с | {:.1} с",
            self.processed(),
            self.accepted(),
            self.rejected(),
            self.processed() as f64 / secs,
            secs,
        )];
        for outcome in Outcome::ALL.into_iter().filter(|o| !matches!(o, Outcome::Accepted)) {
            let count = self.counts[outcome as usize];
            if count > 0 {
                lines.push(format!("  {:<27} {:>8}", outcome.label(), count));
            }
        }
        lines.join("\n")
    }
}

impl Stats {
    pub fn record(&self, outcome: Outcome) {
        self.counts[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            counts: array::from_fn(|i| self.counts[i].load(Ordering::Relaxed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_account_for_all_probes() {
        let stats = Stats::default();
        stats.record(Outcome::Accepted);
        stats.record(Outcome::HttpFailed);
        stats.record(Outcome::ConnectionFailed);
        stats.record(Outcome::DomainTooLong);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.processed(), 4);
        assert_eq!(snapshot.accepted(), 1);
        assert_eq!(snapshot.rejected(), 3);
        let summary = snapshot.summary(Duration::from_secs(2));
        assert!(summary.contains("Проверено: 4"));
        assert!(summary.contains("Слишком длинный домен"));
        assert!(summary.contains("HTTPS на IP"));
    }
}
