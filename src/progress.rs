//! Terminal-safe progress accounting. FAST's emitted count is an estimate
//! from Masscan's configured rate, never a claim of observed packets.
use std::time::Duration;

pub fn line(stage: &str, done: u64, total: Option<u64>, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64().max(0.001);
    let speed = done as f64 / seconds;
    match total {
        Some(total) => {
            let done = done.min(total);
            let remaining = total.saturating_sub(done);
            let percent = if total == 0 { 100.0 } else {
                done as f64 * 100.0 / total as f64
            };
            let eta = if remaining == 0 {
                "0s".to_owned()
            } else if speed < 0.001 {
                "?".to_owned()
            } else {
                let secs = ((remaining as f64 / speed).ceil()).min(u64::MAX as f64) as u64;
                format!("{}m {:02}s", secs/60, secs%60)
            };
            format!("[{stage}] {done}/{total} ({percent:.1}%) | осталось: {remaining} | {speed:.1} IP/с | ETA: {eta}")
        }
        None => format!("[{stage}] готово: {done} | всего: неизвестно (потоковый источник) | {speed:.1} IP/с | ETA: ?"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shows_exact_remaining_and_eta() {
        let s = line("DEEP", 25, Some(100), Duration::from_secs(5));
        assert!(s.contains("25/100 (25.0%)"));
        assert!(s.contains("осталось: 75"));
        assert!(s.contains("ETA: 0m 15s"));
    }
    #[test]
    fn handles_unknown_zero_and_overflow() {
        assert!(line("DEEP", 0, None, Duration::ZERO).contains("ETA: ?"));
        assert!(line("DEEP", 0, Some(0), Duration::ZERO).contains("100.0%"));
        assert!(line("DEEP", 200, Some(100), Duration::from_secs(1)).contains("100/100"));
    }
}
