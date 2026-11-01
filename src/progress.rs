//! Human-friendly per-stage progress. Percent and ETA are never fabricated
//! for unknown-size sources; FAST estimates from the configured send rate.
use std::time::Duration;

pub fn render(
    stage: &str, completed: u64, total: Option<u64>,
    completed_in_window: u64, elapsed: Duration,
) -> String {
    let speed = completed_in_window as f64 / elapsed.as_secs_f64().max(0.001);
    match total {
        Some(total) => {
            let done=completed.min(total);
            let remaining=total.saturating_sub(done);
            let percent=if total==0 {100.0} else {done as f64*100.0/total as f64};
            let eta=if remaining==0 {"0m 00s".to_owned()}
                else if speed<=0.001 {"?".to_owned()}
                else {
                    let sec=(remaining as f64/speed).ceil().min(u64::MAX as f64) as u64;
                    format!("{}m {:02}s",sec/60,sec%60)
                };
            format!("[{stage}] {done}/{total} ({percent:.1}%) | осталось {remaining} | {speed:.1} IP/с | ETA {eta}")
        }
        None => format!(
            "[{stage}] проверено {completed} | всего ? | осталось ? | {speed:.1} IP/с | ETA ?"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percent_remaining_eta_exact() {
        let text=render("DEEP",25,Some(100),25,Duration::from_secs(5));
        assert!(text.contains("25/100 (25.0%)"));
        assert!(text.contains("осталось 75"));
        assert!(text.contains("ETA 0m 15s"));
    }
    #[test]
    fn unknown_zero_and_overrun() {
        assert!(render("DEEP",3,None,3,Duration::from_secs(1)).contains("всего ?"));
        assert!(render("DEEP",0,Some(0),0,Duration::ZERO).contains("100.0%"));
        assert!(render("DEEP",200,Some(100),200,Duration::from_secs(1)).contains("100/100"));
    }
}
