// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::hint::black_box;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Summary {
    pub valid: usize,
    pub mean_ms: f64,
    pub p50: Duration,
    pub p95: Duration,
}

pub fn summarize(samples: &[Duration]) -> Result<Summary, String> {
    if samples.is_empty() {
        return Err("no valid samples".into());
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = |percent: usize| {
        // ceil(n * percent / 100) - 1, without overflowing n * percent.
        let index =
            (sorted.len() / 100) * percent + ((sorted.len() % 100) * percent).div_ceil(100) - 1;
        sorted[index]
    };
    Ok(Summary {
        valid: sorted.len(),
        mean_ms: sorted.iter().map(Duration::as_secs_f64).sum::<f64>() / sorted.len() as f64
            * 1000.0,
        p50: rank(50),
        p95: rank(95),
    })
}

pub fn measure<T, E: std::fmt::Display>(
    name: &str,
    warmup: usize,
    samples: usize,
    mut call: impl FnMut() -> Result<T, E>,
    mut observe: impl FnMut(Duration, T),
) -> Result<Summary, String> {
    if samples == 0 {
        return Err(format!("{name}: samples must be positive; valid=0/0"));
    }
    for i in 0..warmup {
        let output = call().map_err(|error| {
            format!(
                "{name}: warmup {} failed; valid=0/{samples}: {error}",
                i + 1
            )
        })?;
        black_box(output);
    }
    let mut elapsed = Vec::new();
    for i in 0..samples {
        let start = Instant::now();
        let output = black_box(call());
        let duration = start.elapsed();
        let output = output.map_err(|error| {
            format!(
                "{name}: measured sample {} failed; valid={i}/{samples}: {error}",
                i + 1
            )
        })?;
        elapsed.push(duration);
        // Reporting and output destruction are outside the timed call.
        observe(duration, output);
    }
    summarize(&elapsed)
}

impl Summary {
    pub fn print(&self, name: &str, warmup: usize, requested: usize) {
        println!(
            "{name}: valid={}/{requested} warmup={warmup} mean_ms={:.3} p50_ms={:.3} p95_ms={:.3}",
            self.valid,
            self.mean_ms,
            self.p50.as_secs_f64() * 1000.0,
            self.p95.as_secs_f64() * 1000.0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn zero_samples_refused_before_any_work() {
        let mut calls = 0;
        let result = measure(
            "stage",
            2,
            0,
            || {
                calls += 1;
                Ok::<_, &str>(())
            },
            |_, _| {},
        );
        assert!(result.is_err());
        assert_eq!(calls, 0);
    }

    #[test]
    fn warmup_failure_stops_before_measured_samples() {
        let mut calls = 0;
        let result = measure(
            "stage",
            2,
            5,
            || {
                calls += 1;
                Err::<(), _>("invalid tensor")
            },
            |_, _| {},
        );
        let error = result.unwrap_err();
        assert!(error.contains("warmup"));
        assert!(error.contains("valid=0/5"));
        assert!(error.contains("invalid tensor"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn failed_inference_is_not_counted_or_observed_as_valid() {
        let mut calls = 0;
        let mut observed = Vec::new();
        let result = measure(
            "stage",
            1,
            4,
            || {
                calls += 1;
                if calls == 3 {
                    Err("inference failed")
                } else {
                    Ok(calls)
                }
            },
            |_, value| observed.push(value),
        );
        let error = result.unwrap_err();
        assert!(error.contains("valid=1/4"));
        assert!(error.contains("inference failed"));
        assert_eq!(calls, 3);
        assert_eq!(observed, vec![2]);
    }

    #[test]
    fn only_measured_successes_reach_observer_and_summary() {
        let mut calls = 0;
        let mut observed = Vec::new();
        let stats = measure(
            "stage",
            2,
            3,
            || {
                calls += 1;
                Ok::<_, &str>(calls)
            },
            |_, value| observed.push(value),
        )
        .unwrap();
        assert_eq!(observed, vec![3, 4, 5]);
        assert_eq!(stats.valid, 3);
    }

    #[test]
    fn nearest_rank_percentiles_use_sorted_valid_samples() {
        let stats = summarize(&[10, 1, 9, 2, 8, 3, 7, 4, 6, 5].map(Duration::from_millis)).unwrap();
        assert_eq!(stats.p50, Duration::from_millis(5));
        assert_eq!(stats.p95, Duration::from_millis(10));
        assert_eq!(stats.mean_ms, 5.5);
        let singleton = summarize(&[Duration::from_millis(4)]).unwrap();
        assert_eq!(singleton.p50, singleton.p95);
        assert!(summarize(&[]).is_err());
    }
}
