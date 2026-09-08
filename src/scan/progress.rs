//! Live scan status (spec §11): fixed refresh rate, non-TTY degrades to
//! periodic plain lines, honours --quiet, never blocks the walk.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressStyle};

/// How the scan reports progress. Chosen once by the CLI from its console
/// settings so `scan` never depends on `output`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressMode {
    /// `--quiet` or `--json`: nothing.
    Silent,
    /// stderr is a terminal: a live spinner line.
    Spinner,
    /// Not a terminal: a plain line every few seconds.
    Plain,
}

#[derive(Default)]
pub struct Counters {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    pub dirs: AtomicU64,
    pub skipped: AtomicU64,
    pub sources_done: AtomicU64,
}

pub struct Progress {
    counters: Arc<Counters>,
    bar: Option<ProgressBar>,
    stop: Arc<AtomicBool>,
    ticker: Option<std::thread::JoinHandle<()>>,
}

impl Progress {
    pub fn start(mode: ProgressMode, label: &str, total_sources: usize) -> Progress {
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        if mode == ProgressMode::Silent {
            return Progress {
                counters,
                bar: None,
                stop,
                ticker: None,
            };
        }
        if mode == ProgressMode::Spinner {
            let bar = ProgressBar::new_spinner();
            bar.set_style(
                ProgressStyle::with_template("{spinner} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            );
            bar.enable_steady_tick(Duration::from_millis(120));
            let c = Arc::clone(&counters);
            let s = Arc::clone(&stop);
            let b = bar.clone();
            let label = label.to_string();
            let ticker = std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    b.set_message(render(&label, &c, total_sources));
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
            Progress {
                counters,
                bar: Some(bar),
                stop,
                ticker: Some(ticker),
            }
        } else {
            // Plain periodic lines every 5 seconds.
            let c = Arc::clone(&counters);
            let s = Arc::clone(&stop);
            let label = label.to_string();
            let ticker = std::thread::spawn(move || {
                let started = Instant::now();
                let mut last = Instant::now();
                while !s.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                    if last.elapsed() >= Duration::from_secs(5) {
                        eprintln!(
                            "{} ({}s)",
                            render(&label, &c, total_sources),
                            started.elapsed().as_secs()
                        );
                        last = Instant::now();
                    }
                }
            });
            Progress {
                counters,
                bar: None,
                stop,
                ticker: Some(ticker),
            }
        }
    }

    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.ticker.take() {
            let _ = t.join();
        }
        if let Some(b) = self.bar.take() {
            b.finish_and_clear();
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(b) = self.bar.take() {
            b.finish_and_clear();
        }
    }
}

fn render(label: &str, c: &Counters, total_sources: usize) -> String {
    format!(
        "{label}: {} files, {} ({}/{} sources, {} skipped)",
        c.files.load(Ordering::Relaxed),
        crate::output::human::bytes(c.bytes.load(Ordering::Relaxed)),
        c.sources_done.load(Ordering::Relaxed),
        total_sources,
        c.skipped.load(Ordering::Relaxed)
    )
}
