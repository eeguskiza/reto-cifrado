//! TUI en vivo desacoplada del runner por canal `crossbeam_channel`.
//!
//! `TuiSink::on_event` solo hace `try_send`; un hilo renderer aparte
//! consume eventos a 5 Hz, calcula GH/s (ventana móvil 5 s, peak, avg),
//! ETA, y dibuja con `indicatif`. Si el canal se llena (no debería, es
//! unbounded), se descarta el evento — el runner nunca espera.
//!
//! Drop restaura cursor + colores aunque el render esté a media pintada.

use std::collections::VecDeque;
use std::io::Write;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::runner::{ProgressEvent, ProgressSink};

const TICK_PERIOD: Duration = Duration::from_millis(200); // 5 Hz
const SPEED_WINDOW: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct TuiSinkConfig {
    pub n_total_candidates: u64,
    pub project_version: String,
}

pub struct TuiSink {
    tx: Sender<ProgressEvent>,
    handle: Option<JoinHandle<()>>,
}

impl TuiSink {
    pub fn new(config: TuiSinkConfig) -> Self {
        let (tx, rx) = unbounded::<ProgressEvent>();
        let handle = std::thread::Builder::new()
            .name("qc-tui".into())
            .spawn(move || run_renderer(rx, config))
            .expect("spawn tui renderer");
        Self {
            tx,
            handle: Some(handle),
        }
    }

    /// Útil para tests: ¿el hilo renderer ya terminó?
    pub fn is_done(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| h.is_finished())
            .unwrap_or(true)
    }

    /// Espera a que el renderer termine (típicamente tras `PlanCompleted`
    /// o `Paused`), con timeout. Útil para tests deterministas.
    pub fn wait_until_done(&mut self, timeout: Duration) -> bool {
        let started = Instant::now();
        while !self.is_done() && started.elapsed() < timeout {
            std::thread::sleep(Duration::from_millis(20));
        }
        self.is_done()
    }
}

impl ProgressSink for TuiSink {
    fn on_event(&self, event: ProgressEvent) {
        // try_send sobre unbounded nunca devuelve `Full`, solo `Disconnected`
        // (cuando el renderer ya salió tras PlanCompleted/Paused).
        let _ = self.tx.try_send(event);
    }
}

impl Drop for TuiSink {
    fn drop(&mut self) {
        // Cierra el canal (al droppear `tx` se desconecta) y espera al hilo.
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Restaura terminal en cualquier caso — UX no negociable.
        let mut out = std::io::stdout();
        let _ = crossterm::execute!(out, crossterm::cursor::Show, crossterm::style::ResetColor);
        let _ = out.flush();
    }
}

// ============================================================================
// Renderer thread
// ============================================================================

struct Bars {
    plan: ProgressBar,
    config_line: ProgressBar,
    space: ProgressBar,
    speed: ProgressBar,
    gpu_line: ProgressBar,
    state_line: ProgressBar,
    last_sample_line: ProgressBar,
    hits_line: ProgressBar,
    elapsed_line: ProgressBar,
    footer_line: ProgressBar,
}

fn build_bars(mp: &MultiProgress, total_configs: u64, n_total: u64) -> Bars {
    let line = ProgressStyle::with_template("{prefix:<8.bold} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_bar());
    let bar32 = ProgressStyle::with_template("{prefix:<8.bold} {bar:32.cyan/blue}  {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("█░");

    let plan = mp.add(ProgressBar::new(total_configs.max(1)));
    plan.set_prefix("[Plan]");
    plan.set_style(bar32.clone());
    plan.set_message(format!("0/{total_configs} configurations"));

    let config_line = mp.add(ProgressBar::new(0));
    config_line.set_prefix("[Config]");
    config_line.set_style(line.clone());
    config_line.set_message("(esperando)");

    let space = mp.add(ProgressBar::new(n_total.max(1)));
    space.set_prefix("[Space]");
    space.set_style(bar32.clone().progress_chars("█░"));
    space.set_message("0% / -- ETA --");

    let speed = mp.add(ProgressBar::new(100));
    speed.set_prefix("[Speed]");
    speed.set_style(bar32.clone().progress_chars("█░"));
    speed.set_message("0.00 GH/s (peak 0.00, avg 0.00)");

    let gpu_line = mp.add(ProgressBar::new(0));
    gpu_line.set_prefix("[GPU]");
    gpu_line.set_style(line.clone());
    gpu_line.set_message("warming up…");

    let state_line = mp.add(ProgressBar::new(0));
    state_line.set_prefix("[State]");
    state_line.set_style(line.clone());
    state_line.set_message("idle");

    let last_sample_line = mp.add(ProgressBar::new(0));
    last_sample_line.set_prefix("");
    last_sample_line.set_style(line.clone());
    last_sample_line.set_message("");

    let hits_line = mp.add(ProgressBar::new(0));
    hits_line.set_prefix("");
    hits_line.set_style(line.clone());
    hits_line.set_message("Hits found: 0");

    let elapsed_line = mp.add(ProgressBar::new(0));
    elapsed_line.set_prefix("");
    elapsed_line.set_style(line.clone());
    elapsed_line.set_message("Elapsed: 0s");

    let footer_line = mp.add(ProgressBar::new(0));
    footer_line.set_prefix("");
    footer_line.set_style(line);
    footer_line.set_message("Press Ctrl+C to pause and save state safely.");

    Bars {
        plan,
        config_line,
        space,
        speed,
        gpu_line,
        state_line,
        last_sample_line,
        hits_line,
        elapsed_line,
        footer_line,
    }
}

#[derive(Default)]
struct State {
    started_at: Option<Instant>,
    cfg_started_at: Option<Instant>,
    last_batch_at: Option<Instant>,
    speed_window: VecDeque<(Instant, u64)>,
    total_processed: u64,
    peak_ghs: f64,
    cfg_processed: u64,
    last_step: u64,
    n_total: u64,
    #[allow(dead_code)]
    total_configs: usize,
    hits: usize,
    last_sample_idx: u64,
    last_sample_pw: String,
    gpu_unavailable: bool,
    finished: bool,
}

fn fmt_secs(s: f64) -> String {
    let total = s as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let sec = total % 60;
    if h > 0 {
        format!("{h}h{m:02}m{sec:02}s")
    } else if m > 0 {
        format!("{m}m{sec:02}s")
    } else {
        format!("{sec}s")
    }
}

fn run_renderer(rx: Receiver<ProgressEvent>, cfg: TuiSinkConfig) {
    let mp = MultiProgress::new();
    let bars = build_bars(&mp, 1, cfg.n_total_candidates);

    // Cabecera estática.
    let _ = mp.println(format!(
        "quattro-crack v{} — N = {} — AES-128-ECB passraw + MD5 verify (D-035)",
        cfg.project_version, cfg.n_total_candidates
    ));

    let mut st = State {
        n_total: cfg.n_total_candidates,
        ..Default::default()
    };

    loop {
        match rx.recv_timeout(TICK_PERIOD) {
            Ok(event) => {
                handle_event(event, &mut st, &bars, &mp);
                if st.finished {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                tick(&mut st, &bars);
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // Cleanup final.
    bars.plan.finish_and_clear();
    bars.config_line.finish_and_clear();
    bars.space.finish_and_clear();
    bars.speed.finish_and_clear();
    bars.gpu_line.finish_and_clear();
    bars.state_line.finish_and_clear();
    bars.last_sample_line.finish_and_clear();
    bars.hits_line.finish_and_clear();
    bars.elapsed_line.finish_and_clear();
    bars.footer_line.finish_and_clear();
    let _ = mp.clear();
}

fn handle_event(event: ProgressEvent, st: &mut State, bars: &Bars, mp: &MultiProgress) {
    match event {
        ProgressEvent::PlanLoaded {
            total_candidates,
            batch_size,
            device_name,
            config_id,
            ..
        } => {
            // Tras D-029 hay una sola config implícita; mantenemos el
            // bar `[Plan]` por simetría visual pero queda como "0/1" /
            // "1/1" según estado.
            st.total_configs = 1;
            st.n_total = total_candidates;
            st.started_at = Some(Instant::now());
            st.cfg_started_at = Some(Instant::now());
            bars.plan.set_length(1);
            bars.plan.set_message("0/1 configurations  ·  D-035 single");
            bars.config_line
                .set_message(config_id.clone() + "  ·  AES-128");
            bars.space.set_length(total_candidates);
            let _ = mp.println(format!(
                "device: {device_name}  ·  batch_size: {batch_size}  ·  config: {config_id}"
            ));
        }
        ProgressEvent::Resumed { from_step } => {
            st.last_step = from_step;
            let _ = mp.println(format!("[reanuda] desde idx {from_step}"));
        }
        ProgressEvent::ResumeRejected { reason } => {
            let _ = mp.println(format!("[resume rechazado] {reason}"));
            st.finished = true;
        }
        ProgressEvent::BatchCompleted {
            current_step,
            candidates_in_batch,
            batch_duration_ms,
            ..
        } => {
            let now = Instant::now();
            st.last_batch_at = Some(now);
            st.last_step = current_step;
            st.total_processed += candidates_in_batch;
            st.cfg_processed += candidates_in_batch;
            // Ventana móvil 5 s.
            st.speed_window.push_back((now, candidates_in_batch));
            while let Some(&(t, _)) = st.speed_window.front() {
                if now.duration_since(t) > SPEED_WINDOW {
                    st.speed_window.pop_front();
                } else {
                    break;
                }
            }
            // Sample metadata
            st.last_sample_idx = current_step.saturating_sub(candidates_in_batch);
            st.last_sample_pw = String::new(); // no tenemos acceso al pw aquí

            bars.space.set_position(current_step);

            // Speed bar
            let current_ghs = compute_window_ghs(&st.speed_window, now);
            if current_ghs > st.peak_ghs {
                st.peak_ghs = current_ghs;
            }
            let avg_ghs = st
                .started_at
                .map(|t| {
                    let secs = now.duration_since(t).as_secs_f64();
                    if secs > 0.0 {
                        st.total_processed as f64 / secs / 1.0e9
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0);
            // Bar normalizado a peak (mín 0.1 para no dividir por 0).
            let denom = st.peak_ghs.max(0.1);
            let pct = ((current_ghs / denom) * 100.0).clamp(0.0, 100.0) as u64;
            bars.speed.set_position(pct);
            bars.speed.set_message(format!(
                "{:.2} GH/s  (peak {:.2}, avg {:.2})",
                current_ghs, st.peak_ghs, avg_ghs
            ));

            // ETA basado en avg de la config actual.
            let cfg_avg_ghs = if let Some(t) = st.cfg_started_at {
                let secs = now.duration_since(t).as_secs_f64();
                if secs > 0.0 {
                    st.cfg_processed as f64 / secs / 1.0e9
                } else {
                    0.0
                }
            } else {
                0.0
            };
            let eta_str = if cfg_avg_ghs > 0.0 && current_step < st.n_total {
                let remaining = (st.n_total - current_step) as f64;
                let eta_s = remaining / (cfg_avg_ghs * 1.0e9);
                format!("ETA {}", fmt_secs(eta_s))
            } else {
                "ETA --".into()
            };
            let pct_space = if st.n_total > 0 {
                100.0 * (current_step as f64) / (st.n_total as f64)
            } else {
                0.0
            };
            bars.space.set_message(format!(
                "{pct_space:.4}%  {current_step:.3e}/{:.3e}  ·  {eta_str}",
                st.n_total as f64
            ));
            // Batch duration → log debug en state line.
            let _ = batch_duration_ms;
        }
        ProgressEvent::GpuSample {
            utilization_pct,
            memory_used_mb,
            memory_total_mb,
            temperature_c,
            power_w,
        } => {
            if !st.gpu_unavailable {
                bars.gpu_line.set_message(format!(
                    "util {}%  ·  mem {:.1}/{:.1} GB  ·  temp {}°C  ·  power {}W",
                    utilization_pct,
                    memory_used_mb as f64 / 1024.0,
                    memory_total_mb as f64 / 1024.0,
                    temperature_c,
                    power_w
                ));
            }
        }
        ProgressEvent::GpuMetricsUnavailable { reason } => {
            st.gpu_unavailable = true;
            bars.gpu_line
                .set_message(format!("metrics unavailable ({reason})"));
        }
        ProgressEvent::HitConfirmed {
            password,
            idx,
            plaintext_hex_first_32,
            line_ending,
            elapsed_total,
        } => {
            st.hits += 1;
            bars.hits_line
                .set_message(format!("Hits found: {}", st.hits));
            let _ = mp.println(format!(
                "================================================================\n\
                 ★ HIT  idx={idx}  pw='{password}'  line_ending={}  elapsed={:.2}s\n\
                 plaintext[..32]={plaintext_hex_first_32}\n\
                 ================================================================",
                line_ending.as_str(),
                elapsed_total.as_secs_f64()
            ));
            st.finished = true;
        }
        ProgressEvent::HitDiscardedPrefixMismatch { idx } => {
            bars.last_sample_line.set_message(format!(
                "Last sample (idx={idx}):  (kernel false positive, prefix32 ≠ Leonardo da Vinc)"
            ));
        }
        ProgressEvent::HitCriticalMd5Mismatch {
            idx,
            password,
            line_ending,
            embedded_md5_hex,
            computed_md5_hex,
        } => {
            let _ = mp.println(format!(
                "================================================================\n\
                 CRITICAL: prefijo-32 ({}) OK pero MD5 INTEGRITY MISMATCH  \
                 idx={idx} pw='{password}'\n  \
                 embedded MD5(hex): {embedded_md5_hex}\n  \
                 computed MD5(hex): {computed_md5_hex}\n\
                 ABORTANDO el barrido. Estado guardado para inspección.\n\
                 ================================================================",
                line_ending.as_str()
            ));
            st.finished = true;
        }
        ProgressEvent::Paused {
            last_step,
            elapsed_total,
        } => {
            let _ = mp.println(format!(
                "================================================================\n\
                 [PAUSED]  elapsed={:.2}s  last_step={}\n\
                 resume:   quattro-crack run --resume\n\
                 ================================================================",
                elapsed_total.as_secs_f64(),
                last_step
            ));
            st.finished = true;
        }
        ProgressEvent::PlanCompleted {
            total_hits,
            elapsed_total,
        } => {
            let _ = mp.println(format!(
                "[DONE] plan completado · {} hits · elapsed {:.2}s",
                total_hits,
                elapsed_total.as_secs_f64()
            ));
            st.finished = true;
        }
    }
}

fn tick(st: &mut State, bars: &Bars) {
    let now = Instant::now();
    if let Some(at) = st.last_batch_at {
        let ago = now.duration_since(at);
        bars.state_line.set_message(format!(
            "last flush {:.1}s ago  ·  next_step {}",
            ago.as_secs_f64(),
            st.last_step
        ));
    } else {
        bars.state_line.set_message("waiting for first batch…");
    }
    if let Some(start) = st.started_at {
        let total_elapsed = now.duration_since(start);
        bars.elapsed_line.set_message(format!(
            "Elapsed: {}",
            fmt_secs(total_elapsed.as_secs_f64())
        ));
    }
}

fn compute_window_ghs(window: &VecDeque<(Instant, u64)>, now: Instant) -> f64 {
    if window.len() < 2 {
        return 0.0;
    }
    let oldest = window.front().unwrap().0;
    let span = now.duration_since(oldest).as_secs_f64();
    if span <= 0.0 {
        return 0.0;
    }
    let total: u64 = window.iter().map(|(_, n)| *n).sum();
    total as f64 / span / 1.0e9
}
