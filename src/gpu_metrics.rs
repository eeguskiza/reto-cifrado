//! Monitor de métricas de la GPU vía NVML.
//!
//! Lanza un hilo independiente que muestrea NVML cada 500 ms y emite
//! `ProgressEvent::GpuSample` por el `ProgressSink` compartido.
//!
//! Si NVML no se puede inicializar (driver muy nuevo, WSL2 con
//! limitaciones puntuales, etc.), emite **una sola vez**
//! `ProgressEvent::GpuMetricsUnavailable` con la razón y sale sin
//! re-intentar. **El barrido sigue funcionando intacto** — la GPU
//! sigue ejecutando el kernel; solo perdemos las métricas
//! decorativas.
//!
//! El `GpuMonitor` parará el hilo limpiamente al ser dropeado (drop
//! flag + join), así que el caller solo tiene que mantener la
//! variable viva durante el run.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
use nvml_wrapper::Nvml;

use crate::runner::{ProgressEvent, ProgressSink};

const SAMPLE_PERIOD: Duration = Duration::from_millis(500);

pub struct GpuMonitor {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl GpuMonitor {
    /// Lanza el hilo de muestreo. La sink debe ser `Arc<dyn ProgressSink>`
    /// (típicamente la misma que se pasa al runner).
    pub fn start(sink: Arc<dyn ProgressSink>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);

        let handle = std::thread::Builder::new()
            .name("qc-nvml".into())
            .spawn(move || run_monitor(sink, stop_thread))
            .expect("spawn nvml monitor thread");

        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for GpuMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn run_monitor(sink: Arc<dyn ProgressSink>, stop: Arc<AtomicBool>) {
    // 1) Init NVML. Si falla, emitimos `GpuMetricsUnavailable` y salimos.
    let nvml = match Nvml::init() {
        Ok(n) => n,
        Err(e) => {
            sink.on_event(ProgressEvent::GpuMetricsUnavailable {
                reason: format!("Nvml::init falló: {e}"),
            });
            return;
        }
    };

    // 2) Loop: muestreamos periódicamente.
    while !stop.load(Ordering::SeqCst) {
        // device_by_index dentro del loop por si cambia algo entre samples.
        // (En la práctica nunca cambia, pero el coste es despreciable y nos
        // hace robustos a re-enumeraciones por reset/driver hot-swap.)
        let device = match nvml.device_by_index(0) {
            Ok(d) => d,
            Err(_) => {
                std::thread::sleep(SAMPLE_PERIOD);
                continue;
            }
        };

        if let Some(evt) = sample_once(&device) {
            sink.on_event(evt);
        }

        std::thread::sleep(SAMPLE_PERIOD);
    }
}

fn sample_once(device: &nvml_wrapper::Device<'_>) -> Option<ProgressEvent> {
    // Cada llamada NVML puede fallar individualmente — defaults razonables
    // si fallan, no abortamos el sample completo por un campo.
    let util = device.utilization_rates().ok();
    let mem = device.memory_info().ok();
    let temp = device.temperature(TemperatureSensor::Gpu).ok();
    let power = device.power_usage().ok();

    // Si todos fallan, no emitimos nada — el sample no aporta info.
    if util.is_none() && mem.is_none() && temp.is_none() && power.is_none() {
        return None;
    }

    let utilization_pct = util.map(|u| u.gpu.min(100) as u8).unwrap_or(0);
    let (memory_used_mb, memory_total_mb) = mem
        .map(|m| (m.used / 1_048_576, m.total / 1_048_576))
        .unwrap_or((0, 0));
    let temperature_c = temp.map(|t| t.min(255) as u8).unwrap_or(0);
    let power_w = power.map(|p| p / 1000).unwrap_or(0);

    Some(ProgressEvent::GpuSample {
        utilization_pct,
        memory_used_mb,
        memory_total_mb,
        temperature_c,
        power_w,
    })
}
