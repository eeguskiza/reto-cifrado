//! Verifica que NVML inicializa con el shim para el caso WSL2 (D-027).
//!
//! En WSL2, el driver expone `libnvidia-ml.so.1` en `/usr/lib/wsl/lib/`
//! pero NO el symlink `libnvidia-ml.so` que `libloading` busca por
//! defecto. El test sólo se considera REGRESIÓN si NVML estaba
//! funcional y deja de estarlo: si no hay shim, se marca como ignorado
//! con explicación.

use std::process::Command;

#[test]
fn nvml_init_succeeds_when_so_available() {
    // Si la librería no es resoluble en este entorno (sin shim, sin
    // driver), no fallamos el test — no hay regresión, solo entorno.
    // Saltamos con un mensaje informativo.
    let probe = Command::new("ldconfig")
        .arg("-p")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let has_so = probe.contains("libnvidia-ml.so ");
    let env_path = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
    let has_shim = env_path
        .split(':')
        .any(|p| std::path::Path::new(p).join("libnvidia-ml.so").exists());

    if !has_so && !has_shim {
        eprintln!(
            "skip: ni `libnvidia-ml.so` en ldconfig ni shim en LD_LIBRARY_PATH ({}). \
             Crea el symlink documentado en README → Troubleshooting WSL2 → NVML, \
             o exporta LD_LIBRARY_PATH para apuntar al shim.",
            env_path
        );
        return;
    }

    match nvml_wrapper::Nvml::init() {
        Ok(nvml) => {
            let dev = nvml
                .device_by_index(0)
                .expect("device 0 debe existir si Nvml::init pasó");
            // Sanity: leer temperatura. Si esto falla, el driver no expone
            // la métrica (raro pero posible bajo WSL2).
            let _ = dev.temperature(
                nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu,
            );
            eprintln!("Nvml::init OK — métricas GPU disponibles para la TUI");
        }
        Err(e) => {
            // Si la librería se resolvió pero la inicialización aún falla,
            // sí lo reportamos como fallo: hay algo extraño.
            panic!(
                "Nvml::init falló a pesar de tener libnvidia-ml resoluble: {e}. \
                 Revisa README → Troubleshooting WSL2 → NVML."
            );
        }
    }
}
