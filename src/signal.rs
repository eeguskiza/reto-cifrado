//! Manejo de señales para apagado limpio (§7.5).
//!
//! Comportamiento:
//!
//! - **Primer SIGINT/SIGTERM**: marca el flag de parada. El runner
//!   termina el batch en curso, persiste `progress.toml` y sale con
//!   código 0.
//! - **Segundo SIGINT durante el shutdown limpio**: aborto inmediato
//!   (exit code 130). Aceptable perder hasta un batch.
//! - **SIGKILL**: incontrolable; la atomicidad de `state::atomic_write`
//!   es la salvaguarda — en el peor caso se pierde el batch en vuelo.
//!
//! Implementación: `signal-hook 0.3` con dos handlers por señal,
//! registrados en orden:
//!
//! 1. `register_conditional_shutdown` — sale si el flag YA está set.
//! 2. `register` — set del flag.
//!
//! Los handlers se ejecutan en orden de registro: en la primera entrega
//! `conditional_shutdown` ve flag=false (no-op) y luego `register` lo
//! pone a true; en la segunda entrega `conditional_shutdown` ve
//! flag=true y termina el proceso. Ver D-015.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;

/// Instala los handlers de señal sobre el flag compartido.
pub fn install(stop: Arc<AtomicBool>) -> Result<()> {
    // Conditional shutdown PRIMERO (corre antes en la cadena de handlers).
    flag::register_conditional_shutdown(SIGINT, 130, Arc::clone(&stop))
        .context("registrando conditional_shutdown SIGINT")?;
    flag::register_conditional_shutdown(SIGTERM, 143, Arc::clone(&stop))
        .context("registrando conditional_shutdown SIGTERM")?;

    // Set del flag DESPUÉS (corre tras conditional_shutdown).
    flag::register(SIGINT, Arc::clone(&stop)).context("registrando flag SIGINT")?;
    flag::register(SIGTERM, Arc::clone(&stop)).context("registrando flag SIGTERM")?;
    Ok(())
}
