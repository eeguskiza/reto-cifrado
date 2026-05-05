//! `quattro-crack` core library.
//!
//! Módulos puros, sin estado global ni I/O implícito. La orquestación CLI
//! vive en `src/main.rs`.

pub mod ciphertext;
pub mod combinatorics;
pub mod config;
pub mod cuda;
pub mod gpu_metrics;
pub mod kdf;
pub mod plan;
pub mod reference;
pub mod runner;
pub mod signal;
pub mod state;
pub mod tui;
