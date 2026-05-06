//! Tests post-D-029 que blindan la unicidad de la configuración.
//!
//! - `test_plan_is_single_md5hex_ecb_config`: el plan/runner solo tiene
//!   una entrada y es la correcta (no hay forma de invocar otra config).
//! - `test_inspect_reports_ecb_layout`: la salida de `quattro-crack
//!   inspect` ya no menciona IV (ECB) y reporta los 1616 B como CT
//!   completo.

use std::process::Command;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

use quattro_crack::ciphertext::{Ciphertext, CT_BLOCKS, TOTAL_BIN_LEN};
use quattro_crack::plan::{Plan, PLAN_FORMAT_VERSION, SINGLE_PLAN_DESCRIPTION};

const QC_BIN: &str = env!("CARGO_BIN_EXE_quattro-crack");

#[test]
fn test_plan_is_single_md5hex_ecb_config() {
    // El descriptor debe identificar md5hex_full + AES-256-ECB.
    assert!(SINGLE_PLAN_DESCRIPTION.contains("md5hex_full"));
    assert!(SINGLE_PLAN_DESCRIPTION.contains("aes-256-ecb"));
    assert!(SINGLE_PLAN_DESCRIPTION.contains("pkcs7"));

    // El struct `Plan` se construye sin enums de presets/configs.
    let plan = Plan::new_single(
        PLAN_FORMAT_VERSION,
        "/tmp/cifrado.txt",
        "deadbeef".repeat(8),
        64 * 1024 * 1024,
    );
    assert_eq!(plan.program_version, PLAN_FORMAT_VERSION);
    assert_eq!(plan.batch_size, 64 * 1024 * 1024);

    // En el TOML del plan no hay rastro de las antiguas claves.
    let s = toml::to_string_pretty(&plan).unwrap();
    assert!(!s.contains("entries"), "plan TOML no debe llevar `entries`");
    assert!(!s.contains("preset"), "plan TOML no debe llevar `preset`");
    assert!(!s.contains("Cbc"), "plan TOML no debe llevar `Cbc`");
    assert!(!s.contains("First16"), "plan TOML no debe llevar `First16`");
    assert!(!s.contains("Md5Utf8"), "plan TOML no debe llevar `Md5Utf8`");
}

#[test]
fn test_inspect_reports_ecb_layout() {
    // Genera un fichero sintético de 1616 B (no importa el contenido).
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let raw: Vec<u8> = (0..TOTAL_BIN_LEN).map(|i| (i & 0xff) as u8).collect();
    let b64 = STANDARD.encode(&raw);
    std::fs::write(&input_path, b64).unwrap();

    // Sanity en CPU: el loader devuelve 1616 B sin reservar IV.
    let ct = Ciphertext::load(&input_path).unwrap();
    assert_eq!(ct.ct().len(), TOTAL_BIN_LEN);
    assert_eq!(ct.ct().len() / 16, CT_BLOCKS);

    // CLI: `inspect` reporta el layout ECB.
    let output = Command::new(QC_BIN)
        .args(["inspect", input_path.to_str().unwrap()])
        .output()
        .expect("spawn inspect");
    assert!(output.status.success(), "inspect debería terminar limpio");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("1616 B"), "size 1616 B ausente:\n{stdout}");
    assert!(
        stdout.contains("aes-256-ecb") || stdout.contains("AES-256-ECB"),
        "indicador ECB ausente:\n{stdout}"
    );
    assert!(
        stdout.contains("ct[0..32]"),
        "ct[0..32] ausente:\n{stdout}"
    );
    assert!(
        !stdout.contains("iv:") && !stdout.contains("IV "),
        "inspect post-D-029 NO debe mencionar IV:\n{stdout}"
    );
    assert!(
        stdout.contains("sha256(file)"),
        "sha256 del fichero ausente:\n{stdout}"
    );
}

#[test]
fn test_kernel_bundle_takes_no_kdf_parameter() {
    // Sanity de tipo: `KernelBundle::load` ya no recibe Kdf.
    // Si alguien revierte la API, este test no compila.
    fn _assert_signature(ctx: &quattro_crack::cuda::CudaCtx) {
        let _: anyhow::Result<quattro_crack::cuda::KernelBundle> =
            quattro_crack::cuda::KernelBundle::load(ctx);
    }
    let _ = _assert_signature;
}
