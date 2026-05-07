//! D-035 — La construcción real del reto es cifraronline.com:
//! `passraw + AES-128-ECB + null pad + MD5 verify`.
//!
//! Estos tests son contrato: si fallan, el barrido completo es
//! inservible. El #1 (`test_experimental_vector_bit_exact`) es el ancla
//! — lo verificó el usuario cifrando un plaintext conocido con un
//! password conocido en la web y comparando contra `pycryptodome`.

use std::process::Command;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

use quattro_crack::ciphertext::TOTAL_BIN_LEN;
use quattro_crack::combinatorics::{index_to_password, password_to_index, N};
use quattro_crack::cuda::{gpu_dump_pt_block0, CudaCtx, KernelBundle};
use quattro_crack::reference::{
    build_key_passraw, build_message, decrypt_aes128_ecb_raw, encrypt_aes128_ecb,
    encrypt_cifraronline, null_pad_to_block, validate_hit, HitVerdict, LineEnding, KNOWN_PREFIX_16,
    KNOWN_PREFIX_32_CRLF, KNOWN_PREFIX_32_LF,
};
use quattro_crack::runner::{self, ProgressEvent, ProgressSink, RunOptions, RunOutcome};

// ============================================================================
// 1. KDF passraw — clave = pw + null pad hasta 16 B (NUNCA MD5).
// ============================================================================

#[test]
fn test_kdf_is_passraw_with_null_padding() {
    let cases: &[(&[u8; 14], &str)] = &[
        // Vector experimental conocido.
        (b".aAaaeeii1452.", "2e6141616165656969313435322e0000"),
        // Endpoints del espacio.
        (b".aAaabbbb1000.", "2e6141616162626262313030302e0000"),
        (b".zzzzuuuU1999.", "2e7a7a7a7a75757555313939392e0000"),
        // Mid-space.
        (b".bAioembl1452.", "2e6241696f656d626c313435322e0000"),
        // Endpoint inferior alterno.
        (b".aAabbabb1000.", "2e6141616262616262313030302e0000"),
    ];
    for (pw, expected_hex) in cases {
        let key = build_key_passraw(pw.as_slice());
        let got = hex::encode(key);
        assert_eq!(
            got, *expected_hex,
            "key passraw para {pw:?}: got {got}, expected {expected_hex}"
        );
        assert_eq!(&key[..14], pw.as_slice());
        assert_eq!(key[14], 0, "key[14] debe ser null");
        assert_eq!(key[15], 0, "key[15] debe ser null");
    }
}

// ============================================================================
// 2. Vector experimental — bit-exact contra pycryptodome.
//
// El usuario cifró este plaintext con esta clave en cifraronline.com y
// comparó el resultado. Si falla, toda la construcción D-035 está mal.
// ============================================================================

#[test]
fn test_experimental_vector_bit_exact() {
    let password: &[u8] = b".aAaaeeii1452.";
    let plaintext: &[u8] = b"Leonardo da Vinci\n\nLeonardo da Vinci es muy crack 1452.";
    let expected_md5_hex: &[u8] = b"bcba8e3f8c64e5aa7b0546f807138f23";
    let expected_key_hex = "2e6141616165656969313435322e0000";
    let expected_ct_b64 = "ZiJtruxqeLYBXsv4QD3P28g46sarTVak+glc8e7BuBupNdO0K8As740YJcA72ODOW5+IZMguNS17p5cs8BUi1Zs2AFhY3iGn6CcEvvhkXbh+jlAMAhEHNC/6e12UGoIO";

    // 1) MD5(plaintext).hexdigest() debe coincidir con expected_md5_hex.
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(plaintext);
    let raw: [u8; 16] = h.finalize().into();
    let computed_md5_hex = hex::encode(raw);
    assert_eq!(
        computed_md5_hex.as_bytes(),
        expected_md5_hex,
        "MD5(plaintext) discrepa con vector experimental"
    );

    // 2) key = pw + null pad hasta 16 B.
    let key = build_key_passraw(password);
    assert_eq!(
        hex::encode(key),
        expected_key_hex,
        "key passraw discrepa con vector experimental"
    );

    // 3) message = plaintext + md5_hex; padded = + null pad.
    let message = build_message(plaintext);
    assert_eq!(message.len(), plaintext.len() + 32);
    let padded = null_pad_to_block(&message);
    assert_eq!(padded.len() % 16, 0);
    assert_eq!(
        padded.len(),
        96,
        "55 B plaintext + 32 B md5_hex + 9 B null = 96"
    );

    // 4) ciphertext = AES-128-ECB.encrypt(padded, key) — BIT-EXACT.
    let ct = encrypt_aes128_ecb(&key, &padded);
    let expected_ct = STANDARD.decode(expected_ct_b64).unwrap();
    assert_eq!(ct.len(), expected_ct.len());
    assert_eq!(
        ct, expected_ct,
        "ciphertext D-035 NO es bit-exact contra cifraronline.com"
    );

    // 5) round-trip: decrypt(ct) == padded.
    let decrypted = decrypt_aes128_ecb_raw(&key, &ct).unwrap();
    assert_eq!(decrypted, padded);

    // 6) helper end-to-end debe producir el mismo ct.
    let ct_helper = encrypt_cifraronline(&key, plaintext);
    assert_eq!(
        ct_helper, expected_ct,
        "encrypt_cifraronline helper diverge"
    );

    // 7) validate_hit sobre el ct debe devolver Confirmed con LF.
    match validate_hit(&key, &ct).unwrap() {
        HitVerdict::Confirmed { line_ending, .. } => {
            assert_eq!(line_ending, LineEnding::Lf);
        }
        other => panic!("validate_hit no devolvió Confirmed: {other:?}"),
    }
}

// ============================================================================
// 3. Kernel CUDA (D-035) bit-exact contra reference CPU sobre 1M idx.
// ============================================================================

#[test]
fn test_aes128_kernel_matches_pycryptodome_ecb() {
    let ctx = CudaCtx::init().expect("CUDA");

    // CT block arbitrario; lo descifraremos contra cualquier clave del
    // espacio y compararemos byte a byte CPU vs GPU.
    let ct_block_0: [u8; 16] = {
        let mut b = [0u8; 16];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
        }
        b
    };

    // Sampling: 5 chunks de 200K idx en posiciones diversas + boundaries.
    let chunk_size: u64 = 200_000;
    let chunk_starts: [u64; 5] = [0, 100_000_000, N / 2, N - 2 * chunk_size, N - chunk_size];

    let mut total_verified: u64 = 0;
    for &base in chunk_starts.iter() {
        let pts_gpu =
            gpu_dump_pt_block0(&ctx, base, chunk_size, &ct_block_0).expect("gpu_dump_pt_block0");
        assert_eq!(pts_gpu.len(), (chunk_size as usize) * 16);

        for j in 0..chunk_size {
            let idx = base + j;
            let pw = index_to_password(idx);
            let key = build_key_passraw(&pw);
            let pt_cpu = decrypt_aes128_ecb_raw(&key, &ct_block_0).expect("cpu");
            let off = (j as usize) * 16;
            let pt_gpu = &pts_gpu[off..off + 16];
            if &pt_cpu[..16] != pt_gpu {
                panic!(
                    "discrepancia kernel↔reference en idx={idx}\n  cpu={:02x?}\n  gpu={:02x?}",
                    &pt_cpu[..16],
                    pt_gpu
                );
            }
        }
        total_verified += chunk_size;
    }
    eprintln!("D-035 kernel bit-exact verificadas {total_verified} idx contra reference");
    assert!(total_verified >= 1_000_000);
}

// ============================================================================
// 4. validate_hit + kernel encuentran hit con plaintext LF.
// ============================================================================

#[test]
fn test_validate_hit_lf_variant() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válido");

    // Plaintext sintético con \n simple, prefijo-32 LF.
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(KNOWN_PREFIX_32_LF);
    plaintext.extend_from_slice(b" texto biografico de ejemplo aleatorio.");

    let key = build_key_passraw(pw);
    let ct = encrypt_cifraronline(&key, &plaintext);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    // CPU validate_hit detecta LF.
    match validate_hit(&key, &ct).unwrap() {
        HitVerdict::Confirmed { line_ending, .. } => {
            assert_eq!(line_ending, LineEnding::Lf);
        }
        other => panic!("esperaba Confirmed (LF), obtuve {other:?}"),
    }

    // Kernel CUDA emite hit en idx target.
    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load");
    const RANGE: u64 = 200_000;
    let hits = bundle
        .launch(target_idx.saturating_sub(RANGE / 2), RANGE, &ct_block_0)
        .expect("launch");
    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "kernel D-035 no encuentra target_idx={target_idx} (LF)"
    );
}

// ============================================================================
// 5. validate_hit + kernel encuentran hit con plaintext CRLF.
// ============================================================================

#[test]
fn test_validate_hit_crlf_variant() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válido");

    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(KNOWN_PREFIX_32_CRLF);
    plaintext.extend_from_slice(b" texto biografico de ejemplo aleatorio.");

    let key = build_key_passraw(pw);
    let ct = encrypt_cifraronline(&key, &plaintext);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    match validate_hit(&key, &ct).unwrap() {
        HitVerdict::Confirmed { line_ending, .. } => {
            assert_eq!(line_ending, LineEnding::Crlf);
        }
        other => panic!("esperaba Confirmed (CRLF), obtuve {other:?}"),
    }

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load");
    const RANGE: u64 = 200_000;
    let hits = bundle
        .launch(target_idx.saturating_sub(RANGE / 2), RANGE, &ct_block_0)
        .expect("launch");
    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "kernel D-035 no encuentra target_idx={target_idx} (CRLF)"
    );
}

// ============================================================================
// 6. MD5 mismatch crítico: prefijo-32 OK pero MD5 corrompido → abort.
// ============================================================================

#[test]
fn test_md5_mismatch_critical_aborts() {
    // Construye un ciphertext donde el prefijo-32 (LF) coincide pero el
    // MD5 al final está corrompido. El kernel emite hit (compara solo
    // prefijo-16); CPU detecta el MD5 mismatch tras prefijo-32 OK; el
    // runner aborta con error y persiste estado.
    //
    // Usamos pw con idx muy bajo (`.aAaabbbb1000.` = idx 0) para que el
    // primer batch ya lo procese, sin esperar al barrido completo.
    let pw = b".aAaabbbb1000.";
    let target_idx = password_to_index(pw).expect("pw válido");
    assert_eq!(target_idx, 0);

    // Plaintext arbitrario que arranca con LF prefix-32.
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(KNOWN_PREFIX_32_LF);
    plaintext.extend_from_slice(b" cuerpo del mensaje para md5 corruption.");

    let key = build_key_passraw(pw);

    // Construye message + md5_hex y CORROMPE el último byte del md5_hex.
    let mut msg = build_message(&plaintext);
    let last = msg.len() - 1;
    msg[last] = if msg[last] == b'a' { b'b' } else { b'a' };
    let padded = null_pad_to_block(&msg);
    let ct = encrypt_aes128_ecb(&key, &padded);

    // Pad ct a 1616 B simulando el formato real del fichero.
    let mut ct_full = ct.clone();
    while ct_full.len() < TOTAL_BIN_LEN {
        // Añade bloques sintéticos ECB (cifrar bytes 0).
        let extra = encrypt_aes128_ecb(&key, &[0u8; 16]);
        ct_full.extend_from_slice(&extra);
    }
    ct_full.truncate(TOTAL_BIN_LEN);

    // CPU validate_hit: prefijo-32 OK pero md5 mismatch.
    let verdict = validate_hit(&key, &ct).unwrap();
    match verdict {
        HitVerdict::Md5MismatchCritical {
            embedded_md5_hex,
            computed_md5_hex,
            line_ending,
            ..
        } => {
            assert_eq!(line_ending, LineEnding::Lf);
            assert_ne!(embedded_md5_hex, computed_md5_hex);
        }
        other => panic!("esperaba Md5MismatchCritical, obtuve {other:?}"),
    }

    // E2E vía runner: lanza barrido sintético, debe abortar con error
    // crítico cuando llega al idx target.
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    std::fs::write(&input_path, STANDARD.encode(&ct_full)).unwrap();

    let opts = RunOptions {
        input_path,
        state_dir: state_dir.clone(),
        batch_size: 64 * 1024 * 1024,
        resume: false,
        force_resume: false,
        flush_every_n_batches: 1,
    };
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = std::sync::Arc::clone(&stop);
    // Watchdog: aborta el test si tarda más de 60s.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(60));
        stop_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    let _ = target_idx; // consumido para mostrar intención
    let sink = quattro_crack::runner::StderrSink::new();
    let result = runner::run(opts, &sink, stop);
    let err = result.expect_err("runner debería abortar por Md5MismatchCritical");
    let msg_err = format!("{err:?}");
    assert!(
        msg_err.contains("Md5MismatchCritical")
            || msg_err.contains("MD5")
            || msg_err.to_lowercase().contains("crítico"),
        "el error debería mencionar Md5MismatchCritical: {msg_err}"
    );

    // Estado debe haberse persistido.
    let progress_path = state_dir.join("progress.toml");
    assert!(
        progress_path.exists(),
        "progress.toml debe existir tras abort crítico"
    );
}

// ============================================================================
// 7. Pipeline completo sobre corpus sintético: 100 plaintexts, 100 idx,
//    cada uno encontrado por el kernel.
// ============================================================================

#[test]
fn test_full_pipeline_on_synthetic_corpus() {
    // 16 índices semi-aleatorios pero válidos por construcción
    // (`index_to_password` siempre devuelve un pw bien formado).
    // Cubre boundaries (0, N-1) + 14 idx random distribuidos por el
    // espacio para muestrear distintas combinaciones de vocales,
    // consonantes, posición de mayúscula y año.
    let mut idxs: Vec<u64> = vec![0u64, N - 1];
    let mut state: u64 = 0xface_b00c_dead_beef;
    while idxs.len() < 16 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        idxs.push(state % N);
    }

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load");
    const RANGE: u64 = 200_000;

    let mut found = 0;
    let mut failed: Vec<(usize, String)> = Vec::new();

    for (i, &target_idx) in idxs.iter().enumerate() {
        let pw_arr = index_to_password(target_idx);
        let pw: &[u8] = &pw_arr;

        // Plaintext sintético con LF (mayoría de la web es LF).
        let mut pt = Vec::new();
        pt.extend_from_slice(KNOWN_PREFIX_32_LF);
        pt.extend_from_slice(format!(" cuerpo {i:03}: lorem ipsum etc etc.").as_bytes());

        let key = build_key_passraw(pw);
        let ct = encrypt_cifraronline(&key, &pt);
        let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

        // Para idx pequeños arranca en idx_base=0; en general centra el
        // RANGE en target_idx con saturación en los bordes del espacio.
        let idx_base = target_idx
            .saturating_sub(RANGE / 2)
            .min(N.saturating_sub(RANGE));

        let started = Instant::now();
        let hits = bundle.launch(idx_base, RANGE, &ct_block_0).expect("launch");
        let elapsed = started.elapsed();

        if !hits.iter().any(|h| h.idx == target_idx) {
            failed.push((
                i,
                format!(
                    "no se encontró idx={target_idx} pw={:?} en {elapsed:?}",
                    std::str::from_utf8(pw).unwrap_or("<no utf8>")
                ),
            ));
            continue;
        }

        // CPU confirma con MD5 verify.
        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::Confirmed { .. } => found += 1,
            other => failed.push((i, format!("validate_hit: {other:?}"))),
        }
    }

    if !failed.is_empty() {
        for (i, why) in &failed {
            eprintln!("FAIL #{i}: {why}");
        }
        panic!("{}/{} muestras fallaron", failed.len(), idxs.len());
    }
    assert_eq!(found, idxs.len());
}

// ============================================================================
// 8. CLI inspect reporta la nueva construcción.
// ============================================================================

#[test]
fn test_cli_inspect_reports_new_construction() {
    let qc_bin = env!("CARGO_BIN_EXE_quattro-crack");
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let raw: Vec<u8> = (0..TOTAL_BIN_LEN).map(|i| (i & 0xff) as u8).collect();
    std::fs::write(&input_path, STANDARD.encode(&raw)).unwrap();

    let output = Command::new(qc_bin)
        .args(["inspect", input_path.to_str().unwrap()])
        .output()
        .expect("spawn inspect");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("aes-128-ecb"),
        "AES-128 indicator missing:\n{stdout}"
    );
    assert!(
        stdout.contains("passraw"),
        "passraw indicator missing:\n{stdout}"
    );
    assert!(
        stdout.contains("nullpad"),
        "nullpad indicator missing:\n{stdout}"
    );
    assert!(
        stdout.contains("md5verify"),
        "md5verify indicator missing:\n{stdout}"
    );
    assert!(
        !stdout.contains("aes-256"),
        "no debe mencionar AES-256:\n{stdout}"
    );
    assert!(
        !stdout.contains("PKCS7"),
        "no debe mencionar PKCS7:\n{stdout}"
    );
}

// ============================================================================
// 9. Sanity sobre prefijo-16: ambas variantes (LF/CRLF) comparten los
//    primeros 16 bytes "Leonardo da Vinc" (lo que valida el kernel).
// ============================================================================

#[test]
fn test_kernel_prefix_16_valid_for_both_line_endings() {
    assert_eq!(&KNOWN_PREFIX_32_LF[..16], KNOWN_PREFIX_16);
    assert_eq!(&KNOWN_PREFIX_32_CRLF[..16], KNOWN_PREFIX_16);
    assert_eq!(KNOWN_PREFIX_16, b"Leonardo da Vinc");
}

// Stub para silenciar warning: ProgressEvent no-op sink helper.
struct _NoopSink;
impl ProgressSink for _NoopSink {
    fn on_event(&self, _: ProgressEvent) {}
}
fn _ensure_outcomes_visible() {
    let _: Option<RunOutcome> = None;
}
