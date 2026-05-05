//! `test_aes128_fips197_device` y `test_aes256_fips197_device`.
//!
//! Vectores oficiales NIST FIPS-197 Appendix C.1 (AES-128) y C.3 (AES-256).

use quattro_crack::cuda::{gpu_aes128_decrypt, gpu_aes192_decrypt, gpu_aes256_decrypt, CudaCtx};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex válido")
}

#[test]
fn test_aes128_fips197_device() {
    // Appendix C.1 de FIPS-197.
    let key = h("000102030405060708090a0b0c0d0e0f");
    let plain = h("00112233445566778899aabbccddeeff");
    let cipher = h("69c4e0d86a7b0430d8cdb78070b4c55a");

    let ctx = CudaCtx::init().expect("CUDA");
    let pt = gpu_aes128_decrypt(&ctx, &key, &cipher).expect("aes128 dec");
    assert_eq!(pt, plain, "AES-128 decrypt FIPS-197 vector falla");
}

#[test]
fn test_aes128_fips197_device_batch() {
    // Mismo vector replicado para validar paralelización + key schedule
    // independiente por thread.
    let key1 = h("000102030405060708090a0b0c0d0e0f");
    let key2 = h("2b7e151628aed2a6abf7158809cf4f3c"); // FIPS-197 example key (also)
    let cipher1 = h("69c4e0d86a7b0430d8cdb78070b4c55a");
    let plain1 = h("00112233445566778899aabbccddeeff");

    let mut keys = Vec::new();
    let mut cts = Vec::new();
    keys.extend_from_slice(&key1);
    keys.extend_from_slice(&key2);
    cts.extend_from_slice(&cipher1);
    cts.extend_from_slice(&cipher1); // ct2 falso, solo verificamos que ct1 con key1 sale bien

    let ctx = CudaCtx::init().expect("CUDA");
    let pts = gpu_aes128_decrypt(&ctx, &keys, &cts).expect("aes128 dec batch");
    assert_eq!(&pts[0..16], &plain1[..]);
    // El segundo (key2 wrong para cipher1) NO debe coincidir con plain1.
    assert_ne!(&pts[16..32], &plain1[..]);
}

#[test]
fn test_aes192_fips197_device() {
    // Appendix C.2 de FIPS-197.
    let key = h("000102030405060708090a0b0c0d0e0f1011121314151617");
    let plain = h("00112233445566778899aabbccddeeff");
    let cipher = h("dda97ca4864cdfe06eaf70a0ec0d7191");

    let ctx = CudaCtx::init().expect("CUDA");
    let pt = gpu_aes192_decrypt(&ctx, &key, &cipher).expect("aes192 dec");
    assert_eq!(pt, plain, "AES-192 decrypt FIPS-197 vector falla");
}

#[test]
fn test_aes192_matches_rustcrypto() {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes192;

    let mut keys = Vec::new();
    let mut cts = Vec::new();
    let mut expected = Vec::new();

    for seed in 0u8..8 {
        let mut key = [0u8; 24];
        for (i, b) in key.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        let ct = [seed.wrapping_mul(11); 16];
        keys.extend_from_slice(&key);
        cts.extend_from_slice(&ct);

        let cipher = Aes192::new_from_slice(&key).unwrap();
        let mut ga = GenericArray::clone_from_slice(&ct);
        cipher.decrypt_block(&mut ga);
        expected.extend_from_slice(&ga);
    }

    let ctx = CudaCtx::init().expect("CUDA");
    let pts = gpu_aes192_decrypt(&ctx, &keys, &cts).expect("aes192 dec batch");
    assert_eq!(pts, expected, "AES-192 device discrepa con RustCrypto");
}

#[test]
fn test_aes256_fips197_device() {
    // Appendix C.3 de FIPS-197.
    let key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let plain = h("00112233445566778899aabbccddeeff");
    let cipher = h("8ea2b7ca516745bfeafc49904b496089");

    let ctx = CudaCtx::init().expect("CUDA");
    let pt = gpu_aes256_decrypt(&ctx, &key, &cipher).expect("aes256 dec");
    assert_eq!(pt, plain, "AES-256 decrypt FIPS-197 vector falla");
}

#[test]
fn test_aes_device_matches_rustcrypto() {
    // Sanity: 32 (key, ct) aleatorios — comparamos device contra RustCrypto.
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes128;

    let mut keys = Vec::new();
    let mut cts = Vec::new();
    let mut expected = Vec::new();

    for seed in 0u8..16 {
        let key = [seed; 16];
        let ct = [seed.wrapping_mul(7); 16];
        keys.extend_from_slice(&key);
        cts.extend_from_slice(&ct);

        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut ga = GenericArray::clone_from_slice(&ct);
        cipher.decrypt_block(&mut ga);
        expected.extend_from_slice(&ga);
    }

    let ctx = CudaCtx::init().expect("CUDA");
    let pts = gpu_aes128_decrypt(&ctx, &keys, &cts).expect("aes128 dec");
    assert_eq!(pts, expected, "AES-128 device discrepa con RustCrypto");
}
