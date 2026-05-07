//! `test_md5_rfc1321_device` — vectores oficiales RFC 1321 §A.5.

use quattro_crack::cuda::{gpu_md5_batch, gpu_md5_md5_batch, CudaCtx};

const VECTORS: &[(&[u8], &str)] = &[
    (b"", "d41d8cd98f00b204e9800998ecf8427e"),
    (b"a", "0cc175b9c0f1b6a831c399e269772661"),
    (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
    (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
    (
        b"abcdefghijklmnopqrstuvwxyz",
        "c3fcd3d76192e4007dfb496cca67e13b",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "d174ab98d277d9f5a5611c2c9f419d9f",
    ),
    (
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "57edf4a22be3c955ac49da2e2107b67a",
    ),
];

#[test]
fn test_md5_rfc1321_device() {
    let ctx = CudaCtx::init().expect("CUDA");

    let stride: u32 = 128; // suficiente para el más largo (80 B)
    let n = VECTORS.len();
    let mut data = vec![0u8; n * stride as usize];
    let mut lens = vec![0u32; n];
    for (i, (msg, _)) in VECTORS.iter().enumerate() {
        data[i * stride as usize..i * stride as usize + msg.len()].copy_from_slice(msg);
        lens[i] = msg.len() as u32;
    }

    let digests = gpu_md5_batch(&ctx, &data, &lens, stride).expect("gpu md5");
    assert_eq!(digests.len(), n * 16);

    for (i, (msg, expected)) in VECTORS.iter().enumerate() {
        let got = hex::encode(&digests[i * 16..(i + 1) * 16]);
        assert_eq!(
            &got,
            expected,
            "MD5 device discrepa con RFC 1321 para input len={}",
            msg.len()
        );
    }
}

#[test]
fn test_md5_md5_device_matches_double_hash() {
    let ctx = CudaCtx::init().expect("CUDA");

    // Aplico md5 al input "abc" en CPU para tener el digest, luego pido a la
    // GPU MD5(MD5(.)) y comparo con MD5(MD5("abc")) calculado en CPU también.
    let inputs: &[&[u8]] = &[b"", b"abc", b"message digest", b"deadbeef"];
    let mut digest_buf = Vec::with_capacity(inputs.len() * 16);
    for msg in inputs {
        let d: [u8; 16] = md5_cpu(msg);
        digest_buf.extend_from_slice(&d);
    }

    let gpu_dbl = gpu_md5_md5_batch(&ctx, &digest_buf).expect("gpu md5_md5");
    assert_eq!(gpu_dbl.len(), inputs.len() * 16);

    for (i, msg) in inputs.iter().enumerate() {
        let single_cpu = md5_cpu(msg);
        let double_cpu = md5_cpu(&single_cpu);
        let gpu_slice = &gpu_dbl[i * 16..(i + 1) * 16];
        assert_eq!(
            gpu_slice,
            &double_cpu[..],
            "MD5(MD5(.)) device discrepa para input len={}",
            msg.len()
        );
    }
}

fn md5_cpu(data: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}
