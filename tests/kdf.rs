//! `test_kdf_vectors_vs_python` — vectores de validación de las 9 KDFs
//! generados con `hashlib` de Python (CPython 3.12) en el momento de
//! crear la fase 2. Si Python (especificación de jure de los formatos
//! UTF-8/UTF-16) y nuestra implementación disienten, falla aquí.

use quattro_crack::config::Kdf;
use quattro_crack::kdf::derive;

/// Triplas `(password, kdf, hexdigest_de_python)`.
/// Generado con:
///   python3 - <<'PY'
///   import hashlib
///   ... (ver tools de Fase 2)
///   PY
const VECTORS: &[(&str, Kdf, &str)] = &[
    // pw = ".aAaabbbb1000."  (idx = 0, password documentado de la spec)
    (".aAaabbbb1000.", Kdf::Md5Utf8,     "9ac15f8d5a92b3bc03a949212e6a6aed"),
    (".aAaabbbb1000.", Kdf::Md5Utf16Le,  "94481c80c010cd8f200e791ccea7e61a"),
    (".aAaabbbb1000.", Kdf::Md5Utf16Be,  "8bedc537a5dec2a34acad809db357ed7"),
    (".aAaabbbb1000.", Kdf::Md5x2Utf8,   "fcffd97b40ba100bf1f51650022e7518"),
    (".aAaabbbb1000.", Kdf::Md5Dup,      "9ac15f8d5a92b3bc03a949212e6a6aed9ac15f8d5a92b3bc03a949212e6a6aed"),
    (".aAaabbbb1000.", Kdf::Md5Md5Rev,   "9ac15f8d5a92b3bc03a949212e6a6aeded6a6a2e2149a903bcb3925a8d5fc19a"),
    (".aAaabbbb1000.", Kdf::Md5HexFull,  "3961633135663864356139326233626330336139343932313265366136616564"),
    (".aAaabbbb1000.", Kdf::Md5HexLo16,  "39616331356638643561393262336263"),
    (".aAaabbbb1000.", Kdf::PwPadded,    "2e6141616162626262313030302e0000"),

    // pw = ".zzzzuuuU1999." (idx = N-1)
    (".zzzzuuuU1999.", Kdf::Md5Utf8,     "9a3fbdba108501ac3f19bb7bee982974"),
    (".zzzzuuuU1999.", Kdf::Md5Utf16Le,  "63f6e7d991173f6489febc383780ab42"),
    (".zzzzuuuU1999.", Kdf::Md5Utf16Be,  "274d884fe1ce275a2ff73b7cacb46c30"),
    (".zzzzuuuU1999.", Kdf::Md5x2Utf8,   "5ff6d2280f90df47a2ecfa618a1926a6"),
    (".zzzzuuuU1999.", Kdf::Md5Dup,      "9a3fbdba108501ac3f19bb7bee9829749a3fbdba108501ac3f19bb7bee982974"),
    (".zzzzuuuU1999.", Kdf::Md5Md5Rev,   "9a3fbdba108501ac3f19bb7bee982974742998ee7bbb193fac018510babd3f9a"),
    (".zzzzuuuU1999.", Kdf::Md5HexFull,  "3961336662646261313038353031616333663139626237626565393832393734"),
    (".zzzzuuuU1999.", Kdf::Md5HexLo16,  "39613366626462613130383530316163"),
    (".zzzzuuuU1999.", Kdf::PwPadded,    "2e7a7a7a7a75757555313939392e0000"),

    // pw = ".bAioembl1452." (random sample del espacio)
    (".bAioembl1452.", Kdf::Md5Utf8,     "1289f8d7072cdede4f758cf77461c80a"),
    (".bAioembl1452.", Kdf::Md5Utf16Le,  "1dffe05a6b912ad43795c89ded4e647a"),
    (".bAioembl1452.", Kdf::Md5Utf16Be,  "1d803adcf89638814132f7c58dfa8937"),
    (".bAioembl1452.", Kdf::Md5x2Utf8,   "6153594fc9a4970609948ed055d8858a"),
    (".bAioembl1452.", Kdf::Md5Dup,      "1289f8d7072cdede4f758cf77461c80a1289f8d7072cdede4f758cf77461c80a"),
    (".bAioembl1452.", Kdf::Md5Md5Rev,   "1289f8d7072cdede4f758cf77461c80a0ac86174f78c754fdede2c07d7f88912"),
    (".bAioembl1452.", Kdf::Md5HexFull,  "3132383966386437303732636465646534663735386366373734363163383061"),
    (".bAioembl1452.", Kdf::Md5HexLo16,  "31323839663864373037326364656465"),
    (".bAioembl1452.", Kdf::PwPadded,    "2e6241696f656d626c313435322e0000"),
];

#[test]
fn test_kdf_vectors_vs_python() {
    for (pw, kdf, expected_hex) in VECTORS {
        let got = derive(*kdf, pw.as_bytes());
        let got_hex = hex::encode(got.as_slice());
        assert_eq!(
            &got_hex, expected_hex,
            "KDF discrepa con Python para pw={pw:?} kdf={}",
            kdf.as_str()
        );
    }
}

#[test]
fn test_all_9_kdfs_covered_by_vectors() {
    for &kdf in Kdf::all() {
        let count = VECTORS.iter().filter(|(_, k, _)| *k == kdf).count();
        assert!(count >= 3, "kdf={} debería tener ≥3 vectores", kdf.as_str());
    }
}
