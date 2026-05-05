//! Tipos de configuración para el barrido.
//!
//! El modo de cifrado del reto está confirmado oficialmente como **AES-CBC
//! con padding PKCS7**. El `enum Mode` solo tiene una variante para
//! reflejar esa certeza directamente en el sistema de tipos: cualquier
//! intento de añadir CFB/OFB/CTR es un error de tipos, no de runtime.
//! Ver `DECISIONS.md` D-006.

use serde::{Deserialize, Serialize};

/// Modo de cifrado AES soportado por este barrido.
///
/// **Solo CBC** — confirmado por el autor del reto. No es deuda técnica:
/// el espacio de configuraciones se cierra en este eje.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Mode {
    Cbc,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cbc => "cbc",
        }
    }
}

/// Función de derivación de clave: 14 variantes (9 originales + 5 ampliación
/// académica de Fase 3.5).
///
/// **IDs estables**: el orden 0..8 de las 9 originales se preserva
/// exactamente (es contrato de los PTX precompilados y de los hits ya
/// emitidos por el kernel).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Kdf {
    // ---------- 9 KDFs originales (Fase 2/3) — IDs 0..8 ----------
    /// `MD5(pw.encode("utf-8"))` — 16 B.
    Md5Utf8,
    /// `MD5(pw.encode("utf-16-le"))` — 16 B.
    Md5Utf16Le,
    /// `MD5(pw.encode("utf-16-be"))` — 16 B.
    Md5Utf16Be,
    /// `MD5(MD5(pw_utf8))` — 16 B.
    Md5x2Utf8,
    /// `MD5(pw_utf8) ‖ MD5(pw_utf8)` — 32 B.
    Md5Dup,
    /// `MD5(pw_utf8) ‖ MD5(pw_utf8)[::-1]` — 32 B.
    Md5Md5Rev,
    /// 32 chars ASCII del hexdigest. — 32 B.
    Md5HexFull,
    /// Primeros 16 chars ASCII del hexdigest. — 16 B.
    Md5HexLo16,
    /// `(pw_utf8 + b"\0"*16)[:16]` — 16 B.
    PwPadded,

    // ---------- 5 KDFs nuevas (Fase 3.5) — IDs 9..13 ----------
    /// `EVP_BytesToKey(MD5, pw, salt=None, iter=1)[..32]` — 32 B.
    /// `D_1 = MD5(pw)`, `D_2 = MD5(D_1 ‖ pw)`, key = `D_1 ‖ D_2`.
    EvpMd5Aes256Nosalt,
    /// `EVP_BytesToKey(MD5, pw, salt=None, iter=1)[..24]` — 24 B.
    /// Mismas D_1, D_2 que arriba, truncadas a 24 B.
    EvpMd5Aes192Nosalt,
    /// `MD5(pw) ‖ MD5(pw)[..8]` — 24 B.
    Md5Trunc24,
    /// `MD5(pw) ‖ MD5(MD5(pw))[..8]` — 24 B.
    Md5Md5x2_24,
    /// Primeros 24 chars ASCII del hexdigest. — 24 B.
    Md5HexLo24,
}

impl Kdf {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5Utf8 => "md5_utf8",
            Self::Md5Utf16Le => "md5_utf16le",
            Self::Md5Utf16Be => "md5_utf16be",
            Self::Md5x2Utf8 => "md5x2_utf8",
            Self::Md5Dup => "md5_dup",
            Self::Md5Md5Rev => "md5_md5rev",
            Self::Md5HexFull => "md5hex_full",
            Self::Md5HexLo16 => "md5hex_lo16",
            Self::PwPadded => "pw_padded",
            Self::EvpMd5Aes256Nosalt => "evp_md5_aes256_nosalt",
            Self::EvpMd5Aes192Nosalt => "evp_md5_aes192_nosalt",
            Self::Md5Trunc24 => "md5_trunc24",
            Self::Md5Md5x2_24 => "md5_md5x2_24",
            Self::Md5HexLo24 => "md5hex_lo24",
        }
    }

    /// Tamaño de la clave producida por esta KDF, en bytes (16 / 24 / 32).
    pub fn key_len_bytes(self) -> usize {
        match self {
            Self::Md5Utf8
            | Self::Md5Utf16Le
            | Self::Md5Utf16Be
            | Self::Md5x2Utf8
            | Self::Md5HexLo16
            | Self::PwPadded => 16,
            Self::EvpMd5Aes192Nosalt
            | Self::Md5Trunc24
            | Self::Md5Md5x2_24
            | Self::Md5HexLo24 => 24,
            Self::Md5Dup
            | Self::Md5Md5Rev
            | Self::Md5HexFull
            | Self::EvpMd5Aes256Nosalt => 32,
        }
    }

    /// Iterador sobre las 14 KDFs en orden de declaración.
    pub fn all() -> &'static [Kdf] {
        &[
            // 0..8 (originales — orden contrato)
            Self::Md5Utf8,
            Self::Md5Utf16Le,
            Self::Md5Utf16Be,
            Self::Md5x2Utf8,
            Self::Md5Dup,
            Self::Md5Md5Rev,
            Self::Md5HexFull,
            Self::Md5HexLo16,
            Self::PwPadded,
            // 9..13 (Fase 3.5)
            Self::EvpMd5Aes256Nosalt,
            Self::EvpMd5Aes192Nosalt,
            Self::Md5Trunc24,
            Self::Md5Md5x2_24,
            Self::Md5HexLo24,
        ]
    }

    /// Identificador numérico estable que el kernel CUDA usa como `KDF_ID`
    /// y que el host usa para indexar el array de PTX. Coincide con el
    /// índice en `Kdf::all()`. Los IDs 0..8 son contrato — nunca renumerar.
    pub fn id(self) -> u32 {
        match self {
            Self::Md5Utf8 => 0,
            Self::Md5Utf16Le => 1,
            Self::Md5Utf16Be => 2,
            Self::Md5x2Utf8 => 3,
            Self::Md5Dup => 4,
            Self::Md5Md5Rev => 5,
            Self::Md5HexFull => 6,
            Self::Md5HexLo16 => 7,
            Self::PwPadded => 8,
            Self::EvpMd5Aes256Nosalt => 9,
            Self::EvpMd5Aes192Nosalt => 10,
            Self::Md5Trunc24 => 11,
            Self::Md5Md5x2_24 => 12,
            Self::Md5HexLo24 => 13,
        }
    }
}

/// De dónde sale el IV de cada barrido.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum IvSource {
    /// Los primeros 16 B del binario decodificado del fichero objetivo.
    First16,
    /// 16 B a 0x00.
    Zeros,
    /// `MD5(pw_utf8)` — depende de la candidata.
    Md5Pw,
}

impl IvSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::First16 => "first16",
            Self::Zeros => "zeros",
            Self::Md5Pw => "md5pw",
        }
    }

    /// Modo numérico que entiende el kernel: 0=first16, 1=zeros, 2=md5pw.
    pub fn iv_mode(self) -> u32 {
        match self {
            Self::First16 => 0,
            Self::Zeros => 1,
            Self::Md5Pw => 2,
        }
    }
}

/// Una configuración del plan: tripla (KDF, modo, IV).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ConfigEntry {
    pub kdf: Kdf,
    pub mode: Mode,
    pub iv: IvSource,
}

impl ConfigEntry {
    pub fn new(kdf: Kdf, iv: IvSource) -> Self {
        Self {
            kdf,
            mode: Mode::Cbc,
            iv,
        }
    }

    /// Identificador legible `kdf/mode/iv` para logs y CLI.
    pub fn display_id(&self) -> String {
        format!("{}/{}/{}", self.kdf.as_str(), self.mode.as_str(), self.iv.as_str())
    }

    pub fn key_len_bytes(&self) -> usize {
        self.kdf.key_len_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_all_lists_fourteen_variants() {
        assert_eq!(Kdf::all().len(), 14);
    }

    #[test]
    fn klen_distribution_is_six_four_four() {
        let k16 = Kdf::all().iter().filter(|k| k.key_len_bytes() == 16).count();
        let k24 = Kdf::all().iter().filter(|k| k.key_len_bytes() == 24).count();
        let k32 = Kdf::all().iter().filter(|k| k.key_len_bytes() == 32).count();
        assert_eq!(k16, 6, "AES-128 KDFs: {k16}");
        assert_eq!(k24, 4, "AES-192 KDFs: {k24}");
        assert_eq!(k32, 4, "AES-256 KDFs: {k32}");
    }

    #[test]
    fn kdf_ids_match_array_order() {
        for (i, &k) in Kdf::all().iter().enumerate() {
            assert_eq!(k.id() as usize, i);
        }
    }

    #[test]
    fn original_nine_keep_their_ids() {
        // Contrato D-013: nunca renumerar 0..8.
        assert_eq!(Kdf::Md5Utf8.id(), 0);
        assert_eq!(Kdf::Md5Utf16Le.id(), 1);
        assert_eq!(Kdf::Md5Utf16Be.id(), 2);
        assert_eq!(Kdf::Md5x2Utf8.id(), 3);
        assert_eq!(Kdf::Md5Dup.id(), 4);
        assert_eq!(Kdf::Md5Md5Rev.id(), 5);
        assert_eq!(Kdf::Md5HexFull.id(), 6);
        assert_eq!(Kdf::Md5HexLo16.id(), 7);
        assert_eq!(Kdf::PwPadded.id(), 8);
    }

    #[test]
    fn display_id_format() {
        let c = ConfigEntry::new(Kdf::Md5Utf8, IvSource::First16);
        assert_eq!(c.display_id(), "md5_utf8/cbc/first16");
    }
}
