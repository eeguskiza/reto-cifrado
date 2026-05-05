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

/// Función de derivación de clave: 9 variantes (§3.1 de la spec).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Kdf {
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
        }
    }

    /// Tamaño de la clave producida por esta KDF, en bytes.
    pub fn key_len_bytes(self) -> usize {
        match self {
            Self::Md5Utf8
            | Self::Md5Utf16Le
            | Self::Md5Utf16Be
            | Self::Md5x2Utf8
            | Self::Md5HexLo16
            | Self::PwPadded => 16,
            Self::Md5Dup | Self::Md5Md5Rev | Self::Md5HexFull => 32,
        }
    }

    /// Iterador sobre las 9 KDFs en orden de declaración.
    pub fn all() -> &'static [Kdf] {
        &[
            Self::Md5Utf8,
            Self::Md5Utf16Le,
            Self::Md5Utf16Be,
            Self::Md5x2Utf8,
            Self::Md5Dup,
            Self::Md5Md5Rev,
            Self::Md5HexFull,
            Self::Md5HexLo16,
            Self::PwPadded,
        ]
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
    fn kdf_all_lists_nine_variants() {
        assert_eq!(Kdf::all().len(), 9);
    }

    #[test]
    fn klen_distribution_is_six_to_three() {
        let k16 = Kdf::all().iter().filter(|k| k.key_len_bytes() == 16).count();
        let k32 = Kdf::all().iter().filter(|k| k.key_len_bytes() == 32).count();
        assert_eq!(k16, 6);
        assert_eq!(k32, 3);
    }

    #[test]
    fn display_id_format() {
        let c = ConfigEntry::new(Kdf::Md5Utf8, IvSource::First16);
        assert_eq!(c.display_id(), "md5_utf8/cbc/first16");
    }
}
