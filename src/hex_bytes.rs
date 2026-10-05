//! Strict fixed-length hex decoding, shared so that every hex input accepts the same thing.

use std::fmt::Display;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    fn new(reason: impl Display) -> Self {
        Self(reason.to_string())
    }
}

/// Decode exactly `N` bytes, with at most one `0x` or `0X` prefix.
pub fn decode<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    let mut bytes = [0u8; N];
    hex::decode_to_slice(digits, &mut bytes).map_err(|e| match e {
        hex::FromHexError::InvalidStringLength => Error::new(format!(
            "expected {N} bytes, got {} hex digits",
            digits.len()
        )),
        other => Error::new(other),
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_prefix_or_none() {
        for value in ["abababab", "0xabababab", "0Xabababab", "ABABABAB"] {
            assert_eq!(decode::<4>(value).expect(value), [0xab; 4]);
        }
    }

    #[test]
    fn rejects_a_repeated_prefix() {
        assert!(decode::<4>("0x0xabababab").is_err());
    }

    #[test]
    fn rejects_the_wrong_length() {
        assert!(decode::<4>("ababab").is_err());
        assert!(decode::<4>("ababababab").is_err());
        assert!(decode::<4>("").is_err());
    }
}
