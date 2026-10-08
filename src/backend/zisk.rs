//! The proof encoding, the key packing and the public-values layout are prover conventions, not
//! ZisK itself. They follow `ere-verifier-zisk`, which produces the `ere-guests` artifacts.

use std::array::from_fn;

use proofman_verifier::VadcopFinalProof;
use zisk_verifier::{
    IS_VADCOP_FINAL_PROOF, PROGRAM_VK_LEN as PROGRAM_VK_WORDS, VADCOP_FINAL_FLAG_LEN, ZISK_PUBLICS,
    verify_vadcop_final,
};

use crate::{
    backend::{InvalidProgramVk, MAX_DECODE_BYTES, ProofVerifier, Rejection},
    registry::PROGRAM_VK_LEN,
};

/// A registry key is 32 bytes for every proof system. Breaking the build is the point: were ZisK to
/// widen its key, decoding one from the registry would otherwise silently read the wrong thing.
const _: () = assert!(PROGRAM_VK_WORDS * 8 == PROGRAM_VK_LEN);

/// Aggregation verifying key for VadcopFinal proofs under the blake3 hash family, from ZisK
/// 1.3.1-alpha. Vendored from `ere-verifier-zisk` (Apache-2.0 OR MIT).
///
/// It changes between ZisK patch releases, so it is pinned together with the verifier crate.
/// Reproduce it from `provingKey/zisk/vadcop_final/vadcop_final.verkey.bin` in
/// <https://storage.googleapis.com/zisk-setup/zisk-verifykey-1.3.1-alpha-blake3.tar.gz>.
const VADCOP_FINAL_VK: [u64; 4] = [
    17362875648210006843,
    17118080347053690355,
    16676305655426731175,
    2889446131052424392,
];

/// A proof of any other family cannot authenticate against `VADCOP_FINAL_VK`.
const VADCOP_FINAL_HASH_FAMILY: &str = "blake3";

/// Goldilocks (`2^64 - 2^32 + 1`). A limb at or above it is not a field element.
const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;

/// The public values carry a flag and the program's key before the guest's own output.
const GUEST_OUTPUT_OFFSET: usize = VADCOP_FINAL_FLAG_LEN + PROGRAM_VK_WORDS;

/// Verifier bound to one compiled guest program.
pub struct ZiskVerifier {
    /// Merkle root of the program's ROM trace, as four Goldilocks limbs.
    program_vk: [u64; PROGRAM_VK_WORDS],
}

impl ZiskVerifier {
    pub fn new(program_vk: &[u8]) -> Result<Self, InvalidProgramVk> {
        Ok(Self {
            program_vk: decode_program_vk(program_vk)?,
        })
    }
}

impl ProofVerifier for ZiskVerifier {
    fn verify(&self, proof_bytes: &[u8]) -> Result<Vec<u8>, Rejection> {
        let (proof, consumed): (VadcopFinalProof, usize) = bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::legacy().with_limit::<MAX_DECODE_BYTES>(),
        )
        .map_err(Rejection::malformed)?;
        if consumed != proof_bytes.len() {
            return Err(Rejection::malformed("trailing bytes after the proof"));
        }

        if proof.compressed {
            return Err(Rejection::malformed(
                "expected an uncompressed VadcopFinal proof",
            ));
        }
        if proof.hash != VADCOP_FINAL_HASH_FAMILY {
            return Err(Rejection::malformed(format!(
                "expected the {VADCOP_FINAL_HASH_FAMILY} hash family, got {}",
                proof.hash
            )));
        }
        let expected_public_values = GUEST_OUTPUT_OFFSET + ZISK_PUBLICS;
        if proof.public_values.len() != expected_public_values {
            return Err(Rejection::malformed(format!(
                "expected {expected_public_values} public values, got {}",
                proof.public_values.len()
            )));
        }
        if proof.public_values[0] != IS_VADCOP_FINAL_PROOF {
            return Err(Rejection::malformed("not a VadcopFinal proof"));
        }

        // A proof names the program it is of, so this is settled before the cryptography runs.
        if proof.public_values[VADCOP_FINAL_FLAG_LEN..GUEST_OUTPUT_OFFSET] != self.program_vk {
            return Err(Rejection::unverified("proof is of another program"));
        }

        if !verify_vadcop_final(&proof, &VADCOP_FINAL_VK) {
            return Err(Rejection::unverified("the proof does not verify"));
        }

        // Fixed-width, so a guest's output sits in a zero-padded region rather than filling it.
        // A verified proof's values are in range, so the narrowing below cannot fail here.
        proof.public_values[GUEST_OUTPUT_OFFSET..]
            .iter()
            .map(|value| {
                u32::try_from(*value)
                    .map(u32::to_le_bytes)
                    .map_err(|_| Rejection::malformed("a public value does not fit in 32 bits"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|words| words.concat())
    }
}

/// The four limbs ZisK provers publish: little endian, least significant limb first.
fn decode_program_vk(bytes: &[u8]) -> Result<[u64; PROGRAM_VK_WORDS], InvalidProgramVk> {
    if bytes.len() != PROGRAM_VK_LEN {
        return Err(InvalidProgramVk::new(format!(
            "expected {PROGRAM_VK_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let limbs: [u64; PROGRAM_VK_WORDS] =
        from_fn(|i| u64::from_le_bytes(from_fn(|j| bytes[8 * i + j])));
    if limbs.iter().any(|limb| *limb >= GOLDILOCKS_ORDER) {
        return Err(InvalidProgramVk::new("a limb is not a field element"));
    }
    Ok(limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_program_vk_of_the_wrong_length() {
        assert!(decode_program_vk(&[0; 31]).is_err());
        assert!(decode_program_vk(&[0; 33]).is_err());
    }

    /// Unchecked, a limb above the order would reduce inside the field and name a program other
    /// than the one its operator wrote.
    #[test]
    fn rejects_a_program_vk_holding_a_non_field_element() {
        let mut at_the_order = [0u8; PROGRAM_VK_LEN];
        at_the_order[..8].copy_from_slice(&GOLDILOCKS_ORDER.to_le_bytes());

        assert!(decode_program_vk(&at_the_order).is_err());
    }
}
