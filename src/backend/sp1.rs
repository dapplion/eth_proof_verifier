//! The key format, the proof encoding and the exit-code commitment are prover conventions, not SP1
//! itself. They follow `ere-verifier-sp1`, which produces the `ere-guests` artifacts.

use std::{array::from_fn, borrow::Borrow, sync::LazyLock};

use sp1_hypercube::{DIGEST_SIZE, PrimeField32};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{RECURSIVE_PROOF_NUM_PV_ELTS, RecursionPublicValues};
use sp1_verifier::{ProofFromNetwork, compressed::SP1CompressedVerifier};

use crate::{
    backend::{InvalidProgramVk, ProofVerifier, Rejection},
    registry::PROGRAM_VK_LEN,
};

/// A guard, not a size bound: bincode counts an in-memory claim, which can exceed the wire size, so
/// `MAX_PROOF_SIZE` here would refuse proofs the spec admits. `ere` uses 64 MiB too.
const MAX_DECODE_BYTES: usize = 64 * 1024 * 1024;

const PROGRAM_VK_LIMBS: usize = PROGRAM_VK_LEN / 8;

/// Bits per field element in the packed verifying key.
const WORD_BITS: u32 = 31;

/// Shared by every SP1 proof type: building it is the expensive part.
static RECURSION_VERIFIER: LazyLock<SP1CompressedVerifier> =
    LazyLock::new(SP1CompressedVerifier::new);

pub struct Sp1Verifier {
    /// Poseidon2 digest of the program's SP1 verifying key.
    program_vk: [SP1Field; DIGEST_SIZE],
}

impl Sp1Verifier {
    pub fn new(program_vk: &[u8]) -> Result<Self, InvalidProgramVk> {
        LazyLock::force(&RECURSION_VERIFIER);
        Ok(Self {
            program_vk: decode_program_vk(program_vk)?,
        })
    }
}

impl ProofVerifier for Sp1Verifier {
    fn verify(&self, proof_bytes: &[u8]) -> Result<Vec<u8>, Rejection> {
        let (proof, consumed): (ProofFromNetwork, usize) = bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::legacy().with_limit::<MAX_DECODE_BYTES>(),
        )
        .map_err(Rejection::malformed)?;
        if consumed != proof_bytes.len() {
            return Err(Rejection::malformed("trailing bytes after the proof"));
        }

        let compressed = proof.proof.try_as_compressed_ref().ok_or_else(|| {
            Rejection::malformed(format!(
                "expected a compressed proof, got {:?}",
                proof.mode()
            ))
        })?;

        // A guest that exited non-zero never reached its commitment.
        let recursion_public_values = compressed.proof.public_values.as_slice();
        if recursion_public_values.len() != RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(Rejection::malformed(
                "proof does not commit to an exit code",
            ));
        }
        let recursion_public_values: &RecursionPublicValues<_> = recursion_public_values.borrow();
        let exit_code = recursion_public_values.exit_code.as_canonical_u32();
        if exit_code != 0 {
            return Err(Rejection::unverified(format!(
                "guest exited with code {exit_code}"
            )));
        }

        let public_values = proof.public_values.as_slice();
        RECURSION_VERIFIER
            .verify_compressed_with_public_values(compressed, public_values, &self.program_vk)
            .map_err(Rejection::unverified)?;

        Ok(public_values.to_vec())
    }
}

/// `HashableKey::bytes32`: the digest's field elements as base-`2^31` digits of a big endian
/// integer, most significant first.
fn decode_program_vk(bytes: &[u8]) -> Result<[SP1Field; DIGEST_SIZE], InvalidProgramVk> {
    const WORD_MASK: u64 = (1 << WORD_BITS) - 1;

    if bytes.len() != PROGRAM_VK_LEN {
        return Err(InvalidProgramVk::new(format!(
            "expected {PROGRAM_VK_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let mut limbs: [u64; PROGRAM_VK_LIMBS] = from_fn(|i| {
        let offset = PROGRAM_VK_LEN - 8 * (i + 1);
        u64::from_be_bytes(from_fn(|j| bytes[offset + j]))
    });
    let mut words = [0u32; DIGEST_SIZE];
    for word in words.iter_mut().rev() {
        *word = (limbs[0] & WORD_MASK) as u32;
        for i in 0..PROGRAM_VK_LIMBS - 1 {
            limbs[i] = (limbs[i] >> WORD_BITS) | (limbs[i + 1] << (u64::BITS - WORD_BITS));
        }
        limbs[PROGRAM_VK_LIMBS - 1] >>= WORD_BITS;
    }

    // Leftover bits, or an element at or above the field order, means this is not a digest.
    if limbs != [0; PROGRAM_VK_LIMBS] || words.iter().any(|word| *word >= SP1Field::ORDER_U32) {
        return Err(InvalidProgramVk::new("not a canonical packed digest"));
    }
    Ok(words.map(from_canonical_u32))
}

/// Reaches `from_canonical_u32` through the bound: it is on a supertrait, in a crate this one does
/// not depend on directly.
fn from_canonical_u32<F: PrimeField32>(word: u32) -> F {
    F::from_canonical_u32(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_program_vk_of_the_wrong_length() {
        assert!(decode_program_vk(&[0; 31]).is_err());
        assert!(decode_program_vk(&[0; 33]).is_err());
    }

    /// 31 bits times 8 elements leaves the top byte unused, so a key that sets it is packed to a
    /// different convention and names no program here. The elements below it are all valid, so only
    /// the leftover-bits half of the canonicity check refuses this.
    #[test]
    fn rejects_a_program_vk_with_bits_outside_its_elements() {
        let mut top_byte_set = [0u8; PROGRAM_VK_LEN];
        top_byte_set[0] = 0x01;

        assert!(decode_program_vk(&top_byte_set).is_err());
    }

    /// Why the field-order half cannot be dropped. `from_canonical_u32` reduces modulo the order
    /// behind a `debug_assert`, so in release these bytes would bind to the same program as an
    /// all-zero digest: the leading element is the order, which reduces to zero.
    #[test]
    fn rejects_a_program_vk_holding_a_non_field_element() {
        let at_the_order =
            hex::decode("00fe000002000000000000000000000000000000000000000000000000000000")
                .expect("hex");

        assert!(decode_program_vk(&at_the_order).is_err());
    }
}
