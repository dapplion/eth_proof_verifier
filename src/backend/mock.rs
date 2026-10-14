//! Mock proofs, for devnets only (`--mock-proofs`).
//!
//! The mock zkVMs of [zkboost](https://github.com/eth-act/zkboost) (v0.12.0 and later) prove
//! nothing. In place of a proof they send the SSZ container
//!
//! ```text
//! MockProof { public_values: List[byte], proof: List[byte] }
//! ```
//!
//! whose public values are the ones a real proof of the payload would commit to, and whose proof is
//! random bytes. A mock proof cannot be verified, so in mock mode it is accepted without a
//! cryptographic check, but its public values are still checked against the public input, as a real
//! proof's are. A proof that is not a `MockProof` is verified as usual. Prysm (`--zkvm-mock-proofs`)
//! and the eth-act Lighthouse (`--proof-engine-mock-proofs`) accept mock proofs the same way.

use std::sync::Arc;

use super::{ProofVerifier, Rejection};

/// Accepts a [`MockProof`] in place of a proof of the wrapped verifier's proof type.
pub struct MockProofs(pub Arc<dyn ProofVerifier>);

impl ProofVerifier for MockProofs {
    fn verify(&self, proof: &[u8]) -> Result<Vec<u8>, Rejection> {
        match MockProof::from_ssz_bytes(proof) {
            Some(mock) => Ok(mock.public_values.to_vec()),
            None => self.0.verify(proof),
        }
    }
}

/// zkboost's `MockProof`. Decoded by hand, as two variable-size lists are all it holds.
#[derive(Debug, PartialEq, Eq)]
pub struct MockProof<'a> {
    pub public_values: &'a [u8],
    pub proof: &'a [u8],
}

impl<'a> MockProof<'a> {
    /// The fixed part: one 4-byte offset per list.
    const OFFSETS_LEN: usize = 8;

    /// `None` unless `bytes` is a well-formed SSZ `MockProof`.
    pub fn from_ssz_bytes(bytes: &'a [u8]) -> Option<Self> {
        let offset = |at: usize| -> Option<usize> {
            let le = bytes.get(at..at + 4)?.try_into().ok()?;
            usize::try_from(u32::from_le_bytes(le)).ok()
        };
        let public_values_offset = offset(0)?;
        let proof_offset = offset(4)?;
        if public_values_offset != Self::OFFSETS_LEN
            || proof_offset < public_values_offset
            || proof_offset > bytes.len()
        {
            return None;
        }
        Some(Self {
            public_values: &bytes[public_values_offset..proof_offset],
            proof: &bytes[proof_offset..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An SSZ `MockProof`, encoded as zkboost encodes it.
    fn mock_proof(public_values: &[u8], proof: &[u8]) -> Vec<u8> {
        let proof_offset = MockProof::OFFSETS_LEN + public_values.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(MockProof::OFFSETS_LEN as u32).to_le_bytes());
        bytes.extend_from_slice(&(proof_offset as u32).to_le_bytes());
        bytes.extend_from_slice(public_values);
        bytes.extend_from_slice(proof);
        bytes
    }

    /// Stands in for a real proof system.
    struct Real;

    impl ProofVerifier for Real {
        fn verify(&self, _proof: &[u8]) -> Result<Vec<u8>, Rejection> {
            Err(Rejection::malformed("not a real proof"))
        }
    }

    #[test]
    fn decodes_the_zkboost_layout() {
        let bytes = mock_proof(&[1, 2, 3], &[4, 5]);
        // Pinned, so an encoder and this decoder cannot drift together.
        assert_eq!(bytes, [8, 0, 0, 0, 11, 0, 0, 0, 1, 2, 3, 4, 5]);
        assert_eq!(
            MockProof::from_ssz_bytes(&bytes),
            Some(MockProof {
                public_values: &[1, 2, 3],
                proof: &[4, 5],
            })
        );
    }

    #[test]
    fn decodes_empty_lists() {
        let bytes = mock_proof(&[], &[]);
        assert_eq!(
            MockProof::from_ssz_bytes(&bytes),
            Some(MockProof {
                public_values: &[],
                proof: &[],
            })
        );
    }

    #[test]
    fn rejects_bytes_that_are_not_a_mock_proof() {
        let mut first_offset_wrong = mock_proof(&[1], &[2]);
        first_offset_wrong[0] = 9;
        let mut offsets_out_of_order = mock_proof(&[1, 2], &[3]);
        offsets_out_of_order[4] = 7;
        let mut past_the_end = mock_proof(&[1], &[2]);
        past_the_end[4] = 12;

        for bytes in [
            &[][..],
            &[8, 0, 0, 0][..],
            &first_offset_wrong,
            &offsets_out_of_order,
            &past_the_end,
        ] {
            assert_eq!(MockProof::from_ssz_bytes(bytes), None, "{bytes:?}");
        }
    }

    /// The public values are returned for the caller to check, never taken as a verdict.
    #[test]
    fn returns_the_public_values_of_a_mock_proof() {
        let verifier = MockProofs(Arc::new(Real));
        let committed = verifier
            .verify(&mock_proof(&[0xaa; 43], &[0xbb; 16]))
            .expect("a mock proof is accepted");
        assert_eq!(committed, [0xaa; 43]);
    }

    #[test]
    fn verifies_anything_else_as_a_real_proof() {
        let verifier = MockProofs(Arc::new(Real));
        assert!(matches!(
            verifier.verify(&[0xff; 64]),
            Err(Rejection::Malformed(_))
        ));
    }
}
