//! The public input that binds a proof to the payload a beacon node asked about.
//!
//! EIP-8025 gives the beacon node four fields, derived from its own state rather than taken off
//! the wire, and the guest program commits to those same four fields as its only output. A proof
//! answers the beacon node's question exactly when the two agree.
//!
//! `proof-engine.md` says to use `hash_tree_root(public_input)` as the proof-system public input.
//! No shipped guest commits a root; every one commits the plain SSZ serialisation of its
//! `StatelessValidationResult`, so that is what this module produces and what a proof is checked
//! against. The field list is identical and the encoding is fixed-length and injective, so binding
//! to the bytes binds exactly as tightly as binding to their root. The roots could not agree in
//! any case: the spec's `PublicInput` is an EIP-7688 `ProgressiveContainer` and the guest's result
//! is a plain fixed container, so the two merkleize differently.

/// Length of the canonical encoding: root (32) ++ `successful_validation` (1) ++ `chain_id` (8)
/// ++ `schema_id` (2).
pub const ENCODED_LEN: usize = 43;

/// The guests' sentinel `schema_id`, committed when a guest could not decode its input or could
/// not produce a validation result. The rest of the result is then zero, so such a proof can never
/// match a real public input.
pub const UNDECODABLE_SCHEMA_ID: u16 = 0;

/// The four fields a beacon node derives and a guest commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInput {
    /// `hash_tree_root` of the `NewPayloadRequest` whose execution the proof certifies.
    pub new_payload_request_root: [u8; 32],
    /// Whether the guest accepted the payload. A verifier only treats `true` as a validity signal.
    pub successful_validation: bool,
    /// The chain the payload was validated against, which stops cross-chain replay.
    pub chain_id: u64,
    /// The input schema and fork rules the guest ran, which stops a fork mismatch.
    pub schema_id: u16,
}

impl PublicInput {
    /// The canonical SSZ encoding of the equivalent `StatelessValidationResult`.
    pub fn encode(&self) -> [u8; ENCODED_LEN] {
        let mut encoded = [0u8; ENCODED_LEN];
        encoded[..32].copy_from_slice(&self.new_payload_request_root);
        encoded[32] = u8::from(self.successful_validation);
        encoded[33..41].copy_from_slice(&self.chain_id.to_le_bytes());
        encoded[41..].copy_from_slice(&self.schema_id.to_le_bytes());
        encoded
    }

    /// Whether the bytes a guest committed to are this public input.
    ///
    /// The committed bytes may be longer than the encoding, because a proof system can place the
    /// guest's output in a fixed-width region: ZisK commits a fixed number of words whatever the
    /// guest wrote. The padding must be zero, so that nothing the guest committed beyond its
    /// result goes unchecked.
    pub fn is_committed_by(&self, committed: &[u8]) -> bool {
        let Some((output, padding)) = committed.split_at_checked(ENCODED_LEN) else {
            return false;
        };
        output == self.encode() && padding.iter().all(|byte| *byte == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_input() -> PublicInput {
        PublicInput {
            new_payload_request_root: [0xaa; 32],
            successful_validation: true,
            chain_id: 0x0102_0304_0506_0708,
            schema_id: 0x1501,
        }
    }

    /// The layout the guests commit to, asserted field by field so a silent reordering cannot pass.
    #[test]
    fn encodes_to_the_guest_layout() {
        let encoded = public_input().encode();

        assert_eq!(encoded.len(), 43);
        assert_eq!(&encoded[..32], &[0xaa; 32]);
        assert_eq!(encoded[32], 1);
        assert_eq!(&encoded[33..41], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(&encoded[41..], &0x1501_u16.to_le_bytes());
    }

    #[test]
    fn accepts_its_own_encoding() {
        assert!(public_input().is_committed_by(&public_input().encode()));
    }

    #[test]
    fn accepts_zero_padding_but_not_padding_with_content() {
        let mut padded = public_input().encode().to_vec();
        padded.extend_from_slice(&[0; 21]);
        assert!(public_input().is_committed_by(&padded));

        let last = padded.len() - 1;
        padded[last] = 1;
        assert!(!public_input().is_committed_by(&padded));
    }

    #[test]
    fn rejects_a_different_public_input() {
        let other = PublicInput {
            chain_id: 1,
            ..public_input()
        };
        assert!(!public_input().is_committed_by(&other.encode()));
    }

    /// A guest that rejected the payload commits `successful_validation = false`, which differs
    /// from what a beacon node derives and so cannot be mistaken for a positive signal.
    #[test]
    fn rejects_an_unsuccessful_validation() {
        let unsuccessful = PublicInput {
            successful_validation: false,
            ..public_input()
        };
        assert!(!public_input().is_committed_by(&unsuccessful.encode()));
    }

    #[test]
    fn rejects_truncated_commitments() {
        let encoded = public_input().encode();
        assert!(!public_input().is_committed_by(&encoded[..42]));
        assert!(!public_input().is_committed_by(&[]));
    }
}
