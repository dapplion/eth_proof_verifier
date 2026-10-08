//! The spec says to use `hash_tree_root(public_input)`. No guest commits a root: every guest commits
//! the plain SSZ of `StatelessValidationResult`, so a proof binds to those bytes instead. The
//! encoding is fixed-length, so the binding is as tight.

/// root (32) ++ `successful_validation` (1) ++ `chain_id` (8) ++ `schema_id` (2).
pub const ENCODED_LEN: usize = 43;

/// Committed by a guest that could not decode its input. No beacon node derives it.
pub const UNDECODABLE_SCHEMA_ID: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInput {
    /// `hash_tree_root` of the `NewPayloadRequest` the proof certifies.
    pub new_payload_request_root: [u8; 32],
    /// Only `true` is a validity signal.
    pub successful_validation: bool,
    /// Stops cross-chain replay.
    pub chain_id: u64,
    /// Stops a fork mismatch.
    pub schema_id: u16,
}

impl PublicInput {
    pub fn encode(&self) -> [u8; ENCODED_LEN] {
        let mut encoded = [0u8; ENCODED_LEN];
        encoded[..32].copy_from_slice(&self.new_payload_request_root);
        encoded[32] = u8::from(self.successful_validation);
        encoded[33..41].copy_from_slice(&self.chain_id.to_le_bytes());
        encoded[41..].copy_from_slice(&self.schema_id.to_le_bytes());
        encoded
    }

    /// Longer is allowed, because a proof system can pad the guest output to a fixed width. The
    /// padding must be zero, so nothing the guest committed goes unchecked.
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

    /// The interop contract: these bytes are what a guest commits.
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
    fn accepts_zero_padding_but_not_padding_with_content() {
        let mut padded = public_input().encode().to_vec();
        padded.extend_from_slice(&[0; 21]);
        assert!(public_input().is_committed_by(&padded));

        let last = padded.len() - 1;
        padded[last] = 1;
        assert!(!public_input().is_committed_by(&padded));
    }

    /// The comparison must cover the whole encoding. Narrowed to the root, a proof of one payload
    /// would answer for another on the same chain.
    #[test]
    fn tells_apart_inputs_that_differ_in_any_one_field() {
        let others = [
            PublicInput {
                new_payload_request_root: [0xbb; 32],
                ..public_input()
            },
            PublicInput {
                successful_validation: false,
                ..public_input()
            },
            PublicInput {
                chain_id: 1,
                ..public_input()
            },
            PublicInput {
                schema_id: 1,
                ..public_input()
            },
        ];

        for other in others {
            assert!(
                !public_input().is_committed_by(&other.encode()),
                "{other:?}"
            );
        }
    }

    #[test]
    fn rejects_truncated_commitments() {
        let encoded = public_input().encode();
        assert!(!public_input().is_committed_by(&encoded[..42]));
        assert!(!public_input().is_committed_by(&[]));
    }
}
