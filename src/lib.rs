//! Verifies EIP-8025 execution proofs against a named guest program and a given public input.

pub mod api;
pub mod backend;
pub mod hex_bytes;
pub mod public_input;
pub mod registry;

/// EIP-8025 `MAX_PROOF_SIZE`, inclusive.
pub const MAX_PROOF_SIZE: usize = 4_194_304;
