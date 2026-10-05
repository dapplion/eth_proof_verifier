//! A standalone verifier for EIP-8025 execution proofs.
//!
//! A beacon node hands over a proof type, the public input it derived from its own state, and the
//! proof bytes. This crate answers whether the proof verifies against the guest program that proof
//! type names, and commits to that public input.

pub mod api;
pub mod backend;
pub mod public_input;
pub mod registry;
