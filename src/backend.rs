//! Proof systems this binary can verify against.
//!
//! A proof system contributes one thing: given a program's verifying key and some proof bytes,
//! either reject them or hand back the bytes the guest committed to. Deciding whether those bytes
//! are the public input the beacon node asked about is not the proof system's business, and lives
//! in [`crate::public_input`].

pub mod sp1;

use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// A verifier bound to one compiled guest program.
pub trait ProofVerifier: Send + Sync + 'static {
    /// Verify `proof` and return the bytes the guest committed to.
    fn verify(&self, proof: &[u8]) -> Result<Vec<u8>, Rejection>;
}

/// Why a proof was not accepted. Every rejection is an answer of `INVALID`, and the message is
/// reported so an operator can tell a corrupt encoding from a proof that simply does not verify.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Rejection(String);

impl Rejection {
    pub fn new(reason: impl Display) -> Self {
        Self(reason.to_string())
    }
}

/// A verifying key that does not belong to its proof system.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidProgramVk(String);

impl InvalidProgramVk {
    fn new(reason: impl Display) -> Self {
        Self(reason.to_string())
    }
}

/// The proof systems this binary was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofSystem {
    Sp1,
}

impl ProofSystem {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sp1 => "sp1",
        }
    }

    /// Build a verifier bound to the program `program_vk` identifies.
    ///
    /// Done once per proof type at startup, because a proof system may have expensive one-time
    /// setup: SP1 builds its recursion verifier here rather than on the first request.
    pub fn verifier(self, program_vk: &[u8]) -> Result<Box<dyn ProofVerifier>, InvalidProgramVk> {
        match self {
            Self::Sp1 => Ok(Box::new(sp1::Sp1Verifier::new(program_vk)?)),
        }
    }
}

impl Display for ProofSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
