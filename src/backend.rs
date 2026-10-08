//! A proof system turns proof bytes into the bytes the guest committed to. Whether those are the
//! right public input is decided in [`crate::public_input`].

pub mod sp1;

use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// A verifier bound to one compiled guest program.
pub trait ProofVerifier: Send + Sync + 'static {
    fn verify(&self, proof: &[u8]) -> Result<Vec<u8>, Rejection>;
}

/// Both answer `INVALID`, but only `Unverified` says anything about a payload.
#[derive(Debug, thiserror::Error)]
pub enum Rejection {
    /// Not a proof of the shape this proof system expects.
    #[error("{0}")]
    Malformed(String),
    /// Well formed, and does not verify.
    #[error("{0}")]
    Unverified(String),
}

impl Rejection {
    pub fn malformed(reason: impl Display) -> Self {
        Self::Malformed(reason.to_string())
    }

    pub fn unverified(reason: impl Display) -> Self {
        Self::Unverified(reason.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidProgramVk(String);

impl InvalidProgramVk {
    fn new(reason: impl Display) -> Self {
        Self(reason.to_string())
    }
}

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

    /// Called once per proof type at startup. SP1 builds its recursion verifier here, not per
    /// request.
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
