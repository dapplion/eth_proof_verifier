//! The proof types this binary can verify, and the verifier bound to each one.
//!
//! Defaults are compiled in, so the binary verifies with no configuration at all. A verifying key
//! is 32 bytes, so adding a proof type is pasting hex into a `--config` file rather than
//! provisioning anything.

use std::{collections::BTreeMap, fmt::Display, path::Path};

use serde::{Deserialize, Serialize};

use crate::backend::{ProofSystem, ProofVerifier};

/// Length of a verifying key, for every proof system this binary supports.
pub const PROGRAM_VK_LEN: usize = 32;

/// The proof types served when no configuration is given.
const DEFAULT_PROOF_TYPES: &str = include_str!("../default_proof_types.toml");

/// One proof type: an immutable (proof system, guest program, version) triple, and the verifying
/// key of the compiled program it names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTypeSpec {
    pub proof_type: u8,
    pub proof_system: ProofSystem,
    pub proof_system_version: String,
    pub guest: String,
    pub guest_version: String,
    /// Hex, without a `0x` prefix.
    pub program_vk: String,
}

#[derive(Debug, Deserialize)]
struct ProofTypesFile {
    #[serde(default)]
    proof_types: Vec<ProofTypeSpec>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("proof type {proof_type} has a verifying key that is not hex: {source}")]
    ProgramVkNotHex {
        proof_type: u8,
        source: hex::FromHexError,
    },
    #[error("proof type {proof_type} ({proof_system}) has an unusable verifying key: {source}")]
    ProgramVk {
        proof_type: u8,
        proof_system: ProofSystem,
        source: crate::backend::InvalidProgramVk,
    },
    #[error("proof type 0 is not assignable")]
    ReservedProofType,
}

struct Entry {
    spec: ProofTypeSpec,
    verifier: Box<dyn ProofVerifier>,
}

/// Every proof type this process serves.
pub struct Registry {
    entries: BTreeMap<u8, Entry>,
}

impl Registry {
    /// Load the compiled-in defaults, with `config` overriding or extending them by proof type.
    pub fn load(config: Option<&Path>) -> Result<Self, LoadError> {
        let mut specs = parse(DEFAULT_PROOF_TYPES, "the compiled-in defaults")?;

        if let Some(path) = config {
            let display = path.display().to_string();
            let contents = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
                path: display.clone(),
                source,
            })?;
            for (proof_type, spec) in parse(&contents, &display)? {
                specs.insert(proof_type, spec);
            }
        }

        let mut entries = BTreeMap::new();
        for (proof_type, spec) in specs {
            // `ProofType` 0 is outside the assignable range, so an entry for it is a mistake worth
            // reporting rather than something to serve.
            if proof_type == 0 {
                return Err(LoadError::ReservedProofType);
            }
            let program_vk = hex::decode(spec.program_vk.trim_start_matches("0x"))
                .map_err(|source| LoadError::ProgramVkNotHex { proof_type, source })?;
            let verifier =
                spec.proof_system
                    .verifier(&program_vk)
                    .map_err(|source| LoadError::ProgramVk {
                        proof_type,
                        proof_system: spec.proof_system,
                        source,
                    })?;
            entries.insert(proof_type, Entry { spec, verifier });
        }

        Ok(Self { entries })
    }

    /// The verifier for `proof_type`, or `None` if this process does not serve it.
    pub fn verifier(&self, proof_type: u8) -> Option<&dyn ProofVerifier> {
        self.entries
            .get(&proof_type)
            .map(|entry| entry.verifier.as_ref())
    }

    /// The proof types served, which a beacon node needs for its ENR `eproof` field and its
    /// `ExecutionProofStatus` handshake.
    pub fn supported(&self) -> Vec<u8> {
        self.entries.keys().copied().collect()
    }

    pub fn specs(&self) -> Vec<&ProofTypeSpec> {
        self.entries.values().map(|entry| &entry.spec).collect()
    }
}

fn parse(contents: &str, source_name: &str) -> Result<BTreeMap<u8, ProofTypeSpec>, LoadError> {
    let file: ProofTypesFile = toml::from_str(contents).map_err(|source| LoadError::Parse {
        path: source_name.to_owned(),
        source,
    })?;
    Ok(file
        .proof_types
        .into_iter()
        .map(|spec| (spec.proof_type, spec))
        .collect())
}

impl Display for ProofTypeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} = {} {} on {} {}",
            self.proof_type,
            self.guest,
            self.guest_version,
            self.proof_system,
            self.proof_system_version
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compiled-in defaults have to parse and every verifying key in them has to build a
    /// verifier, or a binary with no configuration is dead on arrival.
    #[test]
    fn default_proof_types_load() {
        let registry = Registry::load(None).expect("defaults load");
        assert!(!registry.supported().is_empty());
        for proof_type in registry.supported() {
            assert!(registry.verifier(proof_type).is_some());
        }
    }

    #[test]
    fn unserved_proof_type_has_no_verifier() {
        let registry = Registry::load(None).expect("defaults load");
        assert!(registry.verifier(u8::MAX).is_none());
    }

    #[test]
    fn every_default_program_vk_is_the_expected_length() {
        for spec in parse(DEFAULT_PROOF_TYPES, "defaults")
            .expect("defaults parse")
            .values()
        {
            let vk = hex::decode(&spec.program_vk).expect("vk is hex");
            assert_eq!(vk.len(), PROGRAM_VK_LEN, "proof type {}", spec.proof_type);
        }
    }
}
