//! Loading is unforgiving: a verifier serving something other than what its operator wrote answers
//! `INVALID` for everything, which looks like a network with no provers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    path::Path,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    backend::{ProofSystem, ProofVerifier},
    hex_bytes,
};

/// Verifying key length, for every proof system here.
pub const PROGRAM_VK_LEN: usize = 32;

const DEFAULT_PROOF_TYPES: &str = include_str!("../default_proof_types.toml");

/// An immutable (proof system, guest, version) triple, and the key of the program it names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofTypeSpec {
    pub proof_type: u8,
    pub proof_system: ProofSystem,
    /// The `proof_system` version the guest was proved with, not the verifier's own.
    pub proof_system_version: String,
    pub guest: String,
    pub guest_version: String,
    /// Hex, with an optional `0x` prefix.
    pub program_vk: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofTypesFile {
    /// Required, so a mistyped table header is an error and not an empty file.
    proof_types: Vec<ProofTypeSpec>,
}

/// Lighthouse's `--proof-engine` file: `beacon_node/proof_engine/src/config.rs` on
/// `eth-act/lighthouse`. The zkVM is not written down, it is named by the proof type.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofEngineFile {
    execution_proofs: Vec<ExecutionProofEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionProofEntry {
    proof_type: u8,
    program_vk: String,
}

struct AssignedProofType {
    proof_type: u8,
    guest: &'static str,
    guest_version: &'static str,
    /// `None` for a zkVM with no backend here.
    proof_system: Option<ProofSystem>,
    proof_system_version: &'static str,
}

/// `ProofType` on `eth-act/lighthouse`, with the guest versions its `config.rs` records.
const ASSIGNED_PROOF_TYPES: [AssignedProofType; 7] = [
    AssignedProofType {
        proof_type: 1,
        guest: "ethrex",
        guest_version: "26.0.0",
        proof_system: None,
        proof_system_version: "",
    },
    AssignedProofType {
        proof_type: 2,
        guest: "ethrex",
        guest_version: "26.0.0",
        proof_system: Some(ProofSystem::Sp1),
        proof_system_version: "6.4.0",
    },
    AssignedProofType {
        proof_type: 3,
        guest: "ethrex",
        guest_version: "26.0.0",
        proof_system: Some(ProofSystem::Zisk),
        proof_system_version: "1.2.0-alpha",
    },
    AssignedProofType {
        proof_type: 4,
        guest: "reth",
        guest_version: "0.1.0-rc.3",
        proof_system: None,
        proof_system_version: "",
    },
    AssignedProofType {
        proof_type: 5,
        guest: "reth",
        guest_version: "0.1.0-rc.3",
        proof_system: Some(ProofSystem::Sp1),
        proof_system_version: "6.4.0",
    },
    AssignedProofType {
        proof_type: 6,
        guest: "reth",
        guest_version: "0.1.0-rc.3",
        proof_system: Some(ProofSystem::Zisk),
        proof_system_version: "1.2.0-alpha",
    },
    AssignedProofType {
        proof_type: 7,
        guest: "zesu",
        guest_version: "8.1.4",
        proof_system: Some(ProofSystem::Zisk),
        proof_system_version: "1.2.0-alpha",
    },
];

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
    #[error("cannot parse {path}: {source}")]
    ParseJson {
        path: String,
        source: serde_json::Error,
    },
    #[error("{path} names proof type {proof_type}, which EIP-8025 does not assign")]
    UnassignedProofType { path: String, proof_type: u8 },
    #[error("{path} gives proof type {proof_type} twice")]
    DuplicateProofType { path: String, proof_type: u8 },
    #[error(
        "proof type {proof_type} has a verifying key that is not {PROGRAM_VK_LEN} bytes of hex: {source}"
    )]
    ProgramVkNotHex {
        proof_type: u8,
        source: hex_bytes::Error,
    },
    #[error("proof type {proof_type} has an all-zero verifying key, which names no program")]
    PlaceholderProgramVk { proof_type: u8 },
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
    verifier: Arc<dyn ProofVerifier>,
}

pub struct Registry {
    entries: BTreeMap<u8, Entry>,
}

impl Registry {
    /// Load the defaults, with `config` replacing or adding entries by proof type.
    pub fn load(config: Option<&Path>) -> Result<Self, LoadError> {
        let mut specs: BTreeMap<u8, ProofTypeSpec> =
            parse(DEFAULT_PROOF_TYPES, "the compiled-in defaults")?
                .into_iter()
                .map(|spec| (spec.proof_type, spec))
                .collect();

        if let Some(path) = config {
            let display = path.display().to_string();
            let contents = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
                path: display.clone(),
                source,
            })?;
            let from_file = parse(&contents, &display)?;

            // Otherwise one of the two goes unserved and the operator cannot see which.
            let mut seen = BTreeSet::new();
            for spec in &from_file {
                if !seen.insert(spec.proof_type) {
                    return Err(LoadError::DuplicateProofType {
                        path: display.clone(),
                        proof_type: spec.proof_type,
                    });
                }
            }

            for spec in from_file {
                let proof_type = spec.proof_type;
                if specs.insert(proof_type, spec).is_some() {
                    // Legitimate, but a wrong key here rejects every proof of a type the network
                    // does gossip.
                    warn!("Proof type {proof_type} replaces the compiled-in default");
                }
            }
        }

        Self::build(specs)
    }

    /// Load a Lighthouse `--proof-engine` file, which replaces the compiled-in proof types: it
    /// numbers them differently, so the two cannot be merged.
    pub fn load_proof_engine(path: &Path) -> Result<Self, LoadError> {
        let display = path.display().to_string();
        let contents = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: display.clone(),
            source,
        })?;
        let file: ProofEngineFile =
            serde_json::from_str(&contents).map_err(|source| LoadError::ParseJson {
                path: display.clone(),
                source,
            })?;

        let mut specs = BTreeMap::new();
        for entry in file.execution_proofs {
            let proof_type = entry.proof_type;
            let Some(assigned) = ASSIGNED_PROOF_TYPES
                .iter()
                .find(|assigned| assigned.proof_type == proof_type)
            else {
                return Err(LoadError::UnassignedProofType {
                    path: display,
                    proof_type,
                });
            };
            let Some(proof_system) = assigned.proof_system else {
                warn!(
                    "Proof type {proof_type} ({}) is not served: no OpenVM backend",
                    assigned.guest
                );
                continue;
            };
            let spec = ProofTypeSpec {
                proof_type,
                proof_system,
                proof_system_version: assigned.proof_system_version.to_owned(),
                guest: assigned.guest.to_owned(),
                guest_version: assigned.guest_version.to_owned(),
                program_vk: entry.program_vk,
            };
            if specs.insert(proof_type, spec).is_some() {
                return Err(LoadError::DuplicateProofType {
                    path: display,
                    proof_type,
                });
            }
        }
        Self::build(specs)
    }

    fn build(specs: BTreeMap<u8, ProofTypeSpec>) -> Result<Self, LoadError> {
        let mut entries = BTreeMap::new();
        for (proof_type, spec) in specs {
            if proof_type == 0 {
                return Err(LoadError::ReservedProofType);
            }

            let program_vk = hex_bytes::decode::<PROGRAM_VK_LEN>(&spec.program_vk)
                .map_err(|source| LoadError::ProgramVkNotHex { proof_type, source })?;
            if program_vk == [0; PROGRAM_VK_LEN] {
                return Err(LoadError::PlaceholderProgramVk { proof_type });
            }
            let verifier =
                spec.proof_system
                    .verifier(&program_vk)
                    .map_err(|source| LoadError::ProgramVk {
                        proof_type,
                        proof_system: spec.proof_system,
                        source,
                    })?;
            entries.insert(
                proof_type,
                Entry {
                    spec,
                    verifier: Arc::from(verifier),
                },
            );
        }

        Ok(Self { entries })
    }

    /// Shared, not borrowed: verifying runs off the async runtime and outlives the handler.
    pub fn verifier(&self, proof_type: u8) -> Option<Arc<dyn ProofVerifier>> {
        self.entries
            .get(&proof_type)
            .map(|entry| entry.verifier.clone())
    }

    /// For a beacon node's ENR `eproof` field and its `ExecutionProofStatus` handshake.
    pub fn supported(&self) -> Vec<u8> {
        self.entries.keys().copied().collect()
    }

    pub fn specs(&self) -> Vec<&ProofTypeSpec> {
        self.entries.values().map(|entry| &entry.spec).collect()
    }

    #[cfg(test)]
    pub(crate) fn from_entries(entries: Vec<(ProofTypeSpec, Arc<dyn ProofVerifier>)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(spec, verifier)| (spec.proof_type, Entry { spec, verifier }))
                .collect(),
        }
    }
}

fn parse(contents: &str, source_name: &str) -> Result<Vec<ProofTypeSpec>, LoadError> {
    let file: ProofTypesFile = toml::from_str(contents).map_err(|source| LoadError::Parse {
        path: source_name.to_owned(),
        source,
    })?;
    Ok(file.proof_types)
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

    const FIXTURE_VK: &str = "002d67597a7afdbb45a24a311ea77a6b07ccdebab8b92db5a95fe8371beed380";

    fn load_from(contents: &str) -> Result<Registry, LoadError> {
        let path = std::env::temp_dir().join(format!(
            "eth_proof_verifier-{}-{:?}.toml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, contents).expect("config is writable");
        let loaded = Registry::load(Some(&path));
        let _ = std::fs::remove_file(&path);
        loaded
    }

    fn entry(proof_type: u8, program_vk: &str) -> String {
        format!(
            "[[proof_types]]\n\
             proof_type = {proof_type}\n\
             proof_system = \"sp1\"\n\
             proof_system_version = \"6.4.0\"\n\
             guest = \"guest\"\n\
             guest_version = \"1\"\n\
             program_vk = \"{program_vk}\"\n"
        )
    }

    const RETH_SP1_VK: &str = "00a03cbfa95559cfee3b45ef925f3f7a631181e35e774e92b040277d893511dd";

    fn load_proof_engine_from(contents: &str) -> Result<Registry, LoadError> {
        let path = std::env::temp_dir().join(format!(
            "eth_proof_verifier-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, contents).expect("config is writable");
        let loaded = Registry::load_proof_engine(&path);
        let _ = std::fs::remove_file(&path);
        loaded
    }

    /// Lighthouse numbers reth SP1 as 5, and the defaults here as 1; the file wins outright.
    #[test]
    fn a_proof_engine_file_replaces_the_defaults_and_skips_openvm() {
        let json = format!(
            r#"{{"execution_proofs":[{{"proof_type":4,"program_vk":"0x0025e8d04400"}},{{"proof_type":5,"program_vk":"0x{RETH_SP1_VK}"}}]}}"#
        );
        let registry = load_proof_engine_from(&json).expect("loads");
        assert_eq!(registry.supported(), vec![5]);
        assert_eq!(registry.specs()[0].guest, "reth");
    }

    #[test]
    fn a_proof_engine_file_rejects_an_unassigned_proof_type() {
        let json = format!(
            r#"{{"execution_proofs":[{{"proof_type":8,"program_vk":"0x{RETH_SP1_VK}"}}]}}"#
        );
        assert!(load_proof_engine_from(&json).is_err());
    }

    /// Without this, a binary with no configuration is dead on arrival.
    #[test]
    fn default_proof_types_load() {
        let registry = Registry::load(None).expect("defaults load");
        assert_eq!(registry.supported(), vec![1, 2]);
        for proof_type in registry.supported() {
            assert!(registry.verifier(proof_type).is_some());
        }
    }

    #[test]
    fn serves_an_added_proof_type() {
        let registry = load_from(&entry(3, FIXTURE_VK)).expect("loads");
        assert_eq!(registry.supported(), vec![1, 2, 3]);
    }

    /// This used to parse as an empty file, and the operator's proof type was silently absent.
    #[test]
    fn rejects_a_mistyped_table_header() {
        let singular = entry(3, FIXTURE_VK).replace("[[proof_types]]", "[[proof_type]]");
        assert!(load_from(&singular).is_err());
        assert!(load_from("").is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let extra = format!("{}proof_sytsem = \"sp1\"\n", entry(3, FIXTURE_VK));
        assert!(load_from(&extra).is_err());
    }

    /// This used to keep the last entry silently.
    #[test]
    fn rejects_a_duplicated_proof_type() {
        let twice = format!("{}{}", entry(3, FIXTURE_VK), entry(3, FIXTURE_VK));
        assert!(load_from(&twice).is_err());
    }

    /// A half-filled file must not produce a verifier that rejects everything.
    #[test]
    fn rejects_a_placeholder_verifying_key() {
        assert!(load_from(&entry(3, &"0".repeat(64))).is_err());
    }

    #[test]
    fn rejects_proof_type_zero() {
        assert!(load_from(&entry(0, FIXTURE_VK)).is_err());
    }
}
