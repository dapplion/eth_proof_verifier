#![cfg(feature = "zisk")]
//! The fixture is a genuine ZisK VadcopFinal proof, its program's verifying key, and the public
//! values its guest committed to, from `eth-act/ere`'s `ere-verifier-zisk` test fixtures
//! (Apache-2.0 OR MIT, as here). Its guest is one of ere's own test programs rather than a
//! stateless validator, so its public values are not a validation result.

use eth_proof_verifier::backend::{ProofSystem, ProofVerifier, Rejection};
use proofman_verifier::VadcopFinalProof;

const PROGRAM_VK: &[u8] = include_bytes!("fixtures/zisk/program_vk.bin");
const PROOF: &[u8] = include_bytes!("fixtures/zisk/proof.bin");
const PUBLIC_VALUES: &[u8] = include_bytes!("fixtures/zisk/public_values.bin");

fn verifier(program_vk: &[u8]) -> Box<dyn ProofVerifier> {
    ProofSystem::Zisk
        .verifier(program_vk)
        .expect("verifying key decodes")
}

fn rejection(program_vk: &[u8], proof: &[u8]) -> Rejection {
    verifier(program_vk)
        .verify(proof)
        .expect_err("must be rejected")
}

fn unverified(rejection: Rejection) -> String {
    match rejection {
        Rejection::Unverified(reason) => reason,
        Rejection::Malformed(reason) => {
            panic!("expected a verification failure, but it never decoded: {reason}")
        }
    }
}

fn malformed(rejection: Rejection) -> String {
    match rejection {
        Rejection::Malformed(reason) => reason,
        Rejection::Unverified(reason) => {
            panic!("expected a decoding failure, but it was verified: {reason}")
        }
    }
}

/// Re-encode the fixture with `edit` applied. The round trip is byte for byte, which
/// [`round_trips_to_the_same_bytes`] holds to.
fn edited(edit: impl FnOnce(&mut VadcopFinalProof)) -> Vec<u8> {
    let (mut proof, _): (VadcopFinalProof, usize) = bincode::serde::decode_from_slice(
        PROOF,
        bincode::config::legacy().with_limit::<{ 64 * 1024 * 1024 }>(),
    )
    .expect("the fixture decodes");
    edit(&mut proof);
    bincode::serde::encode_to_vec(&proof, bincode::config::legacy()).expect("re-encodes")
}

/// Where the proof carries its program's key. The guest's own output follows it.
fn program_vk_offset() -> usize {
    PROOF
        .windows(PROGRAM_VK.len())
        .position(|window| window == PROGRAM_VK)
        .expect("the bundle carries its program key verbatim")
}

#[test]
fn verifies_a_real_proof_and_returns_its_public_values() {
    let public_values = verifier(PROGRAM_VK)
        .verify(PROOF)
        .expect("the fixture proof verifies");

    assert_eq!(public_values, PUBLIC_VALUES);
}

/// The width the padding tolerance in `PublicInput::is_committed_by` exists for: a guest's 43-byte
/// result occupies a fraction of this, and the rest must be zero.
#[test]
fn returns_a_fixed_width_zero_padded_commitment() {
    let public_values = verifier(PROGRAM_VK)
        .verify(PROOF)
        .expect("the fixture proof verifies");

    assert_eq!(public_values.len(), 256);
    assert!(public_values[45..].iter().all(|byte| *byte == 0));
}

#[test]
fn rejects_a_proof_under_another_program() {
    let mut other = PROGRAM_VK.to_vec();
    other[0] ^= 0x01;
    let reason = unverified(rejection(&other, PROOF));

    assert_eq!(reason, "proof is of another program");
}

/// The property everything else rests on: public values are committed to by the proof, not carried
/// beside it, so a valid proof of one payload cannot be relabelled as a proof of another.
#[test]
fn rejects_a_proof_whose_guest_output_was_edited() {
    let mut relabelled = PROOF.to_vec();
    relabelled[program_vk_offset() + PROGRAM_VK.len()] ^= 0x01;

    assert_eq!(
        unverified(rejection(PROGRAM_VK, &relabelled)),
        "the proof does not verify"
    );
}

#[test]
fn rejects_trailing_bytes_after_a_proof() {
    let mut padded = PROOF.to_vec();
    padded.push(0);

    assert_eq!(
        malformed(rejection(PROGRAM_VK, &padded)),
        "trailing bytes after the proof"
    );
}

/// Everything below edits a decoded proof and encodes it again, so each case rests on the round trip
/// changing nothing by itself.
#[test]
fn round_trips_to_the_same_bytes() {
    assert_eq!(edited(|_| {}), PROOF);
}

#[test]
fn rejects_a_compressed_proof() {
    let compressed = edited(|proof| proof.compressed = true);

    assert_eq!(
        malformed(rejection(PROGRAM_VK, &compressed)),
        "expected an uncompressed VadcopFinal proof"
    );
}

/// A proof of another hash family cannot authenticate against this aggregation key, so it is turned
/// away rather than handed to the verifier.
#[test]
fn rejects_another_hash_family() {
    let other_family = edited(|proof| proof.hash = "blake2".to_owned());

    assert!(
        malformed(rejection(PROGRAM_VK, &other_family)).contains("hash family"),
        "expected the hash family to be named"
    );
}

#[test]
fn rejects_the_wrong_number_of_public_values() {
    let short = edited(|proof| {
        proof.public_values.pop();
    });

    assert!(
        malformed(rejection(PROGRAM_VK, &short)).contains("public values"),
        "expected the count to be named"
    );
}

/// Without the flag, the words after it need not be a program key and a guest output at all.
#[test]
fn rejects_a_proof_that_is_not_vadcop_final() {
    let unflagged = edited(|proof| proof.public_values[0] = 0);

    assert_eq!(
        malformed(rejection(PROGRAM_VK, &unflagged)),
        "not a VadcopFinal proof"
    );
}
