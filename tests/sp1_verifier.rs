//! The fixture is a genuine SP1 compressed proof, its program's verifying key, and the public values
//! its guest committed to, from `eth-act/ere`'s `ere-verifier-sp1` test fixtures (Apache-2.0 OR MIT,
//! as here). Its guest is one of ere's own test programs rather than a stateless validator, so its
//! public values are not a validation result.
//!
//! Rejections are asserted by kind: a test that only asks for an error passes just as happily when
//! the proof never reached the verifier at all.

use eth_proof_verifier::backend::{ProofSystem, ProofVerifier, Rejection};

const PROGRAM_VK: &[u8] = include_bytes!("fixtures/program_vk.bin");
const PROOF: &[u8] = include_bytes!("fixtures/proof.bin");
const PUBLIC_VALUES: &[u8] = include_bytes!("fixtures/public_values.bin");

/// A verifying key of a different program, to check a proof is bound to its own.
const OTHER_PROGRAM_VK: &str = "00a03cbfa95559cfee3b45ef925f3f7a631181e35e774e92b040277d893511dd";

fn verifier(program_vk: &[u8]) -> Box<dyn ProofVerifier> {
    ProofSystem::Sp1
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

#[test]
fn verifies_a_real_proof_and_returns_its_public_values() {
    let public_values = verifier(PROGRAM_VK)
        .verify(PROOF)
        .expect("the fixture proof verifies");

    assert_eq!(public_values, PUBLIC_VALUES);
}

#[test]
fn rejects_a_proof_under_another_program() {
    let other = hex::decode(OTHER_PROGRAM_VK).expect("hex");
    let reason = unverified(rejection(&other, PROOF));

    assert!(reason.contains("vk hash mismatch"), "{reason}");
}

/// The property everything else rests on: public values are committed to by the proof, not carried
/// beside it, so a valid proof of one payload cannot be relabelled as a proof of another.
#[test]
fn rejects_a_proof_whose_public_values_were_edited() {
    let mut relabelled = PROOF.to_vec();
    let at = relabelled
        .windows(PUBLIC_VALUES.len())
        .position(|window| window == PUBLIC_VALUES)
        .expect("the bundle carries its public values verbatim");
    relabelled[at] ^= 0x01;

    let reason = unverified(rejection(PROGRAM_VK, &relabelled));
    assert!(
        reason.contains("public values do not match the commitment"),
        "{reason}"
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

/// A length prefix inside network bytes must not decide how much the decoder allocates. These bytes
/// declare ~2.1e17: representable, so unbounded it reaches the allocator, and an allocation failure
/// aborts rather than panics, which no caller can catch.
#[test]
fn rejects_a_declared_length_beyond_the_input() {
    let mut input = 3u32.to_le_bytes().to_vec();
    input.extend_from_slice(&211_946_530_762_463_256u64.to_le_bytes());

    assert_eq!(malformed(rejection(PROGRAM_VK, &input)), "LimitExceeded");
}
