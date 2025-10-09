use std::sync::Arc;

use rand::RngCore;

use crate::{
    codecs::unit::Pattern as UnitPattern,
    duplex_sponge::legacy::DigestBridge,
    keccak::Keccak,
    pattern::{Kind, Label, Length, Pattern, PatternState},
    traits::{BytesToUnitSerialize, UnitToBytes},
    DuplexSpongeInterface, ProverState, UnitTranscript, VerifierState,
};

type Sha2 = DigestBridge<sha2::Sha256>;
type Blake2b512 = DigestBridge<blake2::Blake2b512>;
type Blake2s256 = DigestBridge<blake2::Blake2s256>;

/// Test ProverState's rng is not doing completely stupid things.
#[test]
fn test_prover_rng_basic() {
    let pattern = PatternState::<u8>::new().finalize();
    let mut prover_state: ProverState<Keccak> = ProverState::from(&pattern);
    let rng = prover_state.rng();

    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let random_u32 = rng.next_u32();
    let random_u64 = rng.next_u64();
    assert_ne!(random_bytes, [0u8; 32]);
    assert_ne!(random_u32, 0);
    assert_ne!(random_u64, 0);
    assert!(random_bytes.iter().any(|&x| x != random_bytes[0]));
    let _proof = prover_state.finalize();
}

/// Test adding of public bytes and non-public elements to the transcript.
#[test]
fn test_prover_bytewriter_correct() {
    // Expect exactly one add_bytes call.
    let mut pattern = PatternState::<u8>::new();
    pattern.begin_message::<u8>(Label::custom("bytes"), Length::Fixed(1)).expect("Failed to begin message");
    pattern.message_units(Label::custom("units"), 1);
    pattern.end_message::<u8>(Label::custom("bytes"), Length::Fixed(1)).expect("Failed to end message");
    let pattern = pattern.finalize();

    let mut prover_state: ProverState<Keccak> = ProverState::from(&pattern);
    prover_state.add_bytes(Label::BYTES, &[0u8]);
    let proof = prover_state.finalize().unwrap();
    assert_eq!(hex::encode(proof), "00");
}

#[test]
#[should_panic(
    expected = "UnexpectedInteraction"
)]
fn test_prover_bytewriter_invalid() {
    // Expect exactly one add_bytes call.
    let mut pattern = PatternState::<u8>::new();
    pattern.begin_message::<u8>(Label::custom("bytes"), Length::Fixed(1)).expect("Failed to begin message");
    pattern.message_units(Label::custom("units"), 1).expect("Failed to add message units");
    pattern.end_message::<u8>(Label::custom("bytes"), Length::Fixed(1)).expect("Failed to end message");
    let pattern = pattern.finalize();

    let mut prover_state: ProverState<Keccak> = ProverState::from(&pattern);
    prover_state.add_bytes(Label::BYTES, &[0u8]).expect("First add_bytes should succeed");
    prover_state.add_bytes(Label::BYTES, &[1u8]).expect("Second add_bytes should fail");
}

#[test]
#[should_panic(
    expected = "UnexpectedInteraction"
)]
fn test_prover_public_units_invalid() {
    // Expect exactly one public_units call.
    let mut pattern = PatternState::<u8>::new();
    pattern.public_units(Label::custom("public_units"), 1).expect("Failed to add public units to pattern");
    let pattern = pattern.finalize();

    let mut prover_state: ProverState<Keccak> = ProverState::from(&pattern);
    prover_state.public_units(Label::custom("public_units"), &[0u8]).expect("First public_units should succeed");
    prover_state.public_units(Label::custom("public_units"), &[1u8]).expect("Second public_units should fail");
}

/// A protocol flow whose pattern does not match should panic.
#[test]
#[should_panic(
    expected = "Received interaction Atomic Challenge fill_challenge_units Fixed(16) u8, but expected Atomic Message units Fixed(3) u8"
)]
fn test_invalid_domsep_sequence() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_units(Label::custom("units"), 3);
    pattern.challenge_units(Label::custom("challenge_units"), 1);
    let pattern = pattern.finalize();

    let mut verifier_state: VerifierState<Keccak> = VerifierState::new(Arc::new(pattern), &[]);
    // This should panic due to pattern mismatch.
    verifier_state.fill_challenge_bytes(Label::custom("fill_challenge_units"), &mut [0u8; 16]);
}

/// A protocol whose domain separator is not finished should panic.
#[test]
#[should_panic(expected = "Dropped unfinalized transcript.")]
fn test_unfinished_domsep() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_units(Label::custom("elt"), 3);
    pattern.challenge_units(Label::custom("another_elt"), 16);
    let pattern = pattern.finalize();

    let mut _verifier: VerifierState = VerifierState::new(pattern.into(), b"");
}

/// The domain separator tag should be deterministic.
#[test]
fn test_deterministic() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_units(Label::custom("elt"), 3);
    pattern.challenge_units(Label::custom("another_elt"), 16);
    let pattern = pattern.finalize();

    let iv1 = pattern.domain_separator();
    let iv2 = pattern.domain_separator();
    assert_eq!(iv1, iv2);
}

/// Basic check that the domain separator tag has some non-zero byte.
#[test]
fn test_statistics() {
    let pattern = PatternState::<u8>::new().finalize();
    let iv = pattern.domain_separator();
    assert!(iv.iter().any(|&b| b != 0));
}

#[test]
fn test_transcript_readwrite() {
    // Pattern for prover and verifier sequence: add_units, fill_challenge_units, two fill_next_units, then fill_challenge_units
    let mut pattern = PatternState::<u8>::new();
    pattern.message_units(Label::custom("units"), 10);
    pattern.challenge_units(Label::custom("fill_challenge_units"), 10);
    pattern.message_units(Label::custom("units"), 5);
    pattern.message_units(Label::custom("units"), 5);
    pattern.challenge_units(Label::custom("fill_challenge_units"), 10);
    let pattern = pattern.finalize();

    let mut prover_state: ProverState = ProverState::from(&pattern);
    prover_state.add_units(Label::UNITS, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(
        hex::encode(prover_state.challenge_bytes::<10>(Label::custom("fill_challenge_units")).unwrap()),
        "0ccd176155e008b158ad"
    );
    prover_state.add_units(Label::UNITS, &[10, 11, 12, 13, 14]);
    prover_state.add_units(Label::UNITS, &[15, 16, 17, 18, 19]);
    assert_eq!(
        hex::encode(prover_state.challenge_bytes::<10>(Label::custom("fill_challenge_units")).unwrap()),
        "0f691da125269385ceea"
    );
    let proof = prover_state.finalize().unwrap();
    assert_eq!(
        hex::encode(&proof),
        "000102030405060708090a0b0c0d0e0f10111213"
    );

    let mut verifier_state: VerifierState = VerifierState::new(Arc::new(pattern), &proof);
    let mut input = [0u8; 10];
    verifier_state.fill_next_units(Label::custom("units"), &mut input).unwrap();
    assert_eq!(input, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(
        hex::encode(verifier_state.challenge_bytes::<10>(Label::custom("fill_challenge_units")).unwrap()),
        "0ccd176155e008b158ad"
    );
    let mut input = [0u8; 5];
    verifier_state.fill_next_units(Label::custom("units"), &mut input).unwrap();
    assert_eq!(input, [10, 11, 12, 13, 14]);
    verifier_state.fill_next_units(Label::custom("units"), &mut input).unwrap();
    assert_eq!(input, [15, 16, 17, 18, 19]);
    assert_eq!(
        hex::encode(verifier_state.challenge_bytes::<10>(Label::custom("fill_challenge_units")).unwrap()),
        "0f691da125269385ceea"
    );
    verifier_state.finalize();
}

/// An IO that is not fully finished should fail.
/// An IO that is not fully finished should panic.
#[test]
#[should_panic]
fn test_incomplete_domsep() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_units(Label::custom("units"), 10);
    pattern.challenge_units(Label::custom("fill_challenge_units"), 1);
    let pattern = pattern.finalize();

    let mut prover_state: ProverState<Keccak> = ProverState::from(&pattern);
    prover_state.add_units(Label::UNITS, &[0u8; 10]);
    // This should panic due to pattern mismatch length
    prover_state.fill_challenge_bytes(Label::custom("fill_challenge_units"), &mut [0u8; 10]);
}

/// The user should respect the domain separator even with empty length.
/// The user should respect the pattern even with empty operations.
#[test]
fn test_prover_empty_absorb() {
    // Pattern expects one add_units and one challenge
    let mut pattern = PatternState::<u8>::new();
    pattern.message_units(Label::custom("units"), 0).expect("Failed to add message units");
    pattern.challenge_units(Label::custom("fill_challenge_units"), 0).expect("Failed to add challenge units");
    let pattern = pattern.finalize();

    let mut prover_state: ProverState = ProverState::from(&pattern);
    prover_state.add_units(Label::UNITS, b"").expect("Failed to add units");
    let mut challenge = [0u8; 0];
    prover_state.fill_challenge_units(Label::custom("fill_challenge_units"), &mut challenge).expect("Failed to get challenge");
    let proof = prover_state.finalize().expect("Failed to finalize");
    assert!(proof.is_empty());

    let mut vstate: VerifierState<Keccak> = VerifierState::new(Arc::new(pattern), &proof);
    // For 0-length units, we don't read from the proof, but we still need to consume the interaction
    // The verifier state constructor handles this automatically based on the pattern
    let mut vchallenge = [0u8; 0];
    vstate.fill_next_units(Label::custom("units"), &mut vchallenge).expect("Failed to get challenge");
    vstate.fill_challenge_units(Label::custom("fill_challenge_units"), &mut vchallenge).expect("Failed to get challenge");
    vstate.finalize().expect("Failed to finalize");
}

/// Absorbs and squeeze over byte-Units
fn test_absorb_and_squeeze<H: DuplexSpongeInterface>()
where
    ProverState<H>: BytesToUnitSerialize + UnitToBytes,
{
    let bytes = b"yellow submarine";

    let mut pattern = PatternState::<u8>::new();
    pattern.begin_message::<u8>(Label::custom("bytes"), Length::Fixed(16)).expect("Failed to begin message");
    pattern.message_units(Label::custom("units"), 16);
    pattern.end_message::<u8>(Label::custom("bytes"), Length::Fixed(16)).expect("Failed to end message");
    pattern.challenge_units(Label::custom("fill_challenge_units"), 16);
    let pattern = pattern.finalize();

    let mut prover_state: ProverState<H> = ProverState::from(&pattern);
    prover_state.add_bytes(Label::custom("bytes"), bytes);
    let _challenge = prover_state.challenge_bytes::<16>(Label::custom("fill_challenge_units"));
    let _proof = prover_state.finalize();
}

#[test]
fn test_sha2() {
    test_absorb_and_squeeze::<Sha2>();
}

#[test]
fn test_blake2() {
    test_absorb_and_squeeze::<Blake2b512>();
    test_absorb_and_squeeze::<Blake2s256>();
}

#[test]
fn test_keccak() {
    test_absorb_and_squeeze::<Keccak>();
}
