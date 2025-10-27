use rand::RngCore;

use crate::{
    codecs::{bytes::Pattern as BytesPattern, unit::Pattern as UnitPattern},
    keccak::Keccak,
    pattern::{Label, Length, Pattern, PatternState},
    traits::ByteTranscript,
    ProverState, VerifierState,
};

// type Sha2 = DigestBridge<sha2::Sha256>;
// type Blake2b512 = DigestBridge<blake2::Blake2b512>;
// type Blake2s256 = DigestBridge<blake2::Blake2s256>;

#[test]
fn test_prover_rng_basic() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Bytes, 1);
    let pattern = pattern.finalize();

    let mut prover_state = ProverState::<Keccak>::new(pattern, rand::rngs::OsRng);
    let rng = prover_state.rng();

    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let random_u32 = rng.next_u32();
    let random_u64 = rng.next_u64();

    assert_ne!(random_bytes, [0u8; 32]);
    assert_ne!(random_u32, 0);
    assert_ne!(random_u64, 0);
    assert!(random_bytes.iter().any(|&x| x != random_bytes[0]));

    prover_state.abort();
}

#[test]
fn test_prover_state_bytewriter() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Bytes, 1);
    let pattern = pattern.finalize();

    let mut prover_state = ProverState::<Keccak>::new(pattern.clone(), rand::rngs::OsRng);
    prover_state.message_units(Label::Bytes, &[0u8]);
    let proof = prover_state.finalize();
    assert_eq!(proof.len(), 1, "First message should succeed");

    // Test public bytes (not in transcript)
    let mut pattern = PatternState::new();
    pattern.message_public_units(Label::Public, 1);
    let pattern = pattern.finalize();

    let mut prover_state = ProverState::<Keccak>::new(pattern, rand::rngs::OsRng);
    prover_state.message_public_units(Label::Public, &[0u8]);
    assert_eq!(prover_state.narg_string(), b"" as &[u8]);
    prover_state.finalize();
}

#[test]
#[should_panic(expected = "Unexpected interaction")]
fn test_invalid_pattern_sequence() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Bytes, 3);
    pattern.challenge_units(Label::custom("chal"), 1);
    let pattern = pattern.finalize();

    let mut verifier_state = VerifierState::<Keccak>::new(pattern.clone(), b"abc");
    // Try to squeeze before absorbing all messages - this should panic
    let mut out = [0u8; 1];
    verifier_state.challenge_units(Label::custom("chal"), &mut out);
}

#[test]
fn test_deterministic() {
    let mut pattern = PatternState::new();
    pattern.message_bytes(Label::Bytes, 3);
    pattern.challenge_bytes(Label::custom("chal"), 16);
    let pattern = pattern.finalize();

    let mut first_verifier = VerifierState::<Keccak>::new(pattern.clone(), b"123");
    let mut second_verifier = VerifierState::<Keccak>::new(pattern.clone(), b"123");

    let mut first = [0u8; 3];
    let mut second = [0u8; 3];

    // Read through the begin/end structure
    first_verifier.begin::<u8>(
        Label::Bytes,
        crate::pattern::Kind::Message,
        Length::Fixed(3),
    );
    first_verifier
        .fill_next_units(Label::Units, &mut first)
        .unwrap();
    first_verifier.end::<u8>(
        Label::Bytes,
        crate::pattern::Kind::Message,
        Length::Fixed(3),
    );

    second_verifier.begin::<u8>(
        Label::Bytes,
        crate::pattern::Kind::Message,
        Length::Fixed(3),
    );
    second_verifier
        .fill_next_units(Label::Units, &mut second)
        .unwrap();
    second_verifier.end::<u8>(
        Label::Bytes,
        crate::pattern::Kind::Message,
        Length::Fixed(3),
    );

    let mut first_chal = [0u8; 16];
    let mut second_chal = [0u8; 16];

    // Use challenge_bytes to match the pattern structure (which creates begin/units/end)
    first_verifier.challenge_bytes(Label::custom("chal"), &mut first_chal);
    second_verifier.challenge_bytes(Label::custom("chal"), &mut second_chal);

    assert_eq!(first_chal, second_chal);

    let _ = first_verifier.finalize();
    let _ = second_verifier.finalize();
}

#[test]
fn test_statistics() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Bytes, 4);
    pattern.ratchet();
    pattern.challenge_units(Label::custom("output"), 2048);
    let pattern = pattern.finalize();

    let mut verifier_state = VerifierState::<Keccak>::new(pattern, b"seed");
    // Read the message bytes
    let mut msg = [0u8; 4];
    verifier_state
        .read_message_units(Label::Bytes, &mut msg)
        .unwrap();
    verifier_state.ratchet();

    let mut output = [0u8; 2048];
    verifier_state.challenge_units(Label::custom("output"), &mut output);

    let frequencies = (0u8..=255)
        .map(|i| output.iter().filter(|&&x| x == i).count())
        .collect::<Vec<_>>();

    // Each element should appear roughly 8 times on average
    assert!(frequencies.iter().all(|&x| x < 32 && x > 0));

    verifier_state.finalize();
}

#[test]
#[should_panic(expected = "Unexpected interaction")]
fn test_incomplete_pattern() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Units, 10);
    pattern.challenge_units(Label::custom("chal"), 1);
    let pattern = pattern.finalize();

    let mut prover_state = ProverState::<Keccak>::new(pattern, rand::rngs::OsRng);
    prover_state.add_units(Label::Units, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    // Wrong size - should panic due to length mismatch
    prover_state.challenge_bytes(Label::custom("chal"), &mut [0u8; 10]);
}

#[test]
#[should_panic(expected = "Unexpected interaction")]
fn test_prover_empty_absorb() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Bytes, 1);
    pattern.challenge_units(Label::custom("chal"), 1);
    let pattern = pattern.finalize();

    let mut prover = ProverState::<Keccak>::new(pattern.clone(), rand::rngs::OsRng);
    // Skip the message - should panic when trying to challenge
    prover.challenge_units(Label::custom("chal"), &mut [0u8; 1]);
}

#[test]
fn test_verifier_empty_proof() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Bytes, 1);
    let pattern = pattern.finalize();

    let mut verifier = VerifierState::<Keccak>::new(pattern, b"");
    // Empty transcript - should fail with insufficient data error
    let mut bytes = [0u8; 1];
    // This should return an error because there's not enough data
    let result = verifier.read_message_units(Label::Bytes, &mut bytes);
    assert!(result.is_err());
    // Manually abort and forget to avoid panic on drop
    verifier.abort();
    std::mem::forget(verifier);
}

#[test]
#[should_panic(expected = "Dropped unfinalized transcript")]
fn test_verifier_incomplete_read() {
    let mut pattern = PatternState::new();
    pattern.message_units(Label::Bytes, 2);
    pattern.challenge_units(Label::custom("chal"), 1);
    let pattern = pattern.finalize();

    // Create proof with correct data
    let mut prover = ProverState::<Keccak>::new(pattern.clone(), rand::rngs::OsRng);
    prover.message_units(Label::Bytes, b"ab");
    let mut chal = [0u8; 1];
    prover.challenge_units(Label::custom("chal"), &mut chal);
    let proof = prover.finalize();

    // Verifier doesn't read all messages - should panic on drop
    let _verifier = VerifierState::<Keccak>::new(pattern, &proof);
    // Don't read anything - drop should panic
}
