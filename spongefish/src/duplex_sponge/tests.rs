use std::sync::Arc;

use rand::RngCore;

use crate::{
    codecs::{bytes::Pattern as BytesPattern, unit::Pattern as UnitPattern},
    duplex_sponge::legacy::DigestBridge,
    keccak::Keccak,
    pattern::{Label, Pattern, PatternState},
    BytesToUnitDeserialize, BytesToUnitSerialize, CommonUnitToBytes, DuplexSpongeInterface,
    ProverState, UnitToBytes, VerifierState,
};

// type Sha2 = DigestBridge<sha2::Sha256>;
// type Blake2b512 = DigestBridge<blake2::Blake2b512>;
// type Blake2s256 = DigestBridge<blake2::Blake2s256>;

#[test]
fn test_prover_rng_basic() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_bytes(Label::BYTES, 1).unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

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

    prover_state.abort().unwrap();
}

#[test]
fn test_prover_state_bytewriter() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_bytes(Label::BYTES, 1).unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

    let mut prover_state = ProverState::<Keccak>::new(Arc::clone(&pattern), rand::rngs::OsRng);
    assert!(prover_state.message_bytes(Label::BYTES, &[0u8]).is_ok());
    assert!(prover_state.message_bytes(Label::BYTES, &[1u8]).is_err());

    // Test public bytes (not in transcript)
    let mut pattern = PatternState::<u8>::new();
    pattern.public_bytes(Label::PUBLIC, 1).unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

    let mut prover_state = ProverState::<Keccak>::new(pattern, rand::rngs::OsRng);
    // prover_state.public_bytes(Label::PUBLIC, &[0u8]).unwrap();
    assert!(prover_state.public_bytes(Label::PUBLIC, &[0u8]).is_ok());
    assert_eq!(prover_state.narg_string(), b"");
    prover_state.finalize().unwrap();
}

#[test]
fn test_invalid_pattern_sequence() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_bytes(Label::BYTES, 3).unwrap();
    pattern.challenge_bytes(Label::custom("chal"), 1).unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

    let mut verifier_state = VerifierState::<Keccak>::new(Arc::clone(&pattern), b"abc");
    // Try to squeeze before absorbing all messages
    assert!(verifier_state
        .fill_challenge_bytes(Label::custom("chal"), &mut [0u8; 1])
        .is_err());
}

#[test]
fn test_deterministic() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_bytes(Label::BYTES, 3).unwrap();
    pattern.challenge_bytes(Label::custom("chal"), 16).unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

    let mut first_verifier = VerifierState::<Keccak>::new(Arc::clone(&pattern), b"123");
    let mut second_verifier = VerifierState::<Keccak>::new(Arc::clone(&pattern), b"123");

    let mut first = [0u8; 3];
    let mut second = [0u8; 3];

    first_verifier
        .fill_next_bytes(Label::BYTES, &mut first)
        .unwrap();
    second_verifier
        .fill_next_bytes(Label::BYTES, &mut second)
        .unwrap();

    let mut first_chal = [0u8; 16];
    let mut second_chal = [0u8; 16];

    first_verifier
        .fill_challenge_bytes(Label::custom("chal"), &mut first_chal)
        .unwrap();
    second_verifier
        .fill_challenge_bytes(Label::custom("chal"), &mut second_chal)
        .unwrap();

    assert_eq!(first_chal, second_chal);

    first_verifier.finalize().unwrap();
    second_verifier.finalize().unwrap();
}

#[test]
fn test_statistics() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_bytes(Label::BYTES, 4).unwrap();
    pattern.ratchet().unwrap();
    pattern
        .challenge_bytes(Label::custom("output"), 2048)
        .unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

    let mut verifier_state = VerifierState::<Keccak>::new(pattern, b"seed");
    verifier_state
        .fill_next_bytes(Label::BYTES, &mut [0u8; 4])
        .unwrap();
    verifier_state.ratchet().unwrap();

    let mut output = [0u8; 2048];
    verifier_state
        .fill_challenge_bytes(Label::custom("output"), &mut output)
        .unwrap();

    let frequencies = (0u8..=255)
        .map(|i| output.iter().filter(|&&x| x == i).count())
        .collect::<Vec<_>>();

    // Each element should appear roughly 8 times on average
    assert!(frequencies.iter().all(|&x| x < 32 && x > 0));

    verifier_state.finalize().unwrap();
}

#[test]
// fn test_transcript_readwrite() {
//     let mut pattern = PatternState::<u8>::new();
//     pattern.message_units(Label::UNITS, 10).unwrap();
//     pattern.challenge_bytes(Label::custom("chal"), 10).unwrap();
//     let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

//     let mut prover_state = ProverState::<Keccak>::new(Arc::clone(&pattern), rand::rngs::OsRng);
//     prover_state.add_units(Label::UNITS, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
//     let mut prover_challenges = [0u8; 10];
//     prover_state.fill_challenge_bytes(Label::custom("chal"), &mut prover_challenges).unwrap();
//     let transcript = prover_state.finalize().unwrap();

//     let mut verifier_state = VerifierState::<Keccak>::new(pattern, &transcript);
//     let mut input = [0u8; 5];
//     verifier_state.fill_next_units(Label::UNITS, &mut input).unwrap();
//     assert_eq!(input, [0, 1, 2, 3, 4]);
//     verifier_state.fill_next_units(Label::UNITS, &mut input).unwrap();
//     assert_eq!(input, [5, 6, 7, 8, 9]);
//     let mut verifier_challenges = [0u8; 10];
//     verifier_state.fill_challenge_bytes(Label::custom("chal"), &mut verifier_challenges).unwrap();
//     assert_eq!(verifier_challenges, prover_challenges);
//     verifier_state.finalize().unwrap();
// }
#[test]
#[should_panic(expected = "UnexpectedInteraction")]
fn test_incomplete_pattern() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_units(Label::UNITS, 10).unwrap();
    pattern.challenge_bytes(Label::custom("chal"), 1).unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

    let mut prover_state = ProverState::<Keccak>::new(pattern, rand::rngs::OsRng);
    prover_state
        .add_units(Label::UNITS, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .unwrap();
    // Wrong size - should panic
    prover_state
        .fill_challenge_bytes(Label::custom("chal"), &mut [0u8; 10])
        .unwrap();
}

#[test]
fn test_prover_empty_absorb() {
    let mut pattern = PatternState::<u8>::new();
    pattern.message_bytes(Label::BYTES, 1).unwrap();
    pattern.challenge_bytes(Label::custom("chal"), 1).unwrap();
    let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

    let mut prover = ProverState::<Keccak>::new(Arc::clone(&pattern), rand::rngs::OsRng);
    // Skip the message - should fail when trying to challenge
    assert!(prover
        .fill_challenge_bytes(Label::custom("chal"), &mut [0u8; 1])
        .is_err());

    let mut verifier = VerifierState::<Keccak>::new(pattern, b"");
    // Empty transcript - should fail
    assert!(verifier.next_bytes::<1>(Label::BYTES).is_err());
    verifier.abort().unwrap();
}

// fn test_streaming_absorb_and_squeeze<H: DuplexSpongeInterface>()
// where
//     ProverState<H>: BytesToUnitSerialize + UnitToBytes,
// {
//     let bytes = b"yellow submarine";

//     let mut pattern = PatternState::<u8>::new();
//     pattern.message_bytes(Label::BYTES, 16).unwrap();
//     pattern.challenge_bytes(Label::custom("control"), 16).unwrap();
//     pattern.message_bytes(Label::custom("level2"), 1).unwrap();
//     pattern.challenge_bytes(Label::custom("long"), 1024).unwrap();
//     let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

//     // Control - do everything at once
//     let mut prover_state = ProverState::<H>::new(Arc::clone(&pattern), rand::rngs::OsRng);
//     prover_state.message_bytes(Label::BYTES, bytes).unwrap();
//     let control_chal = prover_state.challenge_bytes::<16>(Label::custom("control")).unwrap();
//     let control_transcript = prover_state.narg_string().to_vec();

//     // Streaming - split the operations
//     let mut stream_prover = ProverState::<H>::new(Arc::clone(&pattern), rand::rngs::OsRng);
//     stream_prover.message_bytes(Label::BYTES, &bytes[..10]).unwrap();
//     stream_prover.message_bytes(Label::BYTES, &bytes[10..]).unwrap();
//     let first_chal = stream_prover.challenge_bytes::<8>(Label::custom("control")).unwrap();
//     let second_chal = stream_prover.challenge_bytes::<8>(Label::custom("control")).unwrap();
//     let transcript = stream_prover.narg_string().to_vec();

//     assert_eq!(transcript, control_transcript);
//     assert_eq!(&first_chal[..], &control_chal[..8]);
//     assert_eq!(&second_chal[..], &control_chal[8..]);

//     prover_state.add_bytes(Label::custom("level2"), &[0x42]).unwrap();
//     stream_prover.add_bytes(Label::custom("level2"), &[0x42]).unwrap();

//     let control_chal = prover_state.challenge_bytes::<1024>(Label::custom("long")).unwrap();
//     for control_chunk in control_chal.chunks(16) {
//         let chunk = stream_prover.challenge_bytes::<16>(Label::custom("long")).unwrap();
//         assert_eq!(control_chunk, &chunk[..]);
//     }

//     prover_state.finalize().unwrap();
//     stream_prover.finalize().unwrap();
// }

// #[test]
// fn test_streaming_sha2() {
//     test_streaming_absorb_and_squeeze::<Sha2>();
// }

// #[test]
// fn test_streaming_blake2() {
//     test_streaming_absorb_and_squeeze::<Blake2b512>();
//     test_streaming_absorb_and_squeeze::<Blake2s256>();
// }

// #[test]
// fn test_streaming_keccak() {
//     test_streaming_absorb_and_squeeze::<Keccak>();
// }
