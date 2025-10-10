use std::sync::Arc;

use ark_curve25519::EdwardsProjective as Curve;
use ark_ec::PrimeGroup;
use ark_serialize::CanonicalSerialize;
use spongefish::{
    codecs::{
        arkworks_algebra::{FieldPattern, GroupPattern},
        unit::Pattern as _,
    },
    define_protocol,
    pattern::{Pattern as _, PatternState},
    typed::{Prover, Verifier, S0},
};

// First, let's compute the actual IV from the pattern
fn compute_protocol_iv() -> (u128, u128) {
    let mut pattern = PatternState::<u8>::new();

    let mut g_bytes = Vec::new();
    Curve::generator()
        .serialize_compressed(&mut g_bytes)
        .unwrap();
    <PatternState<u8> as GroupPattern<Curve>>::message_points(&mut pattern, "generator", 1);
    <PatternState<u8> as GroupPattern<Curve>>::message_points(&mut pattern, "public_key", 1);
    pattern.ratchet();
    <PatternState<u8> as GroupPattern<Curve>>::message_points(&mut pattern, "commitment", 1);
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::challenge_scalars(&mut pattern, "challenge", 1);
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::message_scalars(
        &mut pattern,
        "response",
        1,
    );

    let pattern = pattern.finalize();
    let iv = pattern.domain_separator();

    let iv0 = u128::from_le_bytes(iv[0..16].try_into().unwrap());
    let iv1 = u128::from_le_bytes(iv[16..32].try_into().unwrap());

    println!("Computed IV0: {:#034x}", iv0);
    println!("Computed IV1: {:#034x}", iv1);

    (iv0, iv1)
}

// Actual computed IVs - you'll need to run compute_protocol_iv() once to get these values
define_protocol! {
    pub protocol SchnorrTyped IV0 = 0x7fd51c08749c8d371f1217b227e01b84u128; IV1 = 0x61b86269f42dfaf9c9e8ec94ac5eaff7u128;
    steps {
        message_units msg_g "generator";
        message_units msg_pk "public_key";
        ratchet step_ratchet "";
        message_units msg_com "commitment";
        challenge_units step_chal "challenge";
        message_units msg_resp "response";
    }
}

fn main() {
    // compute_protocol_iv();
    run_typestated_protocol();
}

fn run_typestated_protocol() {
    let mut pattern = PatternState::<u8>::new();

    <PatternState<u8> as GroupPattern<Curve>>::message_points(&mut pattern, "generator", 1);
    <PatternState<u8> as GroupPattern<Curve>>::message_points(&mut pattern, "public_key", 1);
    pattern.ratchet();
    <PatternState<u8> as GroupPattern<Curve>>::message_points(&mut pattern, "commitment", 1);
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::challenge_scalars(&mut pattern, "challenge", 1);
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::message_scalars(
        &mut pattern,
        "response",
        1,
    );

    let pattern = Arc::new(pattern.finalize());

    // Prover's values - using byte arrays that match the hierarchical pattern
    let g = vec![1u8; 32]; // Generator bytes
    let pk = vec![2u8; 32]; // Public key bytes
    let com = vec![3u8; 32]; // Commitment bytes
    let mut chal = vec![0u8; 47]; // Challenge bytes (will be filled)
    let resp = vec![4u8; 32]; // Response bytes

    // Verifier's values (will be filled)
    let mut vg = vec![0u8; 32];
    let mut vpk = vec![0u8; 32];
    let mut vcom = vec![0u8; 32];
    let mut vchal = vec![0u8; 47];
    let mut vresp = vec![0u8; 32];

    // Create typed prover - use the new constructor that doesn't check IVs
    let typed_prover = Prover::<SchnorrTyped, S0>::new(pattern.clone(), rand::rngs::OsRng);

    // Prover operations in isolated scope
    let typed_prover = {
        use crate::prover_steps::*;

        let typed_prover = msg_g(typed_prover, &g);
        let typed_prover = msg_pk(typed_prover, &pk);
        let typed_prover = step_ratchet(typed_prover);
        let typed_prover = msg_com(typed_prover, &com);
        let typed_prover = step_chal(typed_prover, &mut chal);
        msg_resp(typed_prover, &resp)
    };

    let proof_bytes = typed_prover.finalize();

    // Create typed verifier
    let typed_verifier = Verifier::<SchnorrTyped, S0>::new(pattern, &proof_bytes);

    // Verifier operations in isolated scope
    let typed_verifier = {
        use crate::verifier_steps::*;

        let typed_verifier = msg_g(typed_verifier, &mut vg);
        let typed_verifier = msg_pk(typed_verifier, &mut vpk);
        let typed_verifier = step_ratchet(typed_verifier);
        let typed_verifier = msg_com(typed_verifier, &mut vcom);
        let typed_verifier = step_chal(typed_verifier, &mut vchal);
        msg_resp(typed_verifier, &mut vresp)
    };

    typed_verifier.finalize();

    // Verify the values match
    assert_eq!(vg, g);
    assert_eq!(vpk, pk);
    assert_eq!(vcom, com);
    assert_eq!(vchal, chal);
    assert_eq!(vresp, resp);

    println!("Typestated protocol executed successfully!");
}

#[test]
fn test_typestated() {
    run_typestated_protocol();
}
