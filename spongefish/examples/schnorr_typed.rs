use std::sync::Arc;

use ark_curve25519::EdwardsProjective as Curve;
use ark_ec::PrimeGroup;
use spongefish::{
    codecs::{
        arkworks_algebra::{FieldPattern, GroupPattern},
        unit::Pattern as UnitPattern,
    },
    define_protocol,
    pattern::{Label, Pattern as _, PatternState},
    typed::{Prover, Verifier, S0},
};

// First, let's compute the actual IV from the pattern
fn compute_protocol_iv() -> (u128, u128) {
    let mut pattern = PatternState::<u8>::new();

    <PatternState<u8> as GroupPattern<Curve>>::message_points(
        &mut pattern,
        Label::custom("generator"),
        1,
    )
    .unwrap();
    <PatternState<u8> as GroupPattern<Curve>>::message_points(
        &mut pattern,
        Label::custom("public_key"),
        1,
    )
    .unwrap();
    <PatternState<u8> as UnitPattern>::ratchet(&mut pattern).unwrap();
    <PatternState<u8> as GroupPattern<Curve>>::message_points(
        &mut pattern,
        Label::custom("commitment"),
        1,
    )
    .unwrap();
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::challenge_scalars(
        &mut pattern,
        Label::custom("challenge"),
        1,
    )
    .unwrap();
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::message_scalars(
        &mut pattern,
        Label::custom("response"),
        1,
    )
    .unwrap();

    let pattern = pattern.finalize().unwrap();
    let iv = pattern.domain_separator();

    let iv0 = u128::from_le_bytes(iv[0..16].try_into().unwrap());
    let iv1 = u128::from_le_bytes(iv[16..32].try_into().unwrap());

    println!("Computed IV0: {:#034x}", iv0);
    println!("Computed IV1: {:#034x}", iv1);

    (iv0, iv1)
}

// Define the protocol with the correct step types
define_protocol! {
    pub protocol SchnorrTyped
    IV0 = 0xa8cd4b8f43345c5c1787dee495750f38u128;
    IV1 = 0x0ac95a8b79017cc1de0962c128c74af2u128;
    steps {
        message_points msg_g "generator";
        message_points msg_pk "public_key";
        ratchet step_ratchet "";
        message_points msg_com "commitment";
        challenge_scalars step_chal "challenge";
        message_scalars msg_resp "response";
    }
}

fn main() {
    let (iv0, iv1) = compute_protocol_iv();
    run_typestated_protocol();
}

fn run_typestated_protocol() {
    let mut pattern = PatternState::<u8>::new();

    <PatternState<u8> as GroupPattern<Curve>>::message_points(
        &mut pattern,
        Label::custom("generator"),
        1,
    )
    .unwrap();
    <PatternState<u8> as GroupPattern<Curve>>::message_points(
        &mut pattern,
        Label::custom("public_key"),
        1,
    )
    .unwrap();
    <PatternState<u8> as UnitPattern>::ratchet(&mut pattern).unwrap();
    <PatternState<u8> as GroupPattern<Curve>>::message_points(
        &mut pattern,
        Label::custom("commitment"),
        1,
    )
    .unwrap();
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::challenge_scalars(
        &mut pattern,
        Label::custom("challenge"),
        1,
    )
    .unwrap();
    <PatternState<u8> as FieldPattern<<Curve as ark_ec::PrimeGroup>::ScalarField>>::message_scalars(
        &mut pattern,
        Label::custom("response"),
        1,
    )
    .unwrap();

    let pattern = Arc::new(pattern.finalize().unwrap());

    // Use actual curve points instead of raw bytes
    use ark_ff::UniformRand;
    let mut rng = rand::rngs::OsRng;

    let g = Curve::generator();
    let sk = <Curve as PrimeGroup>::ScalarField::rand(&mut rng);
    let pk = g * sk;

    let k = <Curve as PrimeGroup>::ScalarField::rand(&mut rng);
    let com = g * k;

    // Create typed prover
    let typed_prover = Prover::<SchnorrTyped, S0>::new(pattern.clone(), rand::rngs::OsRng);

    // Prover operations
    let typed_prover = {
        use crate::prover_steps::*;

        let typed_prover = msg_g(typed_prover, &[g]);
        let typed_prover = msg_pk(typed_prover, &[pk]);
        let typed_prover = step_ratchet(typed_prover);
        let typed_prover = msg_com(typed_prover, &[com]);

        let mut chal = [<Curve as PrimeGroup>::ScalarField::default(); 1];
        let typed_prover = step_chal(typed_prover, &mut chal);

        let response = k + chal[0] * sk;
        msg_resp(typed_prover, &[response])
    };

    let proof_bytes = typed_prover.finalize();

    // Create typed verifier
    let typed_verifier = Verifier::<SchnorrTyped, S0>::new(pattern, &proof_bytes);

    // Verifier operations
    let typed_verifier = {
        use crate::verifier_steps::*;

        let mut vg = [Curve::default(); 1];
        let typed_verifier = msg_g(typed_verifier, &mut vg);

        let mut vpk = [Curve::default(); 1];
        let typed_verifier = msg_pk(typed_verifier, &mut vpk);

        let typed_verifier = step_ratchet(typed_verifier);

        let mut vcom = [Curve::default(); 1];
        let typed_verifier = msg_com(typed_verifier, &mut vcom);

        let mut vchal = [<Curve as PrimeGroup>::ScalarField::default(); 1];
        let typed_verifier = step_chal(typed_verifier, &mut vchal);

        let mut vresp = [<Curve as PrimeGroup>::ScalarField::default(); 1];
        msg_resp(typed_verifier, &mut vresp)
    };

    typed_verifier.finalize();

    println!("Typestated Schnorr protocol executed successfully!");
}
