use std::sync::Arc;

use ark_curve25519::EdwardsProjective as Curve;
use ark_ec::PrimeGroup;
use ark_serialize::CanonicalSerialize;
use spongefish::{
    define_protocol,
    pattern::{PatternState, Pattern as _},
    typed::{Prover, Verifier, S0},
    codecs::unit::Pattern as _,
};

// First, let's compute the actual IV from the pattern
fn compute_protocol_iv() -> (u128, u128) {
    let mut pattern = PatternState::<u8>::new();
    
    let mut g_bytes = Vec::new();
    Curve::generator().serialize_compressed(&mut g_bytes).unwrap();
    pattern.message_units("generator", g_bytes.len());
    pattern.message_units("public_key", 32);
    pattern.ratchet();
    pattern.message_units("commitment", 32);
    pattern.challenge_units("challenge", 16);
    pattern.message_units("response", 32);
    
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
    pub protocol SchnorrTyped IV0 = 0x7737ae506738c6557fdd6f1be1fecda1u128; IV1 =  0xe3b25bd9b1147ae830ce763f3861d640u128;  
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
    
    // Define the protocol structure
    let mut g_bytes = Vec::new();
    Curve::generator().serialize_compressed(&mut g_bytes).unwrap();
    pattern.message_units("generator", g_bytes.len());
    
    let pk_bytes = 32; // Compressed curve point
    pattern.message_units("public_key", pk_bytes);
    
    pattern.ratchet();
    
    let com_bytes = 32; // Compressed curve point
    pattern.message_units("commitment", com_bytes);
    
    pattern.challenge_units("challenge", 16);
    
    let resp_bytes = 32; // Fr serialized size
    pattern.message_units("response", resp_bytes);
    
    let pattern = Arc::new(pattern.finalize());
    
    // Prover's values
    let g = g_bytes;
    let pk = vec![1u8; 32];
    let com = vec![2u8; 32];
    let mut chal = vec![0u8; 16];
    let resp = vec![42u8; 32];
    
    // Verifier's values (will be filled)
    let mut vg = vec![0u8; g.len()];
    let mut vpk = vec![0u8; 32];
    let mut vcom = vec![0u8; 32];
    let mut vchal = vec![0u8; 16];
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