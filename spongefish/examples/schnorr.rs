// examples/schnorr_example.rs

use std::sync::Arc;

/// Example: Simple Schnorr proofs using Spongefish
///
/// Schnorr proofs prove knowledge of a secret key over a group G of prime order p
/// where the discrete logarithm problem is hard.
///
/// Protocol flow:
/// 1. Setup: Define interaction pattern
/// 2. P → V: Statement (generator G, public key X)
/// 3. P → V: K (commitment - a group element)
/// 4. V → P: c (challenge - a scalar, generated from transcript)
/// 5. P → V: r (response - a scalar)
/// 6. V: Check P * r == K + X * c
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::{
    codecs::{
        arkworks_algebra::{
            FieldPattern, FieldTranscript, GroupPattern, GroupTranscript, VerifierFieldTranscript,
            VerifierGroupTranscript,
        },
        unit::Pattern as _,
    },
    pattern::{Common, InteractionPattern, Label, PatternState},
    DefaultHash, ProverState, VerifierError, VerifierState,
};

/// Create the interaction pattern for Schnorr protocol
fn schnorr_pattern<G: CurveGroup>() -> InteractionPattern {
    let mut pattern = PatternState::new();
    pattern
        .begin_protocol(Label::from("Schnorr"))
        // Public params ARE in pattern (affect challenges)
        .message_public_points::<G>(Label::from("generator"), 1)
        .message_public_points::<G>(Label::from("public_key"), 1)
        .ratchet()
        // Proof data
        .message_points::<G>(Label::from("commitment"), 1)
        .challenge_scalars::<G::ScalarField>(Label::from("challenge"), 1)
        .message_scalars::<G::ScalarField>(Label::from("response"), 1);
    pattern.end_protocol(Label::from("Schnorr"));

    pattern.finalize()
}

/// Key generation: returns (secret_key, public_key)
fn keygen<G: PrimeGroup>() -> (G::ScalarField, G) {
    let sk = G::ScalarField::rand(&mut OsRng);
    let pk = G::generator() * sk;
    (sk, pk)
}

/// Schnorr proof generation
#[allow(non_snake_case)]
fn prove<G, R>(prover: &mut ProverState<DefaultHash, u8, R>, P: G, X: G, x: G::ScalarField)
where
    G: CurveGroup,
    R: rand::RngCore + rand::CryptoRng,
    ProverState<DefaultHash, u8, R>: GroupTranscript<G> + FieldTranscript<G::ScalarField>,
{
    // Absorb public parameters
    prover
        .message_public_points(Label::from("generator"), &[P])
        .message_public_points(Label::from("public_key"), &[X])
        .ratchet();

    // Generate random nonce
    let k = G::ScalarField::rand(prover.rng());
    let K = P * k;

    // Send commitment
    prover.message_points(Label::from("commitment"), &[K]);

    // Get challenge from transcript (Fiat-Shamir)
    let mut c_buf = [G::ScalarField::default(); 1];
    prover.challenge_scalars(Label::from("challenge"), &mut c_buf);
    let c = c_buf[0];

    // Compute and send response
    let r = k + c * x;
    prover.message_scalars(Label::from("response"), &[r]);
}

/// Schnorr proof verification
#[allow(non_snake_case)]
fn verify<G>(verifier: &mut VerifierState<DefaultHash, u8>, P: G, X: G) -> Result<(), VerifierError>
where
    G: CurveGroup,
    for<'a> VerifierState<'a, DefaultHash, u8>:
        VerifierGroupTranscript<G> + VerifierFieldTranscript<G::ScalarField>,
{
    // Absorb same public parameters
    verifier
        .message_public_points(Label::from("generator"), &[P])
        .message_public_points(Label::from("public_key"), &[X])
        .ratchet();

    // Read commitment
    let mut K_buf = [G::default(); 1];
    verifier.read_message_points(Label::from("commitment"), &mut K_buf)?;

    let K = K_buf[0];

    // Generate challenge from transcript (same as prover via Fiat-Shamir)
    let mut c_buf = [G::ScalarField::default(); 1];
    verifier.challenge_scalars(Label::from("challenge"), &mut c_buf);
    let c = c_buf[0];

    // Read response
    let mut r_buf = [G::ScalarField::default(); 1];
    verifier.read_message_scalars(Label::from("response"), &mut r_buf)?;
    let r = r_buf[0];

    // Verify: P * r == K + X * c
    if P * r == K + X * c {
        Ok(())
    } else {
        Err(VerifierError::DeserializationError(
            "Invalid proof: equation does not hold".to_string(),
        ))
    }
}

fn main() {
    println!("=== Schnorr Proof Example ===\n");

    // Choose elliptic curve group (Curve25519)
    type G = ark_curve25519::EdwardsProjective;

    // Step 1: Create and finalize the interaction pattern
    let pattern = Arc::new(schnorr_pattern::<G>());
    println!("✓ Pattern created and finalized");

    // Step 2: Setup - generate keys
    #[allow(non_snake_case)]
    let P = G::generator();
    #[allow(non_snake_case)]
    let (x, X) = keygen::<G>();
    println!("✓ Keys generated\n");

    // Step 3: Prover generates proof
    let proof = {
        let mut prover = ProverState::new((*pattern).clone(), OsRng);

        // Generate and send proof (includes public params inside)
        prover.begin_protocol(Label::from("Schnorr"));
        prove(&mut prover, P, X, x);
        prover.end_protocol(Label::from("Schnorr"));

        prover.finalize()
    };

    println!("✓ Proof generated by prover");
    println!("  Proof size: {} bytes\n", proof.len());

    // Step 4: Verifier checks proof
    let result = {
        let mut verifier = VerifierState::new((*pattern).clone(), &proof);

        // Verify the proof (includes public params inside)
        verifier.begin_protocol(Label::from("Schnorr"));
        let verify_result = verify(&mut verifier, P, X);
        verifier.end_protocol(Label::from("Schnorr"));

        // Check for verification equation failure first
        if let Err(e) = verify_result {
            println!("✗ Verification failed: {:?}", e);
            std::process::exit(1);
        }

        verifier.finalize()
    };

    match result {
        Ok(()) => {
            println!("✓ Proof verified successfully!");
            println!("  The prover knows the secret key for the public key");
        }
        Err(e) => {
            println!("✗ Verification failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
