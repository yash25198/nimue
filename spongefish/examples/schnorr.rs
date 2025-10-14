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
    codecs::arkworks_algebra::{
        FieldPattern,
        GroupPattern,
        // Extension traits for ergonomic API
        ProverFieldMessageExt,
        ProverGroupMessageExt,
        UnitToField,
        VerifierFieldMessageExt,
        VerifierGroupMessageExt,
    },
    codecs::unit::Pattern as _,
    pattern::{Label, Pattern, PatternState},
    DefaultHash, ProofError, ProofResult, ProverState, VerifierState,
};

/// Create the interaction pattern for Schnorr protocol
fn schnorr_pattern<G: CurveGroup>() -> PatternState
where
    PatternState: GroupPattern + FieldPattern,
{
    let mut pattern = PatternState::new();

    pattern.begin_protocol(Label::from("schnorr")).unwrap();
    pattern.message_points::<G>(Label::from("generator"), 1).unwrap();
    pattern
        .message_points::<G>(Label::from("public_key"), 1)
        .unwrap();
    pattern.ratchet().unwrap();
    pattern
        .message_points::<G>(Label::from("commitment"), 1)
        .unwrap();
    pattern
        .challenge_scalars::<G::ScalarField>(Label::from("challenge"), 1)
        .unwrap();
    pattern.message_scalars::<G::ScalarField>(Label::from("response"), 1).unwrap();
    pattern.end_protocol(Label::from("schnorr")).unwrap();

    pattern
}

/// Key generation: returns (secret_key, public_key)
fn keygen<G: PrimeGroup>() -> (G::ScalarField, G) {
    let sk = G::ScalarField::rand(&mut OsRng);
    let pk = G::generator() * sk;
    (sk, pk)
}

/// Schnorr proof generation
#[allow(non_snake_case)]
fn prove<G, R>(
    prover: &mut ProverState<DefaultHash, u8, R>,
    P: G,
    x: G::ScalarField,
) -> ProofResult<()>
where
    G: CurveGroup,
    R: rand::RngCore + rand::CryptoRng,
    ProverState<DefaultHash, u8, R>: ProverGroupMessageExt<G>
        + ProverFieldMessageExt<G::ScalarField>
        + UnitToField<G::ScalarField>,
{
    // Generate random nonce
    let k = G::ScalarField::rand(prover.rng());
    let K = P * k;

    // Send commitment
    prover.message_points(Label::from("commitment"), &[K])?;

    // Get challenge from transcript (Fiat-Shamir)
    let mut c_buf = [G::ScalarField::default(); 1];
    prover.fill_challenge_scalars(Label::from("challenge"), &mut c_buf)?;
    let c = c_buf[0];

    // Compute and send response
    let r = k + c * x;
    prover.message_scalars(Label::from("response"), &[r])?;

    Ok(())
}

/// Schnorr proof verification
#[allow(non_snake_case)]
fn verify<G>(verifier: &mut VerifierState<DefaultHash, u8>, P: G, X: G) -> ProofResult<()>
where
    G: CurveGroup,
    for<'a> VerifierState<'a, DefaultHash, u8>: VerifierGroupMessageExt<G>
        + VerifierFieldMessageExt<G::ScalarField>
        + UnitToField<G::ScalarField>,
{
    // Read commitment - USING EXTENSION TRAIT!
    let mut K_buf = [G::default(); 1];
    verifier.fill_message_points(Label::from("commitment"), &mut K_buf)?;
    let K = K_buf[0];

    // Generate challenge from transcript (same as prover via Fiat-Shamir)
    let mut c_buf = [G::ScalarField::default(); 1];
    verifier.fill_challenge_scalars(Label::from("challenge"), &mut c_buf)?;
    let c = c_buf[0];

    // Read response - USING EXTENSION TRAIT!
    let mut r_buf = [G::ScalarField::default(); 1];
    verifier.fill_message_scalars(Label::from("response"), &mut r_buf)?;
    let r = r_buf[0];

    // Verify: P * r == K + X * c
    if P * r == K + X * c {
        Ok(())
    } else {
        Err(ProofError::InvalidProof)
    }
}

fn main() {
    println!("=== Schnorr Proof Example ===\n");

    // Choose elliptic curve group (Curve25519)
    type G = ark_curve25519::EdwardsProjective;

    // Step 1: Create and finalize the interaction pattern
    let pattern = Arc::new(
        schnorr_pattern::<G>()
            .finalize()
            .expect("Failed to finalize pattern"),
    );
    println!("✓ Pattern created and finalized");

    // Step 2: Setup - generate keys
    let P = G::generator();
    let (x, X) = keygen::<G>();
    println!("✓ Keys generated\n");

    // Step 3: Prover generates proof - CLEAN API WITH EXTENSION TRAITS!
    let proof = {
        let mut prover = ProverState::new(pattern.clone(), OsRng);

        prover
            .begin_protocol(Label::from("schnorr"))
            .expect("Failed to begin protocol")
            .message_points(Label::from("generator"), &[P]) // Extension trait!
            .expect("Failed to add generator")
            .message_points(Label::from("public_key"), &[X]) // Extension trait!
            .expect("Failed to add public key")
            .ratchet()
            .expect("Failed to ratchet");

        // Call prove (breaks the chain, but that's fine)
        prove(&mut prover, P, x).expect("Proving failed");

        prover
            .end_protocol(Label::from("schnorr"))
            .expect("Failed to end protocol");

        prover.finalize().expect("Prover finalize failed")
    };

    println!("✓ Proof generated ({} bytes)\n", proof.len());

    // Step 4: Verifier checks proof - CLEAN API WITH EXTENSION TRAITS!
    let result = {
        let mut verifier = VerifierState::new(pattern.clone(), &proof);

        verifier
            .begin_protocol(Label::from("schnorr"))
            .expect("Failed to begin protocol");

        let mut generator = [G::default(); 1];
        verifier
            .fill_message_points(Label::from("generator"), &mut generator) // Extension trait!
            .expect("Failed to read generator");

        let mut public_key = [G::default(); 1];
        verifier
            .fill_message_points(Label::from("public_key"), &mut public_key) // Extension trait!
            .expect("Failed to read public key");

        verifier.ratchet().expect("Failed to ratchet");

        println!("✓ Statement read by verifier");

        // Call verify (breaks the chain, but that's fine)
        verify(&mut verifier, generator[0], public_key[0]).expect("Verification failed");

        verifier
            .end_protocol(Label::from("schnorr"))
            .expect("Failed to end protocol");

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
