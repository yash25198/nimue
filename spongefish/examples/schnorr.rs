use std::sync::Arc;

/// Example: Simple Schnorr proofs using Spongefish
///
/// Schnorr proofs prove knowledge of a secret key over a group G of prime order p
/// where the discrete logarithm problem is hard.
///
/// Protocol flow:
/// 1. Setup: Define interaction pattern
/// 2. P → V: K (commitment - a group element)
/// 3. V → P: c (challenge - a scalar)
/// 4. P → V: r (response - a scalar)
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::{
    codecs::{
        arkworks_algebra::{
            FieldPattern, FieldToUnitDeserialize, FieldToUnitSerialize, GroupPattern,
            GroupToUnitDeserialize, GroupToUnitSerialize, UnitToField,
        },
        unit::Pattern, // Import Pattern trait for ratchet() method
    },
    pattern::{InteractionPattern, Pattern as PatternTrait, PatternState},
    DefaultHash, ProofError, ProofResult, ProverState, VerifierState,
};

fn schnorr_pattern<G: CurveGroup>() -> InteractionPattern
where
    PatternState<u8>: GroupPattern<G> + FieldPattern<G::ScalarField>,
{
    let mut pattern = PatternState::<u8>::new();

    // Statement: generator and public key (public inputs)
    pattern
        .begin_protocol::<str>("schnorr_proof")
        .message_points("generator", 1)
        .message_points("public_key", 1)
        .ratchet()
        .message_points("commitment", 1)
        .challenge_scalars("challenge", 1)
        .message_scalars("response", 1)
        .end_protocol::<str>("schnorr_proof");

    pattern.finalize().unwrap()
}
/// Key generation: returns (secret_key, public_key)
fn keygen<G: CurveGroup>() -> (G::ScalarField, G) {
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
    for<'a> ProverState<DefaultHash, u8, R>: GroupToUnitSerialize<G>
        + FieldToUnitSerialize<G::ScalarField>
        + UnitToField<G::ScalarField>,
{
    // Generate random nonce
    let k = G::ScalarField::rand(prover.rng());
    let K = P * k;

    // Send commitment
    prover.add_points(&[K]);

    // Receive challenge
    let mut c_buf = [G::ScalarField::default(); 1];
    prover.fill_challenge_scalars(&mut c_buf);
    let c = c_buf[0];

    // Send response
    let r = k + c * x;
    prover.add_scalars(&[r]);

    Ok(())
}

/// Schnorr proof verification
#[allow(non_snake_case)]
fn verify<G>(verifier: &mut VerifierState<DefaultHash, u8>, P: G, X: G) -> ProofResult<()>
where
    G: CurveGroup,
    for<'a> VerifierState<'a, DefaultHash, u8>: GroupToUnitDeserialize<G>
        + FieldToUnitDeserialize<G::ScalarField>
        + UnitToField<G::ScalarField>,
{
    // Read commitment
    let mut K_buf = [G::default(); 1];
    verifier.fill_next_points(&mut K_buf)?;
    let K = K_buf[0];

    // Generate challenge
    let mut c_buf = [G::ScalarField::default(); 1];
    verifier.fill_challenge_scalars(&mut c_buf);
    let c = c_buf[0];

    // Read response
    let mut r_buf = [G::ScalarField::default(); 1];
    verifier.fill_next_scalars(&mut r_buf)?;
    let r = r_buf[0];

    // Verify: P * r == K + X * c
    if P * r == K + X * c {
        Ok(())
    } else {
        Err(ProofError::InvalidProof)
    }
}

fn main() {
    // Choose elliptic curve group
    type G = ark_curve25519::EdwardsProjective;

    // Create interaction pattern
    let pattern = Arc::new(schnorr_pattern::<G>());

    // Setup: generate keys
    let P = G::generator();
    let (x, X) = keygen::<G>();

    // Prover: create proof
    let mut prover = ProverState::new(pattern.clone(), OsRng);

    // Begin protocol
    prover
        .begin_protocol()
        .add_points(&[P])
        .add_points(&[P * x])
        .ratchet();

    // Prove (this handles the proof part)
    prove(&mut prover, P, x).expect("Proving failed");

    // End protocol
    prover.end_protocol();

    let proof = prover.finalize().expect("Finalizing proof failed");

    // Verifier: verify proof
    let mut verifier = VerifierState::new(pattern.clone(), &proof);

    // Begin protocol
    let mut statement = [G::default(); 2];
    verifier
        .begin_protocol()
        .fill_next_points(&mut statement)
        .expect("Failed to read statement");
    let (P_recv, X_recv) = (statement[0], statement[1]);
    verifier.ratchet();

    // Verify proof
    verify(&mut verifier, P_recv, X_recv).expect("Verification failed");
    verifier.end_protocol();
    verifier.finalize().expect("Finalize failed");

    println!("✓ Proof verified successfully");
}
