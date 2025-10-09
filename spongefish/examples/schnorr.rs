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
        unit::Pattern as _,
    },
    pattern::{Label, Pattern, PatternState},
    DefaultHash, ProofError, ProofResult, ProverState, VerifierState,
};

fn schnorr_pattern<G: CurveGroup>() -> PatternState<u8>
where
    PatternState<u8>: GroupPattern<G> + FieldPattern<G::ScalarField>,
{
    let mut pattern = PatternState::<u8>::new();
    // Statement: generator and public key (public inputs)
    pattern.begin_protocol(Label::custom("schnorr")).expect("Failed to begin protocol");
    pattern.message_points(Label::custom("generator"), 1).expect("Failed to add generator pattern");
    pattern.message_points(Label::custom("public_key"), 1).expect("Failed to add public_key pattern");

    pattern.ratchet().expect("Failed to ratchet");
    // Proof: commitment, challenge, response
    pattern.message_points(Label::custom("commitment"), 1).expect("Failed to add commitment pattern");
    pattern.message_scalars(Label::custom("challenge"), 1).expect("Failed to add challenge pattern");
    pattern.message_scalars(Label::custom("response"), 1).expect("Failed to add response pattern");
    pattern.end_protocol(Label::custom("schnorr")).expect("Failed to end protocol");
    pattern
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
        + FieldToUnitSerialize<G::ScalarField>,
{
    // Generate random nonce
    let k = G::ScalarField::rand(prover.rng());
    let K = P * k;

    // Send commitment
    prover.add_points(Label::custom("commitment"),&[K]).unwrap();
    

    // Generate challenge (in real protocol, this would come from verifier)
    let c = G::ScalarField::rand(prover.rng());

    // Send challenge
    prover.add_scalars(Label::custom("challenge"),&[c]).unwrap();

    // Send response
    let r = k + c * x;
    prover.add_scalars(Label::custom("response"),&[r]).unwrap();

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
    verifier.fill_next_points(Label::custom("commitment"),&mut K_buf)?;
    let K = K_buf[0];

    // Read challenge
    let mut c_buf = [G::ScalarField::default(); 1];
    verifier.fill_next_scalars(Label::custom("challenge"),&mut c_buf)?;
    let c = c_buf[0];

    // Read response
    let mut r_buf = [G::ScalarField::default(); 1];
    verifier.fill_next_scalars(Label::custom("response"),&mut r_buf)?;
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

    // Finalize the pattern
    let pattern = Arc::new(<PatternState as Clone>::clone(&pattern).finalize());

    // Setup: generate keys
    let P = G::generator();
    let (x, X) = keygen::<G>();

    // Create prover state
    let mut prover = ProverState::new(pattern.clone(), OsRng);
    prover.begin_protocol(Label::custom("schnorr"))
        .expect("Failed to begin protocol")
        .add_points(Label::custom("generator"),&[P])
        .expect("Failed to add generator")
        .add_points(Label::custom("public_key"),&[X])
        .expect("Failed to add public key")
        .ratchet()
        .expect("Failed to ratchet");
    // Generate proof
    prove(&mut prover, P, x).expect("Proving failed");
    prover.end_protocol(Label::custom("schnorr")).expect("Failed to end protocol");

    let proof = prover.finalize().expect("Finalize failed");

    // Read statements
    let mut generator = [G::default(); 1];
    let mut public_key = [G::default(); 1];

    // Create verifier state
    let mut verifier = VerifierState::new(pattern.clone(), &proof);
    verifier.begin_protocol(Label::custom("schnorr"))
        .expect("Failed to begin protocol")
        .fill_next_points(Label::custom("generator"),&mut generator)
        .expect("Failed to read statement")
        .fill_next_points(Label::custom("public_key"),&mut public_key)
        .expect("Failed to read statement")
        .ratchet().expect("Ratchet failed");
    // Verify proof
    verify(&mut verifier, generator[0], public_key[0]).expect("Verification failed");
    verifier.end_protocol(Label::custom("schnorr")).expect("Failed to end protocol");
    verifier.finalize().expect("Finalize failed");

    println!("✓ Proof verified successfully");
}
