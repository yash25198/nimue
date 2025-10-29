use std::sync::Arc;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::{
    pattern::{PatternState,InteractionPattern},
    ProverState, VerifierState, DefaultHash,ProofError,
    codecs::unit::Pattern as UnitPattern,
};
use spongefish::codecs::arkworks_algebra::{
    FieldPattern, FieldTranscript, GroupPattern, GroupTranscript,
    VerifierFieldTranscript, VerifierGroupTranscript,
};

// Define protocol labels
mod schnorr {
    pub const GENERATOR: &str = "generator";
    pub const PUBLIC_KEY: &str = "public_key";
    pub const COMMITMENT: &str = "commitment";
    pub const CHALLENGE: &str = "challenge";
    pub const RESPONSE: &str = "response";
}

// Pattern definition
fn schnorr_pattern<G: CurveGroup>() -> Arc<InteractionPattern> {
    let mut pattern = PatternState::new();
    
    pattern.message_public_points::<G>(schnorr::GENERATOR, 1);
    pattern.message_public_points::<G>(schnorr::PUBLIC_KEY, 1);
    pattern.ratchet();
    pattern.message_points::<G>(schnorr::COMMITMENT, 1);
    pattern.challenge_scalars::<G::ScalarField>(schnorr::CHALLENGE, 1);
    pattern.message_scalars::<G::ScalarField>(schnorr::RESPONSE, 1);
    
    Arc::new(pattern.finalize())
}

// Prover
fn prove<G, R>(
    prover: &mut ProverState<DefaultHash, u8, R>,
    g: G,
    public_key: G,
    secret_key: G::ScalarField,
) where
    G: CurveGroup,
    R: rand::RngCore + rand::CryptoRng,
    ProverState<DefaultHash, u8, R>: 
        GroupTranscript<G> + FieldTranscript<G::ScalarField>,
{
    // Absorb public parameters (chaining works)
    prover
        .message_public_points(schnorr::GENERATOR, &[g])
        .message_public_points(schnorr::PUBLIC_KEY, &[public_key])
        .ratchet();
    
    // Generate and send commitment
    let k = G::ScalarField::rand(prover.rng());
    let commitment = g * k;
    prover.message_points(schnorr::COMMITMENT, &[commitment]);
    
    // Get challenge (mutable borrow for output, breaks chaining)
    let mut c_buf = [G::ScalarField::default(); 1];
    prover.challenge_scalars(schnorr::CHALLENGE, &mut c_buf);
    let c = c_buf[0];
    
    // Compute and send response
    let r = k + c * secret_key;
    prover.message_scalars(schnorr::RESPONSE, &[r]);
}

// Verifier
fn verify<G>(
    verifier: &mut VerifierState<DefaultHash, u8>,
    g: G,
    public_key: G,
) -> Result<(), crate::ProofError>
where
    G: CurveGroup,
    for<'a> VerifierState<'a, DefaultHash, u8>:
        VerifierGroupTranscript<G> + VerifierFieldTranscript<G::ScalarField>,
{
    // Absorb same public parameters (chaining works)
    verifier
        .message_public_points(schnorr::GENERATOR, &[g])
        .message_public_points(schnorr::PUBLIC_KEY, &[public_key])
        .ratchet();
    
    // Read commitment from proof (returns Result)
    let mut commitment_buf = [G::default(); 1];
    verifier.read_message_points(schnorr::COMMITMENT, &mut commitment_buf)?;
    let commitment = commitment_buf[0];
    
    // Generate challenge (deterministic from transcript)
    let mut c_buf = [G::ScalarField::default(); 1];
    verifier.challenge_scalars(schnorr::CHALLENGE, &mut c_buf);
    let c = c_buf[0];
    
    // Read response from proof (returns Result)
    let mut r_buf = [G::ScalarField::default(); 1];
    verifier.read_message_scalars(schnorr::RESPONSE, &mut r_buf)?;
    let r = r_buf[0];
    
    // Verify equation: g^r == commitment * public_key^c
    if g * r != commitment + public_key * c {
        return Err(ProofError::InvalidProof);
    }
    
    Ok(())
}

// Usage
fn main() {
    type G = ark_curve25519::EdwardsProjective;
    
    let pattern = schnorr_pattern::<G>();
    
    // Setup
    let g = G::generator();
    let secret_key = <G as PrimeGroup>::ScalarField::rand(&mut OsRng);
    let public_key = g * secret_key;
    
    // Prove
    let proof = {
        let mut prover = ProverState::new((*pattern).clone(), OsRng);
        prove(&mut prover, g, public_key, secret_key);
        prover.finalize()
    };
    
    println!("✓ Proof generated ({} bytes)", proof.len());
    
    // Verify
    {
        let mut verifier = VerifierState::new((*pattern).clone(), &proof);
        verify(&mut verifier, g, public_key)
            .expect("Verification failed");
        verifier.finalize()
            .expect("Proof has unconsumed data");
    }
    
    println!("✓ Proof verified!");
}