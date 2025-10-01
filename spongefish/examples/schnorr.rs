/// Example: simple Schnorr proofs.
///
/// Schnorr proofs allow to prove knowledge of a secret key over a group $\mathbb{G}$ of prime order $p$ where the discrete logarithm problem is hard. In `spongefish`, we play with 3 data structures:
///
/// 1. `spongefish::DomainSeparator``
/// The DomainSeparator describes the protocol.
/// In the case of Schnorr proofs we have also some public information (the generator $P$ and the public key $X$).
/// The protocol, roughly speaking is:
///
/// - P -> V: K, a commitment (point)
/// - V -> P: c, a challenge (scalar)
/// - P -> V: r, a response (scalar)
///
/// 2. `spongefish::ProverState`, describes the prover state. It contains the transcript, but not only:
/// it also provides a CSPRNG and a reliable way of serializing elements into a proof, so that the prover does not have to worry about them.
/// It can be instantiated via `DomainSeparator::to_prover_state()`.
///
/// 3. `spongefish::VerifierState`, describes the verifier state.
/// It internally will read the transcript, and deserialize elements as requested making sure that they match with the domain separator.
/// It can be used to verify a proof.
use std::sync::Arc;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use spongefish::{
    codecs::unit::{
        Common, Pattern as UnitPattern, Prover as ProverTrait, Verifier as VerifierTrait,
    },
    transcript::{Pattern, PatternState},
    DefaultRng, ProofError, ProofResult, ProverState, VerifierState,
};

fn ark_rng() -> ark_std::rand::rngs::StdRng {
    let seed: [u8; 32] = rand::random();
    <ark_std::rand::rngs::StdRng as ark_std::rand::SeedableRng>::from_seed(seed)
}

/// The key generation algorithm otuputs
/// a secret key `sk` in $\mathbb{Z}_p$
/// and its respective public key `pk` in $\mathbb{G}$.
fn keygen<G: CurveGroup>() -> (G::ScalarField, G) {
    let sk = G::ScalarField::rand(&mut ark_rng());
    let pk = G::generator() * sk;
    (sk, pk)
}

fn point_to_bytes<G: CurveGroup>(point: &G) -> Vec<u8> {
    let mut bytes = Vec::new();
    point.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn bytes_to_point<G: CurveGroup>(bytes: &[u8]) -> ProofResult<G> {
    G::deserialize_compressed(bytes).map_err(|_| ProofError::SerializationError)
}

fn scalar_to_bytes<F: CanonicalSerialize>(scalar: &F) -> Vec<u8> {
    let mut bytes = Vec::new();
    scalar.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn bytes_to_scalar<F: CanonicalDeserialize>(bytes: &[u8]) -> ProofResult<F> {
    F::deserialize_compressed(bytes).map_err(|_| ProofError::SerializationError)
}

fn challenge_to_scalar<F: PrimeField>(challenge_bytes: &[u8]) -> F {
    F::from_le_bytes_mod_order(challenge_bytes)
}

/// The prove algorithm takes as input
/// - the prover state `ProverState`, that has access to a random oracle `H` and can absorb/squeeze elements from the group `G`.
/// - The generator `P` in the group.
/// - the secret key $x \in \mathbb{Z}_p$
/// It returns a zero-knowledge proof of knowledge of `x` as a sequence of bytes.
#[allow(non_snake_case)]
#[allow(non_snake_case)]
fn prove<G>(
    mut prover_state: ProverState<spongefish::DefaultHash, u8, DefaultRng>,
    P: G,
    x: G::ScalarField,
) -> ProofResult<Vec<u8>>
where
    G: CurveGroup,
{
    let k = G::ScalarField::rand(&mut ark_rng());
    let K = P * k;

    let k_bytes = point_to_bytes(&K);
    prover_state.hint_bytes("commitment", &k_bytes);

    let mut c_bytes = vec![0u8; 32];
    prover_state.challenge_units_out("challenge", &mut c_bytes[..]);
    let c: G::ScalarField = challenge_to_scalar(&c_bytes); // ← Fixed!

    let r = k + c * x;

    let r_bytes = scalar_to_bytes(&r);
    prover_state.hint_bytes("response", &r_bytes);

    prover_state.end_protocol::<ProverState>("schnorr");
    Ok(prover_state.finalize())
}

/// The verify algorithm takes as input
/// - the verifier state `VerifierState`, that has access to a random oracle `H` and can deserialize/squeeze elements from the group `G`.
/// - the secret key `witness`
/// It returns a zero-knowledge proof of knowledge of `witness` as a sequence of bytes.
#[allow(non_snake_case)]
fn verify<G>(
    verifier_state: &mut VerifierState<spongefish::DefaultHash, u8>,
    P: G,
    X: G,
) -> ProofResult<()>
where
    G: CurveGroup,
{
    let k_bytes = verifier_state
        .hint_bytes("commitment", 32)
        .map_err(|_| ProofError::SerializationError)?;
    let K: G = bytes_to_point(k_bytes)?;

    let mut c_bytes = vec![0u8; 32];
    verifier_state.challenge_units_out("challenge", &mut c_bytes[..]);
    let c: G::ScalarField = challenge_to_scalar(&c_bytes); // ← Fixed!

    let r_bytes = verifier_state
        .hint_bytes("response", 32)
        .map_err(|_| ProofError::SerializationError)?;
    let r: G::ScalarField = bytes_to_scalar(r_bytes)?;

    verifier_state.end_protocol::<ProverState>("schnorr");
    if P * r == K + X * c {
        Ok(())
    } else {
        Err(ProofError::InvalidProof)
    }
}

#[allow(non_snake_case)]
fn main() {
    type G = ark_curve25519::EdwardsProjective;

    let mut pattern = PatternState::<u8>::new();
    pattern.begin_protocol::<ProverState>("schnorr");
    pattern.public_units("generator", 32); // compressed point size
    pattern.public_units("public_key", 32);
    pattern.ratchet();
    pattern.hint_bytes("commitment", 32);
    pattern.challenge_units("challenge", 32);
    pattern.hint_bytes("response", 32);
    pattern.end_protocol::<ProverState>("schnorr");

    let interaction_pattern = pattern.finalize();

    let mut prover_state =
        ProverState::<spongefish::DefaultHash, u8, DefaultRng>::from(interaction_pattern.clone());

    let P = G::generator();
    let (x, X) = keygen::<G>();

    prover_state.begin_protocol::<ProverState>("schnorr");

    let p_bytes = point_to_bytes(&P);
    let x_bytes = point_to_bytes(&X);
    prover_state.public_units("generator", &p_bytes);
    prover_state.public_units("public_key", &x_bytes);
    prover_state.ratchet();

    let proof = prove(prover_state, P, x).expect("Proving failed");

    println!("Here's a Schnorr signature:\n{}", hex::encode(&proof));

    let mut verifier_state =
        VerifierState::<spongefish::DefaultHash, u8>::new(Arc::new(interaction_pattern), &proof);
    verifier_state.begin_protocol::<ProverState>("schnorr");
    verifier_state.public_units("generator", &p_bytes);
    verifier_state.public_units("public_key", &x_bytes);
    verifier_state.ratchet();
    verify(&mut verifier_state, P, X).expect("Verification failed");
    verifier_state.finalize();
}
