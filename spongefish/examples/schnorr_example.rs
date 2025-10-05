use std::sync::Arc;

use ark_curve25519::EdwardsProjective as Curve;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::{
    codecs::{
        arkworks_algebra::{
            FieldPattern, FieldToUnitDeserialize, FieldToUnitSerialize, GroupPattern,
            GroupToUnitDeserialize, GroupToUnitSerialize, UnitToField,
        },
        unit::Pattern as UnitPattern,
    },
    pattern::{InteractionPattern, PatternState},
    ProverState, VerifierState,
};
fn schnorr_pattern<G: CurveGroup>() -> InteractionPattern
where
    PatternState<u8>: GroupPattern<G> + FieldPattern<G::ScalarField>,
{
    let mut pattern = PatternState::<u8>::new();

    // Statement: generator and public key (public inputs)
    pattern.message_points("generator", 1);
    pattern.message_points("public_key", 1);
    pattern.ratchet();

    // Proof: commitment, challenge, response
    pattern.message_points("commitment", 1);
    pattern.challenge_scalars("challenge", 1);
    pattern.message_scalars("response", 1);

    pattern.finalize()
}

fn main() {
    type ScalarField = <Curve as PrimeGroup>::ScalarField;

    // Build pattern - the traits are now in scope
    let pattern = Arc::new(schnorr_pattern::<Curve>());
    println!("Schnorr pattern: {pattern:#?}");

    // Prove
    let mut prover: ProverState<spongefish::DefaultHash, u8> =
        ProverState::new(pattern.clone(), OsRng);

    let x = ScalarField::rand(prover.rng());
    let g = Curve::generator();
    let pk = g * x;

    // These methods come from GroupToUnitSerialize trait
    GroupToUnitSerialize::<Curve>::add_points(&mut prover, &[g]);
    GroupToUnitSerialize::<Curve>::add_points(&mut prover, &[pk]);
    prover.ratchet();

    let k = ScalarField::rand(prover.rng());
    let commitment = g * k;
    GroupToUnitSerialize::<Curve>::add_points(&mut prover, &[commitment]);

    // From UnitToField trait
    let [challenge]: [ScalarField; 1] = UnitToField::<ScalarField>::challenge_scalars(&mut prover);
    let response = k + challenge * x;

    // From FieldToUnitSerialize trait
    FieldToUnitSerialize::<ScalarField>::add_scalars(&mut prover, &[response]);

    let proof = prover.finalize();

    // Verify
    let mut verifier: VerifierState<spongefish::DefaultHash, u8> =
        VerifierState::new(pattern, &proof);

    // From GroupToUnitDeserialize trait
    let [g_v]: [Curve; 1] = GroupToUnitDeserialize::<Curve>::next_points(&mut verifier).unwrap();
    let [pk_v]: [Curve; 1] = GroupToUnitDeserialize::<Curve>::next_points(&mut verifier).unwrap();
    verifier.ratchet();

    let [commitment_v]: [Curve; 1] =
        GroupToUnitDeserialize::<Curve>::next_points(&mut verifier).unwrap();
    let [challenge_v]: [ScalarField; 1] =
        UnitToField::<ScalarField>::challenge_scalars(&mut verifier);
    let [response_v]: [ScalarField; 1] =
        FieldToUnitDeserialize::<ScalarField>::next_scalars(&mut verifier).unwrap();

    assert_eq!(g_v * response_v, commitment_v + pk_v * challenge_v);
    verifier.finalize();

    println!("✅ Schnorr proof verified!");
}
