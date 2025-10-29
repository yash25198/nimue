//! Bulletproof example using Spongefish PatternState
//!
//! Bulletproofs allow to prove that a vector commitment has the following form:
//! C = ⟨a, G⟩ + ⟨b, H⟩ + ⟨a, b⟩ U

use std::sync::Arc;

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::Field;
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
    pattern::{Label, PatternState,Pattern},
    DefaultHash, ProofError, ProofResult, ProverState, VerifierState,
};

fn bulletproof_pattern<G: CurveGroup>(size: usize) -> PatternState {
    let mut pattern = PatternState::new();

    // Commitment phase
    pattern
        .begin_protocol(Label::new("bulletproof"))
        .message_points::<G>(Label::new("commitment"), 1)
        .ratchet();

    // Recursive folding rounds (log2(size) rounds)
    let num_rounds = (size as f64).log2() as usize;
    for _ in 0..num_rounds {
        pattern
            .message_points::<G>(Label::new("round"), 2)
            .message_scalars::<G::ScalarField>(Label::new("challenge"), 1);
    }

    // Final opening
    pattern
        .message_scalars::<G::ScalarField>(Label::new("final"), 2)
        .end_protocol(Label::new("bulletproof"));

    pattern
}

fn prove<G, R>(
    prover: &mut ProverState<DefaultHash, u8, R>,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    statement: &G,
    witness: (&[G::ScalarField], &[G::ScalarField]),
    round: usize,
) -> ProofResult<()>
where
    G: CurveGroup,
    R: rand::RngCore + rand::CryptoRng,
    ProverState<DefaultHash, u8, R>: GroupTranscript<G> + FieldTranscript<G::ScalarField>,
{
    assert_eq!(witness.0.len(), witness.1.len());

    if witness.0.len() == 1 {
        assert_eq!(generators.0.len(), 1);
        prover.message_scalars(Label::new("final"), &[witness.0[0], witness.1[0]]);
        return Ok(());
    }

    let n = witness.0.len() / 2;
    let (a_left, a_right) = witness.0.split_at(n);
    let (b_left, b_right) = witness.1.split_at(n);
    let (g_left, g_right) = generators.0.split_at(n);
    let (h_left, h_right) = generators.1.split_at(n);
    let u = *generators.2;

    let left = u * dot_prod(a_left, b_right)
        + G::msm_unchecked(g_right, a_left)
        + G::msm_unchecked(h_left, b_right);

    let right = u * dot_prod(a_right, b_left)
        + G::msm_unchecked(g_left, a_right)
        + G::msm_unchecked(h_right, b_left);

    let x = G::ScalarField::rand(prover.rng());
    prover
        .message_points(Label::new("round"), &[left, right])
        .message_scalars(Label::new("challenge"), &[x]);
    let x_inv = x.inverse().expect("Challenge inverse failed");

    let new_g = fold_generators(g_left, g_right, &x_inv, &x);
    let new_h = fold_generators(h_left, h_right, &x, &x_inv);
    let new_generators = (&new_g[..], &new_h[..], generators.2);

    let new_a = fold(a_left, a_right, &x, &x_inv);
    let new_b = fold(b_left, b_right, &x_inv, &x);
    let new_witness = (&new_a[..], &new_b[..]);

    let new_statement = *statement + left * x.square() + right * x_inv.square();

    prove(
        prover,
        new_generators,
        &new_statement,
        new_witness,
        round + 1,
    )
}

fn verify<G>(
    verifier: &mut VerifierState<DefaultHash, u8>,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    mut n: usize,
    statement: &G,
) -> ProofResult<()>
where
    G: CurveGroup,
    for<'a> VerifierState<'a, DefaultHash, u8>:
        VerifierGroupTranscript<G> + VerifierFieldTranscript<G::ScalarField>,
{
    let mut g = generators.0.to_vec();
    let mut h = generators.1.to_vec();
    let u = *generators.2;
    let mut statement = *statement;

    while n != 1 {
        let mut lr_buf = [G::default(); 2];
        verifier.read_message_points(Label::new("round"), &mut lr_buf)?;
        let [left, right] = lr_buf;

        n /= 2;
        let (g_left, g_right) = g.split_at(n);
        let (h_left, h_right) = h.split_at(n);

        let mut x_buf = [G::ScalarField::default(); 1];
        verifier.read_message_scalars(Label::new("challenge"), &mut x_buf)?;
        let x = x_buf[0];
        let x_inv = x.inverse().expect("Challenge inverse failed");

        g = fold_generators(g_left, g_right, &x_inv, &x);
        h = fold_generators(h_left, h_right, &x, &x_inv);
        statement = statement + left * x.square() + right * x_inv.square();
    }

    let mut ab_buf = [G::ScalarField::default(); 2];
    verifier.read_message_scalars(Label::new("final"), &mut ab_buf)?;
    let [a, b] = ab_buf;

    let c = a * b;
    if (g[0] * a + h[0] * b + u * c - statement).is_zero() {
        Ok(())
    } else {
        Err(ProofError::InvalidProof)
    }
}

fn fold_generators<A: AffineRepr>(
    a: &[A],
    b: &[A],
    x: &A::ScalarField,
    y: &A::ScalarField,
) -> Vec<A> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| (a * x + b * y).into_affine())
        .collect()
}

fn dot_prod<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b.iter()).map(|(&a, &b)| a * b).sum()
}

fn fold<F: Field>(a: &[F], b: &[F], x: &F, y: &F) -> Vec<F> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| a * x + b * y)
        .collect()
}

fn main() {
    use ark_curve25519::EdwardsProjective as G;
    use ark_std::UniformRand;

    type F = <G as PrimeGroup>::ScalarField;
    type GAffine = <G as CurveGroup>::Affine;

    // Vector size
    let size = 8;

    // Create interaction pattern
    let pattern = Arc::new(bulletproof_pattern::<G>(size).finalize());

    // Test vectors
    let a = (0..size).map(|x| F::from(x as u32)).collect::<Vec<_>>();
    let b = (0..size)
        .map(|x| F::from(x as u32 + 42))
        .collect::<Vec<_>>();
    let ab = dot_prod(&a, &b);

    // Generators
    let g = (0..a.len())
        .map(|_| GAffine::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let h = (0..b.len())
        .map(|_| GAffine::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let u = GAffine::rand(&mut OsRng);

    let generators = (&g[..], &h[..], &u);
    let statement = G::msm_unchecked(&g, &a) + G::msm_unchecked(&h, &b) + u * ab;
    let witness = (&a[..], &b[..]);

    // Create prover state
    let mut prover = ProverState::new((*pattern).clone(), OsRng);
    prover
        .begin_protocol(Label::new("bulletproof"))
        .message_points(Label::new("commitment"), &[statement])
        .ratchet();

    // Generate proof
    prove(&mut prover, generators, &statement, witness, 0).expect("Proving failed");

    prover.end_protocol(Label::new("bulletproof"));

    let proof = prover.finalize();

    println!(
        "Here's a bulletproof for {} elements ({} bytes)",
        size,
        proof.len()
    );

    // Create verifier state
    let mut commitment = [G::default(); 1];
    let mut verifier = VerifierState::new((*pattern).clone(), &proof);
    verifier
        .begin_protocol(Label::new("bulletproof"))
        .read_message_points(Label::new("commitment"), &mut commitment)
        .expect("Failed to read commitment");
    verifier.ratchet();

    // Verify proof
    verify(&mut verifier, generators, size, &commitment[0]).expect("Verification failed");

    verifier.end_protocol(Label::new("bulletproof"));

    verifier.finalize().expect("Finalize failed");

    println!("✓ Proof verified successfully");
}
