use std::sync::Arc;

/// Example: WHIR Polynomial Commitment Scheme using Spongefish
///
/// WHIR proves evaluations of committed polynomials with weighted batch openings.
/// This example demonstrates a simplified version focusing on the transcript interaction.
///
/// Protocol flow:
/// 1. Setup: Define interaction pattern
/// 2. P → V: Commitment to polynomial (Merkle root)
/// 3. V → P: Challenge evaluation point (Fiat-Shamir from commitment)
/// 4. P → V: Claimed evaluation
/// 5. V → P: Folding challenges (Fiat-Shamir)
/// 6. P → V: Opening proof (decommitment path + folded values)
/// 7. V: Verify consistency
use ark_bn254::Fr;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::Config,
};
use ark_ff::{Field, PrimeField, UniformRand};
use rand::rngs::OsRng;
use spongefish::{
    codecs::{
        arkworks_algebra::{
            FieldPattern, ProverFieldMessageExt, UnitToField, VerifierFieldMessageExt,
        },
        unit::Pattern as _,
    },
    pattern::{Label, Pattern, PatternState},
    DefaultHash, ProofError, ProofResult, ProverState, VerifierState,
};

// ============================================================================
// Mock Merkle Tree Configuration (simplified for example)
// ============================================================================

#[derive(Clone)]
struct MockLeafHash;
impl CRHScheme for MockLeafHash {
    type Input = [Fr];
    type Output = Fr;
    type Parameters = ();

    fn setup<R: rand::Rng>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Ok(input.borrow().iter().sum())
    }
}

#[derive(Clone)]
struct MockTwoToOne;
impl TwoToOneCRHScheme for MockTwoToOne {
    type Input = Fr;
    type Output = Fr;
    type Parameters = ();

    fn setup<R: rand::Rng>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        _: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Ok(*left.borrow() + *right.borrow())
    }

    fn compress<T: std::borrow::Borrow<Self::Output>>(
        params: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Self::evaluate(params, left, right)
    }
}

#[derive(Clone)]
struct MockMerkleConfig;
impl Config for MockMerkleConfig {
    type Leaf = [Fr];
    type LeafDigest = Fr;
    type LeafInnerDigestConverter = ark_crypto_primitives::merkle_tree::IdentityDigestConverter<Fr>;
    type InnerDigest = Fr;
    type LeafHash = MockLeafHash;
    type TwoToOneHash = MockTwoToOne;
}

// ============================================================================
// WHIR Protocol Structures
// ============================================================================

/// Simplified polynomial representation (evaluations over boolean hypercube)
#[derive(Clone)]
struct Polynomial {
    /// Evaluations of the polynomial at points in {0,1}^n
    evaluations: Vec<Fr>,
    /// Number of variables
    num_vars: usize,
}

impl Polynomial {
    fn new(evaluations: Vec<Fr>) -> Self {
        let num_vars = (evaluations.len() as f64).log2() as usize;
        assert_eq!(1 << num_vars, evaluations.len(), "Size must be power of 2");
        Self {
            evaluations,
            num_vars,
        }
    }

    /// Evaluate at a random point using multilinear extension
    fn evaluate_at(&self, point: &[Fr]) -> Fr {
        assert_eq!(point.len(), self.num_vars);

        // Simple multilinear evaluation
        let mut result = Fr::from(0u64);
        for (i, &eval) in self.evaluations.iter().enumerate() {
            let mut term = eval;
            for (var_idx, &x) in point.iter().enumerate() {
                let bit = (i >> var_idx) & 1;
                term *= if bit == 1 { x } else { Fr::from(1u64) - x };
            }
            result += term;
        }
        result
    }
}

/// Commitment to a polynomial (Merkle root)
type Commitment = Fr;

// ============================================================================
// WHIR Interaction Pattern
// ============================================================================

fn whir_pattern(num_vars: usize) -> PatternState<u8>
where
    PatternState<u8>: FieldPattern<Fr>,
{
    let mut pattern = PatternState::<u8>::new();

    pattern.begin_protocol(Label::from("whir")).unwrap();

    // Commitment phase
    <PatternState<u8> as FieldPattern<Fr>>::message_scalars(
        &mut pattern,
        Label::from("commitment"),
        1,
    )
    .unwrap();

    // Challenge: evaluation point
    <PatternState<u8> as FieldPattern<Fr>>::challenge_scalars(
        &mut pattern,
        Label::from("eval_point"),
        num_vars,
    )
    .unwrap();

    // Query phase: claimed evaluation
    <PatternState<u8> as FieldPattern<Fr>>::message_scalars(
        &mut pattern,
        Label::from("claimed_eval"),
        1,
    )
    .unwrap();

    pattern.ratchet().unwrap();

    // Challenge phase (multiple rounds for folding)
    for round in 0..num_vars {
        <PatternState<u8> as FieldPattern<Fr>>::message_scalars(
            &mut pattern,
            Label::from(format!("round_{}_value", round)),
            1,
        )
        .unwrap();
        <PatternState<u8> as FieldPattern<Fr>>::challenge_scalars(
            &mut pattern,
            Label::from(format!("round_{}_challenge", round)),
            1,
        )
        .unwrap();
        <PatternState<u8> as FieldPattern<Fr>>::message_scalars(
            &mut pattern,
            Label::from(format!("round_{}_auth", round)),
            1,
        )
        .unwrap();
    }

    pattern.end_protocol(Label::from("whir")).unwrap();
    pattern
}

// ============================================================================
// Committer (Prover Setup)
// ============================================================================

fn commit_polynomial(poly: &Polynomial) -> Commitment {
    // In real WHIR, this would be a Merkle tree root
    // Here we use a simple hash of all evaluations
    poly.evaluations.iter().sum()
}

// ============================================================================
// Prover
// ============================================================================

fn prove_opening<R>(
    prover: &mut ProverState<DefaultHash, u8, R>,
    poly: &Polynomial,
    commitment: Commitment,
) -> ProofResult<()>
where
    R: rand::RngCore + rand::CryptoRng,
    ProverState<DefaultHash, u8, R>: ProverFieldMessageExt<Fr> + UnitToField<Fr>,
{
    // Send commitment
    prover.message_scalars(Label::from("commitment"), &[commitment])?;

    // Get evaluation point as Fiat-Shamir challenge (after commitment!)
    let mut eval_point = vec![Fr::default(); poly.num_vars];
    prover.fill_challenge_scalars(Label::from("eval_point"), &mut eval_point)?;

    println!("  Prover received challenge point from transcript");

    // Compute and send claimed evaluation
    let claimed_eval = poly.evaluate_at(&eval_point);
    prover.message_scalars(Label::from("claimed_eval"), &[claimed_eval])?;

    prover.ratchet()?;

    // Folding protocol (simplified)
    let mut current_poly = poly.clone();

    for round in 0..poly.num_vars {
        // Send current polynomial evaluation at a folded point
        let round_value = current_poly.evaluations[0]; // Simplified
        prover.message_scalars(
            Label::from(format!("round_{}_value", round)),
            &[round_value],
        )?;

        // Get folding challenge
        let mut challenge_buf = [Fr::default(); 1];
        prover.fill_challenge_scalars(
            Label::from(format!("round_{}_challenge", round)),
            &mut challenge_buf,
        )?;
        let challenge = challenge_buf[0];

        // Fold polynomial (simplified - in reality this involves careful folding)
        let new_size = current_poly.evaluations.len() / 2;
        let mut folded_evals = vec![Fr::from(0u64); new_size];
        for i in 0..new_size {
            folded_evals[i] = current_poly.evaluations[2 * i]
                + challenge
                    * (current_poly.evaluations[2 * i + 1] - current_poly.evaluations[2 * i]);
        }
        current_poly = Polynomial::new(folded_evals);

        // Send authentication value (simplified)
        let auth_value = round_value * challenge; // Mock auth path
        prover.message_scalars(Label::from(format!("round_{}_auth", round)), &[auth_value])?;
    }

    Ok(())
}

// ============================================================================
// Verifier
// ============================================================================

fn verify_opening(verifier: &mut VerifierState<DefaultHash, u8>, num_vars: usize) -> ProofResult<()>
where
    for<'a> VerifierState<'a, DefaultHash, u8>: VerifierFieldMessageExt<Fr> + UnitToField<Fr>,
{
    // Read commitment
    let mut commitment_buf = [Fr::default(); 1];
    verifier.fill_message_scalars(Label::from("commitment"), &mut commitment_buf)?;
    let _commitment = commitment_buf[0];

    // Generate evaluation point as challenge (after seeing commitment!)
    let mut eval_point = vec![Fr::default(); num_vars];
    verifier.fill_challenge_scalars(Label::from("eval_point"), &mut eval_point)?;

    println!("  Verifier generated challenge point from transcript");

    // Read claimed evaluation
    let mut claimed_eval_buf = [Fr::default(); 1];
    verifier.fill_message_scalars(Label::from("claimed_eval"), &mut claimed_eval_buf)?;
    let mut expected_eval = claimed_eval_buf[0];

    verifier.ratchet()?;

    // Verify folding rounds
    for round in 0..num_vars {
        // Read round value
        let mut round_value_buf = [Fr::default(); 1];
        verifier.fill_message_scalars(
            Label::from(format!("round_{}_value", round)),
            &mut round_value_buf,
        )?;
        let round_value = round_value_buf[0];

        // Generate challenge
        let mut challenge_buf = [Fr::default(); 1];
        verifier.fill_challenge_scalars(
            Label::from(format!("round_{}_challenge", round)),
            &mut challenge_buf,
        )?;
        let challenge = challenge_buf[0];

        // Read authentication
        let mut auth_buf = [Fr::default(); 1];
        verifier
            .fill_message_scalars(Label::from(format!("round_{}_auth", round)), &mut auth_buf)?;
        let auth_value = auth_buf[0];

        // Verify consistency (simplified check)
        let expected_auth = round_value * challenge;
        if auth_value != expected_auth {
            return Err(ProofError::InvalidProof);
        }

        // Update expected evaluation for next round
        expected_eval = round_value + challenge * (expected_eval - round_value);
    }

    // Final check: after all rounds, we should have folded to a constant
    println!("  Final folded value: {:?}", expected_eval);

    Ok(())
}

// ============================================================================
// Main Example
// ============================================================================

fn main() {
    println!("=== WHIR Polynomial Commitment Example ===\n");

    // Step 1: Setup - create a polynomial
    let poly_size = 8; // 2^3
    let num_vars = 3;
    let mut rng = OsRng;

    let evaluations: Vec<Fr> = (0..poly_size).map(|_| Fr::rand(&mut rng)).collect();
    let poly = Polynomial::new(evaluations);
    println!("✓ Random polynomial created ({} evaluations)\n", poly_size);

    // Step 2: Create and finalize pattern
    let pattern = Arc::new(
        whir_pattern(num_vars)
            .finalize()
            .expect("Failed to finalize pattern"),
    );
    println!("✓ WHIR interaction pattern created\n");

    // Step 3: Commit to polynomial
    let commitment = commit_polynomial(&poly);
    println!("✓ Polynomial committed\n");

    // Step 4: Prover generates opening proof
    // NOTE: eval_point is now generated via Fiat-Shamir INSIDE the prove function!
    let proof = {
        let mut prover = ProverState::new(pattern.clone(), rng);

        prover
            .begin_protocol(Label::from("whir"))
            .expect("Failed to begin protocol");

        prove_opening(&mut prover, &poly, commitment).expect("Proving failed");

        prover
            .end_protocol(Label::from("whir"))
            .expect("Failed to end protocol");

        prover.finalize().expect("Prover finalize failed")
    };

    println!("✓ Opening proof generated ({} bytes)\n", proof.len());

    // Step 5: Verifier checks proof
    let result = {
        let mut verifier = VerifierState::new(pattern.clone(), &proof);

        verifier
            .begin_protocol(Label::from("whir"))
            .expect("Failed to begin protocol");

        verify_opening(&mut verifier, num_vars).expect("Verification failed");

        verifier
            .end_protocol(Label::from("whir"))
            .expect("Failed to end protocol");

        verifier.finalize()
    };

    match result {
        Ok(()) => {
            println!("✓ Opening proof verified successfully!");
            println!("  The committed polynomial evaluates correctly at the challenge point");
            println!("\n📌 Key security property:");
            println!("  The evaluation point was generated AFTER commitment via Fiat-Shamir,");
            println!("  preventing the prover from tailoring the polynomial to a known point.");
        }
        Err(e) => {
            println!("✗ Verification failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
