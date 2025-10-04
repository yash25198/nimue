//! This module provides implementations for encoding field elements into
//! transcript patterns. It is designed to be used with pattern-based transcripts
//! to define interactions between a prover and verifier over finite fields.

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};

use crate::{
    codecs::unit::Pattern,
    transcript::{Length, Pattern as TranscriptPattern, PatternState},
    Unit,
};

/// Bytes needed to unambiguously represent a field element with the given modulus bit size
const fn bytes_modp(modulus_bit_size: u32) -> usize {
    // This ensures we don't exceed the field modulus when packing bytes
    let safe_bits = modulus_bit_size.saturating_sub(1);
    ((safe_bits + 7) / 8) as usize
}

/// Bytes needed in order to obtain a uniformly distributed random element of `modulus_bits`
const fn bytes_uniform_modp(modulus_bit_size: u32) -> usize {
    ((modulus_bit_size + 128 + 7) / 8) as usize
}

/// A trait for adding field-specific information to a pattern state.
/// This extends the basic pattern with operations specific to finite field elements.
pub trait FieldPatternBuilder<F> {
    fn add_scalars(&mut self, count: usize, label: &'static str);
    fn add_challenge_scalars(&mut self, count: usize, label: &'static str);
}

impl<F, U> FieldPatternBuilder<F> for PatternState<U>
where
    F: Field,
    U: Unit,
{
    fn add_scalars(&mut self, count: usize, label: &'static str) {
        // For byte-based patterns, calculate total bytes needed
        self.begin_message::<F>(label, Length::Fixed(count));
        let total_units = count
            * F::extension_degree() as usize
            * bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        self.message_units("add_scalars", total_units);
        self.end_message::<F>(label, Length::Fixed(count));
    }

    fn add_challenge_scalars(&mut self, count: usize, label: &'static str) {
        self.begin_challenge::<F>(label, Length::Fixed(count));
        let total_units = count
            * F::extension_degree() as usize
            * bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        self.challenge_units("add_challenge_scalars", total_units);
        self.end_challenge::<F>(label, Length::Fixed(count));
    }
}

/// A trait for adding group-specific information to a pattern state.
/// This extends the basic pattern with operations specific to elliptic curve group elements.
pub trait GroupPatternBuilder<G: CurveGroup> {
    /// Add group elements that the prover will send to the verifier.
    fn add_group_elements(&mut self, count: usize, label: &'static str);
}

impl<G, U> GroupPatternBuilder<G> for PatternState<U>
where
    G: CurveGroup,
    U: Unit,
{
    fn add_group_elements(&mut self, count: usize, label: &'static str) {
        self.begin_message::<G>(label, Length::Fixed(count));
        let total_units = count * G::default().compressed_size();
        self.message_units("add_group_elements", total_units);
        self.end_message::<G>(label, Length::Fixed(count));
    }
}

pub trait BytesPatternBuilder<F> {
    // Add public bytes that the prover will send to the verifier.
    fn add_public_bytes(&mut self, count: usize, label: &'static str);
    fn add_challenge_public_bytes(&mut self, count: usize, label: &'static str);
    fn add_hint_public_bytes(&mut self, count: usize, label: &'static str);
}

impl<F, U> BytesPatternBuilder<F> for PatternState<U>
where
    F: PrimeField,
    U: Unit,
{
    fn add_public_bytes(&mut self, count: usize, label: &'static str) {
        self.begin_message::<F>(label, Length::Fixed(count));
        self.message_units("add_public_bytes", count);
        self.end_message::<F>(label, Length::Fixed(count));
    }

    fn add_challenge_public_bytes(&mut self, count: usize, label: &'static str) {
        self.begin_challenge::<F>(label, Length::Fixed(count));
        self.challenge_units("add_challenge_public_bytes", count);
        self.end_challenge::<F>(label, Length::Fixed(count));
    }

    fn add_hint_public_bytes(&mut self, count: usize, label: &'static str) {
        self.begin_hint::<F>(label, Length::Fixed(count));
        self.hint_bytes("add_hint_public_bytes", count);
        self.end_hint::<F>(label, Length::Fixed(count));
    }
}

// #[cfg(test)]
// mod tests {
//     use ark_bls12_381::{Fq2, Fr};
//     use ark_curve25519::EdwardsProjective as Curve;
//     use ark_ff::{
//         AdditiveGroup, Fp2, Fp2Config, Fp4, Fp4Config, Fp64, MontBackend, MontConfig, MontFp,
//         PrimeField,
//     };

//     use super::*;
//     use crate::{transcript::PatternState, ProverState, VerifierState};

//     /// Configuration for the BabyBear field (modulus = 2^31 - 2^27 + 1, generator = 21).
//     #[derive(MontConfig)]
//     #[modulus = "2013265921"]
//     #[generator = "21"]
//     pub struct BabybearConfig;

//     /// Base field type using the BabyBear configuration.
//     pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

//     #[test]
//     fn test_arkworks_field_pattern_builder() {
//         let pattern = FieldPatternBuilder::<Fr>::challenge_scalars(
//             PatternState::new().add_scalars(3, "commitments"),
//             1,
//             "challenge",
//         )
//         .finalize();

//         let mut prover: ProverState = pattern.clone().into();
//         let mut verifier: VerifierState = VerifierState::new(pattern.into(), &[]);

//         // Test sending field elements
//         let field_elements = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
//         prover.send(&field_elements).unwrap();
//         let received: Vec<Fr> = verifier.receive().unwrap();
//         assert_eq!(field_elements, received);

//         // Test challenge
//         let challenge: Fr = verifier.challenge().unwrap();
//         let prover_challenge: Fr = prover.challenge().unwrap();
//         assert_eq!(challenge, prover_challenge);

//         prover.finalize().unwrap();
//         verifier.finalize().unwrap();
//     }

//     #[test]
//     fn test_arkworks_group_elements() {
//         use ark_bls12_381::G1Projective;
//         use ark_ec::Group;

//         let pattern = PatternState::new()
//             .add_group_elements::<G1Projective>(2, "group_elements")
//             .challenge_scalars::<Fr>(1, "challenge")
//             .finalize();

//         let mut prover: ProverState = pattern.clone().into();
//         let mut verifier: VerifierState = VerifierState::new(pattern.into(), &[]);

//         // Test sending group elements
//         let group_elements = vec![
//             G1Projective::generator() * Fr::from(42u64),
//             G1Projective::generator() * Fr::from(123u64),
//         ];

//         prover.send(&group_elements).unwrap();
//         let received: Vec<G1Projective> = verifier.receive().unwrap();
//         assert_eq!(group_elements, received);

//         // Test challenge
//         let challenge: Fr = verifier.challenge().unwrap();
//         let prover_challenge: Fr = prover.challenge().unwrap();
//         assert_eq!(challenge, prover_challenge);

//         prover.finalize().unwrap();
//         verifier.finalize().unwrap();
//     }

//     #[test]
//     fn test_pattern_convenience_methods() {
//         use ark_bls12_381::G1Projective;

//         let pattern = PatternState::new()
//             .prover_scalars::<Fr>("x_values", 3)
//             .verifier_scalar_challenges::<Fr>("alpha", 1)
//             .prover_group_elements::<G1Projective>("commitments", 2)
//             .finalize();

//         let mut prover: ProverState = pattern.clone().into();
//         let mut verifier: VerifierState = VerifierState::new(pattern.into(), &[]);

//         // Test the pattern works correctly
//         let field_elements = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
//         prover.send(&field_elements).unwrap();
//         let received: Vec<Fr> = verifier.receive().unwrap();
//         assert_eq!(field_elements, received);

//         prover.finalize().unwrap();
//         verifier.finalize().unwrap();
//     }

//     #[test]
//     fn test_field_vs_unit_equivalence() {
//         type F = Fr;

//         // Test that field patterns calculate correct unit counts
//         let scalar_units =
//             F::extension_degree() as usize * bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
//         let challenge_units = F::extension_degree() as usize
//             * bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);

//         let field_pattern = PatternState::new()
//             .add_scalars::<F>(1, "scalar")
//             .challenge_scalars::<F>(1, "challenge")
//             .finalize();

//         let unit_pattern = PatternState::new()
//             .message_units("scalar", scalar_units)
//             .challenge_units("challenge", challenge_units)
//             .finalize();

//         // Both patterns should be equivalent
//         assert_eq!(field_pattern, unit_pattern);
//     }

//     #[test]
//     fn test_group_vs_unit_equivalence() {
//         type G = Curve;

//         let group_units = G::default().compressed_size();

//         let group_pattern = PatternState::new()
//             .add_group_elements::<G>(1, "point")
//             .finalize();

//         let unit_pattern = PatternState::new()
//             .message_units("point", group_units)
//             .finalize();

//         // Both patterns should be equivalent
//         assert_eq!(group_pattern, unit_pattern);
//     }

//     #[test]
//     fn test_mixed_field_and_group_pattern() {
//         use ark_bls12_381::G1Projective;

//         let pattern = PatternState::new()
//             .prover_group_elements::<G1Projective>("commitment", 1)
//             .verifier_scalar_challenges::<Fr>("challenge", 1)
//             .prover_scalars::<Fr>("response", 1)
//             .finalize();

//         let mut prover: ProverState = pattern.clone().into();
//         let mut verifier: VerifierState = VerifierState::new(pattern.into(), &[]);

//         // Test group element
//         let commitment = vec![G1Projective::generator()];
//         prover.send(&commitment).unwrap();
//         let received_commitment: Vec<G1Projective> = verifier.receive().unwrap();
//         assert_eq!(commitment, received_commitment);

//         // Test challenge
//         let challenge: Fr = verifier.challenge().unwrap();
//         let prover_challenge: Fr = prover.challenge().unwrap();
//         assert_eq!(challenge, prover_challenge);

//         // Test response
//         let response = vec![Fr::from(42u64)];
//         prover.send(&response).unwrap();
//         let received_response: Vec<Fr> = verifier.receive().unwrap();
//         assert_eq!(response, received_response);

//         prover.finalize().unwrap();
//         verifier.finalize().unwrap();
//     }
// }
