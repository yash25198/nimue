use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Fp, FpConfig,PrimeField};
use rand::{CryptoRng, RngCore};
use super::{CommonFieldToUnit, CommonGroupToUnit, FieldToUnitSerialize, GroupToUnitSerialize,UnitToBytes,UnitToField};
use crate::codecs::bytes_uniform_modp;
use crate::pattern::Length;
use crate::{
    pattern::{Label, Kind, PatternError,Pattern}, 
    BytesToUnitSerialize, CommonUnitToBytes, DuplexSpongeInterface, ProverState, UnitTranscript
};

// ============================================================================
// PROVER IMPLEMENTATIONS FOR u8 (byte-based operations)
// ============================================================================

impl<F, H, R> FieldToUnitSerialize<F> for ProverState<H, u8, R>
where
    F: Field,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_scalars(&mut self, _label: Label, _kind: Kind, input: &[F]) -> Result<&mut Self, PatternError> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Serialize to bytes
        let mut buf = Vec::new();
        for f in input {
            f.serialize_compressed(&mut buf).expect("Serialization failed");
        }
        
        // Add bytes directly - this matches the pattern's inner message_bytes call
        self.add_bytes(Label::BASE_FIELD_COEFFICIENTS_LITTLE_ENDIAN, &buf)?;
        
        Ok(self)
    }
}

impl<G, H, R> GroupToUnitSerialize<G> for ProverState<H, u8, R>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_points(&mut self, _label: Label, _kind: Kind, input: &[G]) -> Result<&mut Self, PatternError> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Serialize to bytes
        let mut buf = Vec::new();
        for p in input {
            p.serialize_compressed(&mut buf).expect("Serialization failed");
        }
        
        // Add bytes directly - this matches the pattern's inner message_bytes call
        self.add_bytes(Label::SERIALIZED_GROUP, &buf)?;
        
        Ok(self)
    }
}

impl<F, H, R> CommonFieldToUnit<F> for ProverState<H, u8, R>
where
    F: Field,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> Result<Self::Repr, PatternError> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf).expect("Serialization failed");
        }
        self.public_bytes(Label::PUBLIC, &buf)?;
        Ok(buf)
    }
}

impl<G, H, R> CommonGroupToUnit<G> for ProverState<H, u8, R>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    type Repr = Vec<u8>;

    fn public_points(&mut self, label: Label, input: &[G]) -> Result<Self::Repr, PatternError> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf).expect("Serialization failed");
        }
        self.public_bytes(label, &buf)?;
        Ok(buf)
    }
}

// ============================================================================
// PROVER IMPLEMENTATIONS FOR Fp<C, N> (field-native operations)
// ============================================================================

impl<F, C, H, R, const N: usize> FieldToUnitSerialize<F> for ProverState<H, Fp<C, N>, R>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
{
    fn add_scalars(&mut self, _label: Label, _kind: Kind, input: &[F]) -> Result<&mut Self, PatternError> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Flatten to base field elements
        let flattened: Vec<_> = input
            .iter()
            .flat_map(Field::to_base_prime_field_elements)
            .collect();
        
        // Add units directly - this matches the pattern's inner message_units call
        self.add_units(Label::BASE_FIELD_COEFFICIENTS, &flattened)?;
        
        Ok(self)
    }
}

// ============================================================================
// SHORT WEIERSTRASS CURVE IMPLEMENTATION
// ============================================================================

impl<P, H, R, C, const N: usize> GroupToUnitSerialize<ark_ec::short_weierstrass::Projective<P>> 
    for ProverState<H, Fp<C, N>, R>
where
    P: ark_ec::short_weierstrass::SWCurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    C: FpConfig<N>,
{
    fn add_points(
        &mut self, 
        _label: Label, 
        _kind: Kind, 
        input: &[ark_ec::short_weierstrass::Projective<P>]
    ) -> Result<&mut Self, PatternError> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Extract coordinates
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        
        // Add units directly - this matches the pattern's inner message_units call
        self.add_units(Label::COORDINATES, &coords)?;
        
        Ok(self)
    }
}

// ============================================================================
// TWISTED EDWARDS CURVE IMPLEMENTATION
// ============================================================================

impl<P, H, R, C, const N: usize> GroupToUnitSerialize<ark_ec::twisted_edwards::Projective<P>> 
    for ProverState<H, Fp<C, N>, R>
where
    P: ark_ec::twisted_edwards::TECurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    C: FpConfig<N>,
{
    fn add_points(
        &mut self, 
        _label: Label, 
        _kind: Kind, 
        input: &[ark_ec::twisted_edwards::Projective<P>]
    ) -> Result<&mut Self, PatternError> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Extract coordinates
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        
        // Add units directly - this matches the pattern's inner message_units call
        self.add_units(Label::COORDINATES, &coords)?;
        
        Ok(self)
    }
}

impl<F, H, R, C, const N: usize> CommonFieldToUnit<F> for ProverState<H, Fp<C, N>, R>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    C: FpConfig<N>,
{
    type Repr = ();

    fn public_scalars(&mut self, input: &[F]) -> Result<Self::Repr, PatternError> {
        let flattened: Vec<_> = input
            .iter()
            .flat_map(Field::to_base_prime_field_elements)
            .collect();
        self.public_units(Label::PUBLIC, &flattened)?;
        Ok(())
    }
}

// ============================================================================
// SHORT WEIERSTRASS CURVE - COMMON IMPLEMENTATION FOR Fp<C, N>
// ============================================================================

impl<P, H, R, C, const N: usize> CommonGroupToUnit<ark_ec::short_weierstrass::Projective<P>> 
    for ProverState<H, Fp<C, N>, R>
where
    P: ark_ec::short_weierstrass::SWCurveConfig<BaseField = Fp<C, N>>,
    C: FpConfig<N>,
    R: RngCore + CryptoRng,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    type Repr = ();

    fn public_points(
        &mut self, 
        label: Label, 
        input: &[ark_ec::short_weierstrass::Projective<P>]
    ) -> Result<Self::Repr, PatternError> {
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        self.public_units(label, &coords)?;
        Ok(())
    }
}

// ============================================================================
// TWISTED EDWARDS CURVE - COMMON IMPLEMENTATION FOR Fp<C, N>
// ============================================================================

impl<P, H, R, C, const N: usize> CommonGroupToUnit<ark_ec::twisted_edwards::Projective<P>> 
    for ProverState<H, Fp<C, N>, R>
where
    P: ark_ec::twisted_edwards::TECurveConfig<BaseField = Fp<C, N>>,
    C: FpConfig<N>,
    R: RngCore + CryptoRng,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    type Repr = ();

    fn public_points(
        &mut self, 
        label: Label, 
        input: &[ark_ec::twisted_edwards::Projective<P>]
    ) -> Result<Self::Repr, PatternError> {
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        self.public_units(label, &coords)?;
        Ok(())
    }
}

impl<H, R, C, const N: usize> CommonUnitToBytes for ProverState<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: CryptoRng + RngCore,
{
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError> {
        for &byte in input {
            self.public_units(label, &[Fp::from(byte)])?;
        }
        Ok(self)
    }
}


impl<F, H, R> UnitToField<F> for ProverState<H, u8, R> 
where
    F: Field,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn fill_challenge_scalars(&mut self, label: Label, output: &mut [F]) -> Result<&mut Self, PatternError> {
        let base_field_size = bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let ext_degree = F::extension_degree() as usize;
        let element_size = ext_degree * base_field_size;
        let total_bytes = output.len() * element_size;
        let mut buf = vec![0u8; total_bytes];

        self.pattern.begin_challenge::<F>(label, Length::Fixed(output.len()))?;
        self.fill_challenge_bytes(Label::BASE_FIELD_COEFFICIENTS_LITTLE_ENDIAN, &mut buf)?;
        self.pattern.end_challenge::<F>(label, Length::Fixed(output.len()))?;

        // Convert bytes to field elements by chunking the buffer
        for (elem, chunk) in output.iter_mut().zip(buf.chunks_exact(element_size)) {
            *elem = F::from_base_prime_field_elems(
                chunk.chunks_exact(base_field_size)
                    .map(F::BasePrimeField::from_be_bytes_mod_order),
            )
            .expect("Could not convert bytes to field element");
        }
        
        Ok(self)
    }
}

impl<H, R, C, const N: usize> UnitToField<Fp<C, N>> for ProverState<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
{
    fn fill_challenge_scalars(&mut self, label: Label, output: &mut [Fp<C, N>]) -> Result<&mut Self, PatternError> {
        self.fill_challenge_units(label, output)
    }
}

// #[cfg(test)]
// mod tests {
//     use ark_bls12_381::Fr;
//     use ark_curve25519::EdwardsProjective;
//     use ark_ec::PrimeGroup;
//     use ark_ff::{Fp64, MontBackend, MontConfig, UniformRand};
//     use std::sync::Arc;
//     use ark_serialize::CanonicalSerialize;
//     use super::*;
//     use crate::{
//         codecs::{
//             arkworks_algebra::{
//                 FieldPattern, 
//                 FieldToUnitSerialize, 
//                 GroupPattern, 
//                 GroupToUnitSerialize,
//                 CommonFieldToUnit,
//                 CommonGroupToUnit,
//             },
//             bytes::Pattern as BytesPattern,
//             unit::Pattern as UnitPattern,
//         },
//         pattern::{PatternState, Pattern as _, Label, Interaction, Hierarchy, Kind, Length},
//         DefaultHash, 
//         ProverState,
//         VerifierState,
//         BytesToUnitSerialize,
//         BytesToUnitDeserialize,
//     };

//     type G = EdwardsProjective;

//     #[derive(MontConfig)]
//     #[modulus = "2013265921"]
//     #[generator = "21"]
//     pub struct BabybearConfig;

//     pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

//     #[test]
//     fn test_add_scalars() {
//         // Sample 3 random BabyBear field elements
//         let mut rng = ark_std::test_rng();
//         let (f0, f1, f2) = (
//             BabyBear::rand(&mut rng),
//             BabyBear::rand(&mut rng),
//             BabyBear::rand(&mut rng),
//         );

//         // Create a simple pattern without hierarchical structure
//         let pattern = Arc::new(PatternState::<u8>::new().finalize());

//         // Create prover state
//         let mut prover_state = ProverState::<DefaultHash>::new(Arc::clone(&pattern), rand::rngs::OsRng);

//         // Try to add the scalars - this should fail with the current pattern
//         let result = prover_state.add_scalars(Label::custom("com"), &[f0, f1, f2]);
        
//         // We expect this to fail because the pattern doesn't have the right interactions
//         assert!(result.is_err(), "Expected error due to pattern mismatch");
        
//         prover_state.abort().expect("Failed to abort");
//     }

//     #[test]
//     fn test_add_scalars_u8_unit() {
//         // Create a simple pattern without hierarchical structure
//         let pattern = PatternState::<u8>::new().finalize();

//         // Create prover state
//         let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);

//         // Use two deterministic values for test
//         let f0 = Fr::from(5u64);
//         let f1 = Fr::from(42u64);

//         // Try to add the scalars - this should fail with the current pattern
//         let result = prover.add_scalars(Label::custom("com"), &[f0, f1]);
        
//         // We expect this to fail because the pattern doesn't have the right interactions
//         assert!(result.is_err(), "Expected error due to pattern mismatch");
        
//         prover.abort().expect("Failed to abort");
//     }

//     #[test]
//     fn test_add_points_u8_unit() {
//         // Create a simple pattern without hierarchical structure
//         let pattern = PatternState::<u8>::new().finalize();

//         let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);
//         let point = G::generator();

//         // Try to add the point - this should fail with the current pattern
//         let result = prover.add_points(Label::custom("pt"), &[point]);
        
//         // We expect this to fail because the pattern doesn't have the right interactions
//         assert!(result.is_err(), "Expected error due to pattern mismatch");
        
//         prover.abort().expect("Failed to abort");
//     }

//     #[test]
//     fn test_add_points_fp_unit() {
//         // Create a simple pattern without hierarchical structure
//         let pattern = PatternState::<u8>::new().finalize();

//         let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);
//         let point = G::generator();

//         // Try to add the point - this should fail with the current pattern
//         let result = prover.add_points(Label::custom("pt"), &[point]);
        
//         // We expect this to fail because the pattern doesn't have the right interactions
//         assert!(result.is_err(), "Expected error due to pattern mismatch");
        
//         prover.abort().expect("Failed to abort");
//     }

//     #[test]
//     fn test_add_bytes_fp_unit() {
//         let input = b"hello world!";

//         // Create a simple pattern without hierarchical structure
//         let pattern = PatternState::<u8>::new().finalize();

//         let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);

//         // Try to add the bytes - this should fail with the current pattern
//         let result = prover.add_bytes(Label::custom("com"), input);
        
//         // We expect this to fail because the pattern doesn't have the right interactions
//         assert!(result.is_err(), "Expected error due to pattern mismatch");
        
//         prover.abort().expect("Failed to abort");
//     }

//     #[test]
//     fn test_fill_next_bytes_fp_unit() {
//         let input = b"secret-msg";

//         // Create a simple pattern without hierarchical structure
//         let pattern = Arc::new(PatternState::<u8>::new().finalize());
        
//         let mut prover = ProverState::<DefaultHash>::new(Arc::clone(&pattern), rand::rngs::OsRng);
        
//         // Try to add the bytes - this should fail with the current pattern
//         let result = prover.add_bytes(Label::custom("msg"), input);
        
//         // We expect this to fail because the pattern doesn't have the right interactions
//         assert!(result.is_err(), "Expected error due to pattern mismatch");
        
//         prover.abort().expect("Failed to abort");
//     }
// }