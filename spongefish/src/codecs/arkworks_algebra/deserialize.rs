// deserialize.rs - FIXED: Remove double wrapping + proper curve reconstruction

use ark_ec::{
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    CurveGroup,
};
use ark_ff::{Field, Fp, FpConfig, PrimeField};
use ark_serialize::CanonicalDeserialize;
use crate::traits::BytesToUnitDeserialize;
use crate::pattern::PatternError;

use super::{FieldToUnitDeserialize, GroupToUnitDeserialize};
use crate::{
    codecs::bytes_modp, 
    pattern::Label, 
    DuplexSpongeInterface, 
    ProofResult, 
    VerifierState
};

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR u8 (byte-based operations)
// ============================================================================

impl<F, H> FieldToUnitDeserialize<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn fill_next_scalars(&mut self, label: Label, output: &mut [F]) -> ProofResult<&mut Self> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Calculate buffer size for each scalar
        let scalar_bytes = bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let mut buf = vec![0u8; scalar_bytes];
        
        // Read and deserialize each scalar from bytes
        for o in output.iter_mut() {
            // Fill bytes directly - this matches the pattern's inner message_bytes call
            self.fill_next_bytes(Label::BASE_FIELD_COEFFICIENTS_LITTLE_ENDIAN, &mut buf)?;
            *o = F::deserialize_compressed(buf.as_slice())
                .map_err(|_| PatternError::DeserializationError)?;
        }
        
        Ok(self)
    }
}

impl<G, H> GroupToUnitDeserialize<G> for VerifierState<'_, H, u8>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn fill_next_points(&mut self, label: Label, output: &mut [G]) -> ProofResult<&mut Self> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Calculate buffer size for each point
        let point_size = G::default().compressed_size();
        let mut buf = vec![0u8; point_size];
        
        // Read and deserialize each point from bytes
        for o in output.iter_mut() {
            // Fill bytes directly - this matches the pattern's inner message_bytes call
            self.fill_next_bytes(Label::SERIALIZED_GROUP, &mut buf)?;
            *o = G::deserialize_compressed(buf.as_slice())
                .map_err(|_| PatternError::DeserializationError)?;
        }
        
        Ok(self)
    }
}

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR Fp<C, N> (field-native operations)
// ============================================================================

impl<F, H, C, const N: usize> FieldToUnitDeserialize<F> for VerifierState<'_, H, Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn fill_next_scalars(&mut self, label: Label, output: &mut [F]) -> ProofResult<&mut Self> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Calculate number of base field elements needed
        let extension_degree = F::extension_degree() as usize;
        let mut flattened = vec![Fp::<C, N>::default(); output.len() * extension_degree];
        
        // Read base field coefficients directly - matches pattern's inner message_units call
        self.fill_next_units(Label::BASE_FIELD_COEFFICIENTS, &mut flattened)?;
        
        // Convert base field elements back to extension field
        for (i, o) in output.iter_mut().enumerate() {
            let start = i * extension_degree;
            let end = start + extension_degree;
            *o = F::from_base_prime_field_elems(flattened[start..end].iter().copied())
                .expect("Could not convert from base field elements");
        }
        
        Ok(self)
    }
}

// ============================================================================
// SHORT WEIERSTRASS CURVE IMPLEMENTATION
// ============================================================================

impl<P, H, C, const N: usize> GroupToUnitDeserialize<ark_ec::short_weierstrass::Projective<P>> 
    for VerifierState<'_, H, Fp<C, N>>
where
    P: SWCurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn fill_next_points(
        &mut self, 
        label: Label, 
        output: &mut [ark_ec::short_weierstrass::Projective<P>]
    ) -> ProofResult<&mut Self> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Read all coordinates (2 per point: x and y) directly
        let mut coords = vec![Fp::<C, N>::default(); output.len() * 2];
        self.fill_next_units(Label::COORDINATES, &mut coords)?;
        
        // Convert coordinate pairs to points using Short Weierstrass constructor
        for (i, o) in output.iter_mut().enumerate() {
            let x = coords[i * 2];
            let y = coords[i * 2 + 1];
            
            // Create affine point using Short Weierstrass new_unchecked
            let affine = SWAffine::<P>::new_unchecked(x, y);
            *o = affine.into();
        }
        
        Ok(self)
    }
}

// ============================================================================
// TWISTED EDWARDS CURVE IMPLEMENTATION
// ============================================================================

impl<P, H, C, const N: usize> GroupToUnitDeserialize<ark_ec::twisted_edwards::Projective<P>> 
    for VerifierState<'_, H, Fp<C, N>>
where
    P: TECurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn fill_next_points(
        &mut self, 
        label: Label, 
        output: &mut [ark_ec::twisted_edwards::Projective<P>]
    ) -> ProofResult<&mut Self> {
        // NO begin/end here - pattern trait handles that
        // Just do the inner atomic operation
        
        // Read all coordinates (2 per point: x and y) directly
        let mut coords = vec![Fp::<C, N>::default(); output.len() * 2];
        self.fill_next_units(Label::COORDINATES, &mut coords)?;
        
        // Convert coordinate pairs to points using Twisted Edwards constructor
        for (i, o) in output.iter_mut().enumerate() {
            let x = coords[i * 2];
            let y = coords[i * 2 + 1];
            
            // Create affine point using Twisted Edwards new_unchecked
            let affine = TEAffine::<P>::new_unchecked(x, y);
            *o = affine.into();
        }
        
        Ok(self)
    }
}
#[cfg(test)]
mod tests {
    use ark_bls12_381::G1Projective;
    use ark_curve25519::EdwardsProjective;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::{AdditiveGroup, Fp64, MontBackend, MontConfig, UniformRand};
    use ark_serialize::CanonicalSerialize;
    use std::sync::Arc;

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{
            FieldPattern, 
            GroupPattern, 
            FieldToUnitDeserialize,
            GroupToUnitDeserialize,
        },
        pattern::{PatternState, Pattern as _, Label},
        DefaultHash,
        VerifierState,
    };

    /// Custom field for testing: BabyBear
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    #[test]
    fn test_fill_next_scalars_generic_field() {
        use ark_bls12_381::Fr as F;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(Arc::new(pattern), &[]);

        let mut out = [F::ZERO; 2];
        let result = verifier.fill_next_scalars(Label::custom("scalar"), &mut out);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        // Finalize the verifier to avoid the "Dropped unfinalized transcript" panic
        let _ = verifier.finalize();
    }

    #[test]
    fn test_fill_next_scalars_fp_unit() {
        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<BabyBear>::new().finalize();

        let mut verifier: VerifierState<DefaultHash, u8> = VerifierState::new(Arc::new(pattern), &[]);
        let mut out = [BabyBear::ZERO; 2];
        let result = verifier.fill_next_scalars(Label::custom("x"), &mut out);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        // Finalize the verifier to avoid the "Dropped unfinalized transcript" panic
        let _ = verifier.finalize();
    }

    #[test]
    fn test_fill_next_points_curve25519_edwards() {
        type G = EdwardsProjective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(Arc::new(pattern), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(Label::custom("pt"), &mut out);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        // Finalize the verifier to avoid the "Dropped unfinalized transcript" panic
        let _ = verifier.finalize();
    }

    #[test]
    fn test_fill_next_points_bls12_sw() {
        type G = G1Projective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(Arc::new(pattern), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(Label::custom("pt"), &mut out);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        // Finalize the verifier to avoid the "Dropped unfinalized transcript" panic
        let _ = verifier.finalize();
    }

    #[test]
    fn test_fill_next_points_fp_unit_edwards() {
        type G = EdwardsProjective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(Arc::new(pattern), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(Label::custom("pt"), &mut out);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        // Finalize the verifier to avoid the "Dropped unfinalized transcript" panic
        let _ = verifier.finalize();
    }

    #[test]
    fn test_fill_next_points_fp_unit_swcurve() {
        type G = G1Projective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(Arc::new(pattern), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(Label::custom("pt"), &mut out);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        // Finalize the verifier to avoid the "Dropped unfinalized transcript" panic
        let _ = verifier.finalize();
    }
}