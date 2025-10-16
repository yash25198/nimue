use ark_ec::{
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    CurveGroup,
};
use ark_ff::{Field, Fp, FpConfig, PrimeField};

use super::{FieldToUnitDeserialize, GroupToUnitDeserialize};
use crate::{
    codecs::bytes_modp, pattern::{Label, PatternError}, traits::BytesToUnitDeserialize, DuplexSpongeInterface,
    ProofError, ProofResult, VerifierState,
};

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR u8 (unit-basedoperations)
// ============================================================================

impl<F, H> FieldToUnitDeserialize<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn fill_next_scalars(&mut self, output: &mut [F]) -> ProofResult<&mut Self> {
        // Calculate buffer size for ALL scalars
        let scalar_bytes = bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let total_bytes = output.len() * scalar_bytes;
        let mut buf = vec![0u8; total_bytes];

        // Read all bytes at once - this matches the pattern's single message_bytes call
        self.fill_next_bytes(Label::BaseFieldCoefficients, &mut buf);
        
        if self.has_error() {
            return Err(ProofError::PatternError(self.get_error().cloned().unwrap_or(PatternError::AlreadyFinalized).to_string()));
        }

        // Deserialize each scalar from its chunk
        for (i, o) in output.iter_mut().enumerate() {
            let start = i * scalar_bytes;
            let end = start + scalar_bytes;
            *o = F::deserialize_compressed(&buf[start..end])?;
        }

        Ok(self)
    }
}

impl<G, H> GroupToUnitDeserialize<G> for VerifierState<'_, H, u8>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn fill_next_points(&mut self, output: &mut [G]) -> ProofResult<&mut Self> {
        // Calculate buffer size for ALL points
        let point_size = G::default().compressed_size();
        let total_bytes = output.len() * point_size;
        let mut buf = vec![0u8; total_bytes];

        // Read all bytes at once - this matches the pattern's single message_bytes call
        self.fill_next_bytes(Label::SerializedGroup, &mut buf);
        
        if self.has_error() {
            return Err(ProofError::PatternError(self.get_error().cloned().unwrap_or(PatternError::AlreadyFinalized).to_string()));
        }

        // Deserialize each point from its chunk
        for (i, o) in output.iter_mut().enumerate() {
            let start = i * point_size;
            let end = start + point_size;
            *o = G::deserialize_compressed(&buf[start..end])?;
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
    fn fill_next_scalars(&mut self, output: &mut [F]) -> ProofResult<&mut Self> {
        // Calculate number of base field elements needed
        let extension_degree = F::extension_degree() as usize;
        let mut flattened = vec![Fp::<C, N>::default(); output.len() * extension_degree];

        // Read base field coefficients directly - matches pattern's inner message_units call
        self.fill_next_units(Label::BaseFieldCoefficients, &mut flattened);
        
        if self.has_error() {
            return Err(ProofError::PatternError(self.get_error().cloned().unwrap_or(PatternError::AlreadyFinalized).to_string()));
        }

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
        output: &mut [ark_ec::short_weierstrass::Projective<P>],
    ) -> ProofResult<&mut Self> {
        // Read all SerializedGroup (2 per point: x and y) directly
        let mut coords = vec![Fp::<C, N>::default(); output.len() * 2];
        self.fill_next_units(Label::SerializedGroup, &mut coords);
        
        if self.has_error() {
            return Err(ProofError::PatternError(self.get_error().cloned().unwrap_or(PatternError::AlreadyFinalized).to_string()));
        }

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
        output: &mut [ark_ec::twisted_edwards::Projective<P>],
    ) -> ProofResult<&mut Self> {
        // Read all SerializedGroup (2 per point: x and y) directly
        let mut coords = vec![Fp::<C, N>::default(); output.len() * 2];
        self.fill_next_units(Label::SerializedGroup, &mut coords);
        
        if self.has_error() {
            return Err(ProofError::PatternError(self.get_error().cloned().unwrap_or(PatternError::AlreadyFinalized).to_string()));
        }

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
    use std::sync::Arc;

    use ark_bls12_381::G1Projective;
    use ark_curve25519::EdwardsProjective;
    use ark_ff::{AdditiveGroup, Fp64, MontBackend, MontConfig};

    use crate::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, GroupToUnitDeserialize},
        pattern::PatternState,
        DefaultHash, VerifierState,
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
        let pattern = PatternState::new()
            .finalize()
            .expect("Failed to finalize pattern");

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &[]);

        let mut out = [F::ZERO; 2];
        let result = verifier.fill_next_scalars(&mut out);

        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");

        // Must call abort() to prevent drop panic
        let _ = verifier.abort();
    }

    #[test]
    fn test_fill_next_scalars_fp_unit() {
        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::new()
            .finalize()
            .expect("Failed to finalize pattern");

        let mut verifier: VerifierState<DefaultHash, u8> =
            VerifierState::new(pattern, &[]);
        let mut out = [BabyBear::ZERO; 2];
        let result = verifier.fill_next_scalars(&mut out);

        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");

        // Must call abort() to prevent drop panic
        let _ = verifier.abort();
    }

    #[test]
    fn test_fill_next_points_curve25519_edwards() {
        type G = EdwardsProjective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::new()
            .finalize()
            .expect("Failed to finalize pattern");

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(&mut out);

        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");

        // Must call abort() to prevent drop panic
        let _ = verifier.abort();
    }

    #[test]
    fn test_fill_next_points_bls12_sw() {
        type G = G1Projective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::new()
            .finalize()
            .expect("Failed to finalize pattern");

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(&mut out);

        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");

        // Must call abort() to prevent drop panic
        let _ = verifier.abort();
    }

    #[test]
    fn test_fill_next_points_fp_unit_edwards() {
        type G = EdwardsProjective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::new()
            .finalize()
            .expect("Failed to finalize pattern");

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(&mut out);

        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");

        // Must call abort() to prevent drop panic
        let _ = verifier.abort();
    }

    #[test]
    fn test_fill_next_points_fp_unit_swcurve() {
        type G = G1Projective;

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::new()
            .finalize()
            .expect("Failed to finalize pattern");

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &[]);
        let mut out = [G::ZERO];
        let result = verifier.fill_next_points(&mut out);

        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");

        // Must call abort() to prevent drop panic
        let _ = verifier.abort();
    }
}
