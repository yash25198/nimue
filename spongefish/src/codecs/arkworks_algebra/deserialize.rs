use ark_ec::{
    short_weierstrass::{Affine as SWAffine, Projective as SWCurve, SWCurveConfig},
    twisted_edwards::{Affine as EdwardsAffine, Projective as EdwardsCurve, TECurveConfig},
    CurveGroup,
};
use ark_ff::{Field, Fp, FpConfig};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use super::{FieldToUnitDeserialize, GroupToUnitDeserialize};
use crate::{
    codecs::bytes_modp, pattern::{Hierarchy, Interaction, Kind, Label, Length, Pattern as _}, DuplexSpongeInterface, ProofResult, Unit, VerifierState
};

impl<F, H> FieldToUnitDeserialize<F> for VerifierState<'_, H>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn fill_next_scalars(&mut self, label: Label, output: &mut [F]) -> ProofResult<&mut Self> {
        // Begin the outer field message
        self.pattern.begin_message::<F>(label, Length::Fixed(output.len()))?;
        
        // Begin the inner bytes layer
        let scalar_bytes = bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let total_bytes = output.len() * scalar_bytes;
        self.pattern.begin_message::<u8>(Label::BYTES, Length::Fixed(total_bytes))?;
        
        // Process the atomic interaction
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Message,
            Label::UNITS,
            Length::Fixed(total_bytes),
        ))?;

        let point_size = F::default().compressed_size();
        let mut buf = vec![0u8; point_size];
        for o in output.iter_mut() {
            u8::read(&mut self.narg_string, &mut buf)?;
            *o = F::deserialize_compressed(buf.as_slice())?;
            self.duplex_sponge.absorb_unchecked(&buf);
        }
        
        // End the inner bytes layer
        self.pattern.end_message::<u8>(Label::BYTES, Length::Fixed(total_bytes))?;
        
        // End the outer field message
        self.pattern.end_message::<F>(label, Length::Fixed(output.len()))?;
        
        Ok(self)
    }
}

impl<G, H> GroupToUnitDeserialize<G> for VerifierState<'_, H>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn fill_next_points(&mut self, label: Label, output: &mut [G]) -> ProofResult<&mut Self> {
        // Begin the outer group message
        self.pattern.begin_message::<G>(label, Length::Fixed(output.len()))?;
        
        // Begin the inner bytes layer
        let point_size = G::default().compressed_size();
        let total_bytes = output.len() * point_size;
        self.pattern.begin_message::<u8>(Label::SERIALIZED_GROUP, Length::Fixed(total_bytes))?;
        
        // Process the atomic interaction
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Message,
            Label::UNITS,
            Length::Fixed(total_bytes),
        ))?;

        let mut buf = vec![0u8; point_size];
        for o in output.iter_mut() {
            u8::read(&mut self.narg_string, &mut buf)?;
            *o = G::deserialize_compressed(buf.as_slice())?;
            self.duplex_sponge.absorb_unchecked(&buf);
        }
        
        // End the inner bytes layer
        self.pattern.end_message::<u8>(Label::SERIALIZED_GROUP, Length::Fixed(total_bytes))?;
        
        // End the outer group message
        self.pattern.end_message::<G>(label, Length::Fixed(output.len()))?;
        
        Ok(self)
    }
}

impl<H, C, const N: usize> FieldToUnitDeserialize<Fp<C, N>> for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn fill_next_scalars(&mut self, label: Label, output: &mut [Fp<C, N>]) -> ProofResult<&mut Self> {
        // Begin the outer field message
        self.pattern.begin_message::<Fp<C, N>>(label, Length::Fixed(output.len()))?;
        
        // Use fill_next_units which now handles the inner hierarchy correctly
        self.fill_next_units(Label::BASE_FIELD_COEFFICIENTS, Kind::Message, output)?;
        
        // End the outer field message
        self.pattern.end_message::<Fp<C, N>>(label, Length::Fixed(output.len()))?;
        
        Ok(self)
    }
}

impl<P, H, C, const N: usize> GroupToUnitDeserialize<EdwardsCurve<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    P: TECurveConfig<BaseField = Fp<C, N>>,
{
    fn fill_next_points(&mut self, label: Label, output: &mut [EdwardsCurve<P>]) -> ProofResult<&mut Self> {
        self.fill_next_curve_points::<EdwardsCurve<P>, EdwardsAffine<P>>(label, output)
    }
}

impl<P, H, C, const N: usize> GroupToUnitDeserialize<SWCurve<P>> for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    P: SWCurveConfig<BaseField = Fp<C, N>>,
{
    fn fill_next_points(&mut self, label: Label, output: &mut [SWCurve<P>]) -> ProofResult<&mut Self> {
        self.fill_next_curve_points::<SWCurve<P>, SWAffine<P>>(label, output)
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