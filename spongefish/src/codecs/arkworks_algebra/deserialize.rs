use ark_ec::{
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    CurveGroup,
};
use ark_ff::{Field, Fp, FpConfig, PrimeField};

use super::traits::{VerifierFieldTranscript, VerifierGroupTranscript};
use crate::{
    pattern::Label, ByteTranscript, DuplexSpongeInterface, ProofError, ProofResult,
    VerifierByteTranscript, VerifierState,
};

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR u8 (unit-based operations)
// ============================================================================

impl<F, H> VerifierFieldTranscript<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn read_message_scalars_unchecked(&mut self, output: &mut [F]) -> ProofResult<&mut Self> {
        use crate::codecs::bytes_modp;

        let base_field_size = bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let ext_degree = F::extension_degree() as usize;
        let element_size = ext_degree * base_field_size;
        let total_bytes = output.len() * element_size;
        let mut buf = vec![0u8; total_bytes];

        // Read all bytes at once - this matches the pattern's single message_bytes call
        self.read_message_bytes(Label::BaseFieldCoefficients, &mut buf);

        // Deserialize each scalar from its chunk
        for (elem, chunk) in output.iter_mut().zip(buf.chunks_exact(element_size)) {
            *elem = F::deserialize_compressed(chunk)?;
        }

        Ok(self)
    }
}

impl<G, H> VerifierGroupTranscript<G> for VerifierState<'_, H, u8>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn read_message_points_unchecked(&mut self, output: &mut [G]) -> ProofResult<&mut Self> {
        // Calculate buffer size for ALL points
        let point_size = G::default().compressed_size();
        let total_bytes = output.len() * point_size;
        let mut buf = vec![0u8; total_bytes];

        // Read all bytes at once - this matches the pattern's single message_bytes call
        self.read_message_bytes(Label::SerializedGroup, &mut buf);

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

impl<F, H, C, const N: usize> VerifierFieldTranscript<F> for VerifierState<'_, H, Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn read_message_scalars_unchecked(&mut self, output: &mut [F]) -> ProofResult<&mut Self> {
        let extension_degree = F::extension_degree() as usize;
        let mut flattened = vec![Fp::<C, N>::default(); output.len() * extension_degree];

        self.read_message_units(Label::BaseFieldCoefficients, &mut flattened)?;

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

impl<P, H, C, const N: usize> VerifierGroupTranscript<ark_ec::short_weierstrass::Projective<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    P: SWCurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn read_message_points_unchecked(
        &mut self,
        output: &mut [ark_ec::short_weierstrass::Projective<P>],
    ) -> ProofResult<&mut Self> {
        // Read all SerializedGroup (2 per point: x and y) directly
        let mut coords = vec![Fp::<C, N>::default(); output.len() * 2];
        self.read_message_units(Label::SerializedGroup, &mut coords)?;

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

impl<P, H, C, const N: usize> VerifierGroupTranscript<ark_ec::twisted_edwards::Projective<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    P: TECurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn read_message_points_unchecked(
        &mut self,
        output: &mut [ark_ec::twisted_edwards::Projective<P>],
    ) -> ProofResult<&mut Self> {
        // Read all SerializedGroup (2 per point: x and y) directly
        let mut coords = vec![Fp::<C, N>::default(); output.len() * 2];
        self.read_message_units(Label::SerializedGroup, &mut coords)?;

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

    use ark_bls12_381::{Fr as BlsFr, G1Projective};
    use ark_curve25519::{EdwardsProjective, Fr as Curve25519Fr};
    use ark_ff::{Field, Fp64, MontBackend, MontConfig, UniformRand};

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{FieldPattern, FieldTranscript, GroupPattern, GroupTranscript},
        pattern::{Label, PatternState},
        DefaultHash, ProverState,
    };

    /// Custom field for testing: BabyBear
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    #[test]
    fn test_roundtrip_scalars_u8_unit() {
        let mut rng = ark_std::test_rng();
        let scalars = [BlsFr::rand(&mut rng), BlsFr::rand(&mut rng)];

        let mut pattern = PatternState::new();
        pattern.message_scalars::<BlsFr>(Label::custom("data"), 2);
        let pattern = Arc::new(pattern.finalize());

        let mut prover = ProverState::<DefaultHash>::new(Arc::clone(&pattern), rand::rngs::OsRng);
        prover.message_scalars(Label::custom("data"), &scalars);
        let proof = prover.finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern, &proof);
        let mut received = [BlsFr::from(0); 2];
        verifier
            .read_message_scalars(Label::custom("data"), &mut received)
            .expect("Failed to read scalars");
        verifier.finalize();

        assert_eq!(scalars, received);
    }

    #[test]
    fn test_roundtrip_points_edwards_u8_unit() {
        let mut rng = ark_std::test_rng();
        let points = [
            EdwardsProjective::rand(&mut rng),
            EdwardsProjective::rand(&mut rng),
        ];

        let mut pattern = PatternState::new();
        pattern.message_points::<EdwardsProjective>(Label::custom("commits"), 2);
        let pattern = Arc::new(pattern.finalize());

        let mut prover = ProverState::<DefaultHash>::new(Arc::clone(&pattern), rand::rngs::OsRng);
        prover.message_points(Label::custom("commits"), &points);
        let proof = prover.finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern, &proof);
        let mut received = [EdwardsProjective::default(); 2];
        verifier
            .read_message_points(Label::custom("commits"), &mut received)
            .expect("Failed to read points");
        verifier.finalize();

        assert_eq!(points, received);
    }

    #[test]
    fn test_roundtrip_points_sw_u8_unit() {
        let mut rng = ark_std::test_rng();
        let points = [G1Projective::rand(&mut rng), G1Projective::rand(&mut rng)];

        let mut pattern = PatternState::new();
        pattern.message_points::<G1Projective>(Label::custom("commits"), 2);
        let pattern = Arc::new(pattern.finalize());

        let mut prover = ProverState::<DefaultHash>::new(Arc::clone(&pattern), rand::rngs::OsRng);
        prover.message_points(Label::custom("commits"), &points);
        let proof = prover.finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern, &proof);
        let mut received = [G1Projective::default(); 2];
        verifier
            .read_message_points(Label::custom("commits"), &mut received)
            .expect("Failed to read points");
        verifier.finalize();

        assert_eq!(points, received);
    }
}
