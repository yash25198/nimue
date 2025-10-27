use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Fp, FpConfig, PrimeField};
use rand::{CryptoRng, RngCore};

use super::traits::{FieldTranscript, GroupTranscript};
use crate::{
    codecs::bytes_uniform_modp, pattern::Label, ByteTranscript, DuplexSpongeInterface, ProverState,
};

// ============================================================================
// PROVER IMPLEMENTATIONS FOR u8
// ============================================================================

impl<F, H, R> FieldTranscript<F> for ProverState<H, u8, R>
where
    F: Field,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn message_scalars_unchecked(&mut self, input: &[F]) -> &mut Self {
        // Serialize to bytes - pre-allocate with estimated capacity
        // Typical compressed field element is 32 bytes
        let mut buf = Vec::with_capacity(input.len() * 64);
        for f in input {
            f.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }

        // Add bytes directly - this matches the pattern's inner message_bytes call
        self.message_bytes(Label::BaseFieldCoefficients, &buf)
    }

    fn message_public_scalars_unchecked(&mut self, input: &[F]) -> &mut Self {
        let mut buf = Vec::with_capacity(input.len() * 64);
        for f in input {
            f.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        // Only absorb into sponge, don't write to proof
        self.message_public_units(Label::BaseFieldCoefficients, &buf)
    }

    fn challenge_scalars_unchecked(&mut self, output: &mut [F]) -> &mut Self {
        let base_field_size = bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let ext_degree = F::extension_degree() as usize;
        let element_size = ext_degree * base_field_size;
        let total_bytes = output.len() * element_size;
        let mut buf = vec![0u8; total_bytes];
        self.challenge_bytes(Label::BaseFieldCoefficients, &mut buf);
        for (elem, chunk) in output.iter_mut().zip(buf.chunks_exact(element_size)) {
            *elem = F::from_base_prime_field_elems(
                chunk
                    .chunks_exact(base_field_size)
                    .map(F::BasePrimeField::from_be_bytes_mod_order),
            )
            .expect("Could not convert bytes to field element");
        }
        self
    }
}

impl<G, H, R> GroupTranscript<G> for ProverState<H, u8, R>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn message_points_unchecked(&mut self, input: &[G]) -> &mut Self {
        let mut buf = Vec::with_capacity(input.len() * 48);
        for p in input {
            p.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.message_bytes(Label::SerializedGroup, &buf)
    }

    fn message_public_points_unchecked(&mut self, input: &[G]) -> &mut Self {
        let mut buf = Vec::with_capacity(input.len() * 48);
        for p in input {
            p.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        // Only absorb into sponge, don't write to proof
        self.message_public_bytes(Label::SerializedGroup, &buf)
    }
}

// ============================================================================
// PROVER IMPLEMENTATIONS FOR Fp<C, N>
// ============================================================================

impl<F, C, H, R, const N: usize> FieldTranscript<F> for ProverState<H, Fp<C, N>, R>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
{
    fn message_scalars_unchecked(&mut self, input: &[F]) -> &mut Self {
        let flattened: Vec<_> = input
            .iter()
            .flat_map(Field::to_base_prime_field_elements)
            .collect();
        self.message_units(Label::BaseFieldCoefficients, &flattened)
    }

    fn message_public_scalars_unchecked(&mut self, input: &[F]) -> &mut Self {
        let flattened: Vec<_> = input
            .iter()
            .flat_map(Field::to_base_prime_field_elements)
            .collect();
        // Only absorb into sponge, don't write to proof
        self.message_public_units(Label::BaseFieldCoefficients, &flattened)
    }

    fn challenge_scalars_unchecked(&mut self, output: &mut [F]) -> &mut Self {
        let ext_degree = F::extension_degree() as usize;
        let total_elements = output.len() * ext_degree;
        let mut base_field_elements = vec![Fp::<C, N>::default(); total_elements];
        self.challenge_units(Label::BaseFieldCoefficients, &mut base_field_elements);
        for (i, elem) in output.iter_mut().enumerate() {
            let start = i * ext_degree;
            let end = start + ext_degree;
            *elem = F::from_base_prime_field_elems(base_field_elements[start..end].iter().copied())
                .expect("Could not construct extension field element");
        }
        self
    }
}

// ============================================================================
// SHORT WEIERSTRASS CURVE IMPLEMENTATION
// ============================================================================

impl<P, H, R, C, const N: usize> GroupTranscript<ark_ec::short_weierstrass::Projective<P>>
    for ProverState<H, Fp<C, N>, R>
where
    P: ark_ec::short_weierstrass::SWCurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    C: FpConfig<N>,
{
    fn message_points_unchecked(
        &mut self,
        input: &[ark_ec::short_weierstrass::Projective<P>],
    ) -> &mut Self {
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        self.message_units(Label::SerializedGroup, &coords)
    }

    fn message_public_points_unchecked(
        &mut self,
        input: &[ark_ec::short_weierstrass::Projective<P>],
    ) -> &mut Self {
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        // Only absorb into sponge, don't write to proof
        self.message_public_units(Label::SerializedGroup, &coords)
    }
}

// ============================================================================
// TWISTED EDWARDS CURVE IMPLEMENTATION
// ============================================================================

impl<P, H, R, C, const N: usize> GroupTranscript<ark_ec::twisted_edwards::Projective<P>>
    for ProverState<H, Fp<C, N>, R>
where
    P: ark_ec::twisted_edwards::TECurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    C: FpConfig<N>,
{
    fn message_points_unchecked(
        &mut self,
        input: &[ark_ec::twisted_edwards::Projective<P>],
    ) -> &mut Self {
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        self.message_units(Label::SerializedGroup, &coords)
    }

    fn message_public_points_unchecked(
        &mut self,
        input: &[ark_ec::twisted_edwards::Projective<P>],
    ) -> &mut Self {
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        // Only absorb into sponge, don't write to proof
        self.message_public_units(Label::SerializedGroup, &coords)
    }
}

#[cfg(test)]
mod tests {
    use ark_curve25519::EdwardsProjective as G;
    use ark_ec::PrimeGroup;
    use ark_ff::{Fp64, MontBackend, MontConfig, UniformRand};
    use ark_serialize::CanonicalSerialize;

    use super::*;
    use crate::{
        codecs::{
            arkworks_algebra::{FieldPattern, GroupPattern, VerifierFieldTranscript},
        },
        pattern::PatternState,
        DefaultHash,
    };

    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    #[test]
    fn test_message_scalars_with_pattern() {
        let mut rng = ark_std::test_rng();
        let scalars = [
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
        ];

        let mut pattern = PatternState::new();
        pattern.message_scalars::<BabyBear>(Label::custom("scalars"), 3);
        let pattern = pattern.finalize();

        let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
        prover.message_scalars(Label::custom("scalars"), &scalars);

        let mut expected_bytes = Vec::new();
        for scalar in &scalars {
            scalar.serialize_compressed(&mut expected_bytes).unwrap();
        }
        assert_eq!(prover.narg_string(), expected_bytes);

        prover.finalize();
    }

    #[test]
    fn test_message_points_u8_unit() {
        let point = G::generator();

        let mut pattern = PatternState::new();
        pattern.message_points::<G>(Label::custom("point"), 1);
        let pattern = pattern.finalize();

        let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
        prover.message_points(Label::custom("point"), &[point]);

        let mut expected = Vec::new();
        point.serialize_compressed(&mut expected).unwrap();
        assert_eq!(prover.narg_string(), expected);

        prover.finalize();
    }

    #[test]
    fn test_challenge_scalars() {
        let mut pattern = PatternState::new();
        pattern.challenge_scalars::<BabyBear>(Label::custom("challenge"), 2);
        let pattern = pattern.finalize();

        let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
        let mut output = [BabyBear::from(0); 2];
        prover.challenge_scalars(Label::custom("challenge"), &mut output);
        assert_ne!(output[0], BabyBear::from(0));

        prover.finalize();
    }

    #[test]
    #[should_panic(expected = "No more expected interactions in pattern")]
    fn test_add_scalars_pattern_mismatch() {
        let mut rng = ark_std::test_rng();
        let scalars = [
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
        ];

        // Empty pattern - should panic
        let pattern = PatternState::new().finalize();
        let mut prover = ProverState::<DefaultHash>::new(pattern, rand::rngs::OsRng);

        prover.message_scalars(Label::custom("scalars"), &scalars);
    }

    #[test]
    #[should_panic(expected = "No more expected interactions in pattern")]
    fn test_add_points_pattern_mismatch() {
        let point = G::generator();

        // Empty pattern - should panic
        let pattern = PatternState::new().finalize();
        let mut prover = ProverState::<DefaultHash>::new(pattern, rand::rngs::OsRng);

        prover.message_points(Label::custom("point"), &[point]);
    }

    #[test]
    #[should_panic(expected = "No more expected interactions in pattern")]
    fn test_add_bytes_pattern_mismatch() {
        let input = b"hello world!";

        // Empty pattern - should panic
        let pattern = PatternState::new().finalize();
        let mut prover = ProverState::<DefaultHash>::new(pattern, rand::rngs::OsRng);

        prover.message_bytes(Label::Bytes, input);
    }

    #[test]
    fn test_roundtrip_with_verifier() {
        let mut rng = ark_std::test_rng();
        let scalars = [BabyBear::rand(&mut rng), BabyBear::rand(&mut rng)];

        // Create pattern
        let mut pattern = PatternState::new();
        pattern.message_scalars::<BabyBear>(Label::custom("data"), 2);
        let pattern = pattern.finalize();

        // Prover
        let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
        prover.message_scalars(Label::custom("data"), &scalars);
        let proof = prover.finalize();

        // Verifier
        let mut verifier = crate::VerifierState::<DefaultHash>::new(pattern.clone(), &proof);
        let mut received = [BabyBear::from(0u64); 2];
        verifier
            .read_message_scalars(Label::custom("data"), &mut received)
            .unwrap();

        assert_eq!(scalars, received);
        verifier.finalize();
    }
}
