use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Fp, FpConfig, PrimeField};

use super::traits::{FieldTranscript, GroupTranscript};
use crate::{
    codecs::bytes_uniform_modp,
    pattern::{labels, Label, Pattern,Length},
    ByteTranscript, DuplexSpongeInterface, VerifierState,
};

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR u8
// ============================================================================

impl<F, H> FieldTranscript<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn message_scalars_unchecked(&mut self, _input: &[F]) -> &mut Self {
        panic!("Verifier cannot send message_scalars");
    }

    fn message_public_scalars_unchecked(&mut self, input: &[F]) -> &mut Self {
        let mut buf = Vec::with_capacity(input.len() * 64);
        for f in input {
            f.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        // Pattern expects message_bytes structure: Begin Message -> Message units -> End Message
        // Manually create Message interaction and absorb (but don't read from proof)
        self.begin_message::<u8>(
        labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(buf.len()),
        );

        use crate::pattern::{Hierarchy, Interaction, Kind, Length};
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Message,
            labels::UNITS,
            Length::Fixed(buf.len()),
        ));
        self.duplex_sponge.absorb_unchecked(&buf);

        self.end_message::<u8>(
            labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(buf.len()),
        );
        self
    }

    fn challenge_scalars_unchecked(&mut self, output: &mut [F]) -> &mut Self {
        let base_field_size = bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let ext_degree = F::extension_degree() as usize;
        let element_size = ext_degree * base_field_size;
        let total_bytes = output.len() * element_size;
        let mut buf = vec![0u8; total_bytes];
        // Match the pattern structure: challenge_bytes creates begin_challenge + units + end_challenge
        self.begin_challenge::<u8>(
            labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(buf.len()),
        );
        self.challenge_units(labels::UNITS, &mut buf);
        self.end_challenge::<u8>(
            labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(buf.len()),
        );
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

impl<G, H> GroupTranscript<G> for VerifierState<'_, H, u8>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn message_points_unchecked(&mut self, _input: &[G]) -> &mut Self {
        panic!("Verifier cannot send message_points");
    }

    fn message_public_points_unchecked(&mut self, input: &[G]) -> &mut Self {
        let mut buf = Vec::with_capacity(input.len() * 48);
        for p in input {
            p.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        // Only absorb into sponge, don't read from proof
        self.message_public_bytes(labels::SERIALIZED_GROUP, &buf)
    }
}

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR Fp<C, N>
// ============================================================================

impl<F, H, C, const N: usize> FieldTranscript<F> for VerifierState<'_, H, Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn message_scalars_unchecked(&mut self, _input: &[F]) -> &mut Self {
        panic!("Verifier cannot send message_scalars");
    }

    fn message_public_scalars_unchecked(&mut self, input: &[F]) -> &mut Self {
        let flattened: Vec<_> = input
            .iter()
            .flat_map(Field::to_base_prime_field_elements)
            .collect();
        // Pattern expects message_bytes structure: Begin Message -> Message units -> End Message
        // Manually create Message interaction and absorb (but don't read from proof)
        self.begin_message::<Fp<C, N>>(
            labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(flattened.len()),
        );

        use crate::pattern::{Hierarchy, Interaction, Kind, Length};
        self.pattern.interact(Interaction::new::<Fp<C, N>>(
            Hierarchy::Atomic,
            Kind::Message,
            labels::UNITS,
            Length::Fixed(flattened.len()),
        ));
        self.duplex_sponge.absorb_unchecked(&flattened);

        self.end_message::<Fp<C, N>>(
            labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(flattened.len()),
        );
        self
    }

    fn challenge_scalars_unchecked(&mut self, output: &mut [F]) -> &mut Self {
        let ext_degree = F::extension_degree() as usize;
        let total_elements = output.len() * ext_degree;
        let mut base_field_elements = vec![Fp::<C, N>::default(); total_elements];
        // Match the pattern structure: challenge_bytes creates begin_challenge + units + end_challenge
        self.begin_challenge::<Fp<C, N>>(
            labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(base_field_elements.len()),
        );
        self.challenge_units(labels::UNITS, &mut base_field_elements);
        self.end_challenge::<Fp<C, N>>(
            labels::BASE_FIELD_COEFFICIENTS,
           Length::Fixed(base_field_elements.len()),
        );
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
// SHORT WEIERSTRASS CURVE IMPLEMENTATION FOR Fp<C, N>
// ============================================================================

impl<P, H, C, const N: usize> GroupTranscript<ark_ec::short_weierstrass::Projective<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    P: ark_ec::short_weierstrass::SWCurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn message_points_unchecked(
        &mut self,
        _input: &[ark_ec::short_weierstrass::Projective<P>],
    ) -> &mut Self {
        panic!("Verifier cannot send message_points");
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
        // Only absorb into sponge, don't read from proof
        self.message_public_units(labels::SERIALIZED_GROUP, &coords)
    }
}

// ============================================================================
// TWISTED EDWARDS CURVE IMPLEMENTATION FOR Fp<C, N>
// ============================================================================

impl<P, H, C, const N: usize> GroupTranscript<ark_ec::twisted_edwards::Projective<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    P: ark_ec::twisted_edwards::TECurveConfig<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn message_points_unchecked(
        &mut self,
        _input: &[ark_ec::twisted_edwards::Projective<P>],
    ) -> &mut Self {
        panic!("Verifier cannot send message_points");
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
        // Only absorb into sponge, don't read from proof
        self.message_public_units(labels::SERIALIZED_GROUP, &coords)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ec::{AdditiveGroup, PrimeGroup};
    use ark_ff::{Fp64, MontBackend, MontConfig, UniformRand};
    use ark_serialize::CanonicalSerialize;

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{
            FieldPattern, FieldTranscript, GroupPattern, VerifierFieldTranscript,
            VerifierGroupTranscript,
        },
        duplex_sponge::Unit,
        pattern::PatternState,
        DefaultHash, ProverState,
    };

    /// Configuration for the BabyBear field (modulus = 2^31 - 2^27 + 1, generator = 21).
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    /// Base field type using the BabyBear configuration.
    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;
    #[test]
    fn test_unit_write_read_babybear_roundtrip() {
        let mut rng = ark_std::test_rng();
        let values = [BabyBear::rand(&mut rng), BabyBear::rand(&mut rng)];
        let mut buf = Vec::new();

        // Write BabyBear field elements to the buffer using `Unit::write`
        BabyBear::write(&values, &mut buf).expect("write failed");

        // Read them back using `Unit::read`
        let mut decoded = [BabyBear::ZERO; 2];
        BabyBear::read(&mut buf.as_slice(), &mut decoded).expect("read failed");

        // Round-trip check
        assert_eq!(values, decoded, "Unit read/write roundtrip failed");
    }
    #[test]
    fn test_common_field_to_unit_bytes() {
        let mut rng = ark_std::test_rng();
        let values = [BabyBear::rand(&mut rng), BabyBear::rand(&mut rng)];
        let mut values2 = [BabyBear::rand(&mut rng), BabyBear::rand(&mut rng)];

        let mut pattern = PatternState::new();
        pattern.message_scalars::<BabyBear>(Label::from("tag"), 2);
        let pattern = pattern.finalize();

        let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
        let _ = prover.message_scalars(Label::from("tag"), &values);

        // Verify narg_string
        let mut expected_bytes = Vec::new();
        for v in &values {
            v.serialize_compressed(&mut expected_bytes).unwrap();
        }
        assert_eq!(prover.narg_string(), expected_bytes);

        let proof = prover.finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &proof);

        let _ = verifier
            .read_message_scalars(Label::from("tag"), &mut values2)
            .unwrap();
        verifier.finalize();
        assert_eq!(
            values2, values,
            "Serialized field elements should be deterministic"
        );
    }

    #[test]
    fn test_common_group_to_unit_curve_u8() {
        // Generator of the curve group
        let point = ark_curve25519::EdwardsProjective::generator();

        // Manual serialization for comparison
        let mut expected = Vec::new();
        point.serialize_compressed(&mut expected).unwrap();

        let mut pattern = PatternState::new();
        pattern.message_points::<ark_curve25519::EdwardsProjective>(Label::new("generator"), 1);
        let pattern = pattern.finalize();

        let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
        let _ = prover.message_points(Label::new("generator"), &[point]);

        // Verify narg_string matches expected serialization
        assert_eq!(prover.narg_string(), expected);

        let proof = prover.finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &proof);

        let mut out = [ark_curve25519::EdwardsProjective::ZERO];
        let _ = verifier
            .read_message_points(Label::new("generator"), &mut out)
            .unwrap();

        // Finalize the verifier to avoid panic on drop
        let _ = verifier.finalize();

        let mut actual = Vec::new();
        out[0].serialize_compressed(&mut actual).unwrap();

        assert_eq!(
            actual, expected,
            "Group element serialization should be deterministic"
        );

        // Curve25519 points serialize to 32 bytes in compressed format
        assert_eq!(
            expected.len(),
            32,
            "Curve25519 point should serialize to 32 bytes"
        );
    }

    #[test]
    fn test_unit_to_field_fill_challenge_scalars_u8() {
        // Create a pattern with a message scalar (not challenge)
        let mut pattern = PatternState::new();
        pattern.message_scalars::<BabyBear>(Label::from("tag"), 1);
        let pattern = pattern.finalize();

        let mut prover = ProverState::<DefaultHash, u8>::new(pattern.clone(), rand::rngs::OsRng);

        let mut out = [BabyBear::ONE; 1];
        prover.message_scalars(Label::from("tag"), &mut out);

        // Verify narg_string
        let mut expected = Vec::new();
        BabyBear::ONE.serialize_compressed(&mut expected).unwrap();
        assert_eq!(prover.narg_string(), expected);

        // Finalize the prover to get the proof
        let proof = prover.finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &proof);

        let mut out = [BabyBear::ZERO; 1];
        let _ = verifier
            .read_message_scalars(Label::from("tag"), &mut out)
            .unwrap();
        verifier.finalize();

        assert_eq!(out[0], BabyBear::ONE, "Scalar should be ONE");
    }

    #[test]
    fn test_unit_read_invalid_bytes() {
        // Provide malformed input that cannot be deserialized into a BabyBear field element
        let mut buf = &[0xff, 0xff][..];
        let mut output = [BabyBear::ZERO; 1];

        let result = BabyBear::read(&mut buf, &mut output);

        assert!(
            result.is_err(),
            "Reading invalid compressed field bytes should fail"
        );
    }

    #[test]
    fn test_roundtrip() {
        let mut rng = ark_std::test_rng();
        let scalars = [Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let mut pattern = PatternState::new();
        pattern.message_scalars::<Fr>(Label::new("data"), 2);
        let pattern = pattern.finalize();

        let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
        prover.message_scalars(Label::new("data"), &scalars);
        let proof = prover.finalize();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &proof);
        let mut received = [Fr::from(0); 2];
        verifier
            .read_message_scalars(Label::new("data"), &mut received)
            .unwrap();

        assert_eq!(scalars, received);
        verifier.finalize();
    }

    #[test]
    fn test_public_parameters_affect_challenges() {
        let mut rng = ark_std::test_rng();
        let public1 = Fr::rand(&mut rng);
        let public2 = Fr::rand(&mut rng);

        // Two patterns with different public parameters
        let mut pattern = PatternState::new();
        pattern.message_public_scalars::<Fr>(Label::new("public"), 1);
        pattern.challenge_scalars::<Fr>(Label::new("challenge"), 1);
        let pattern = pattern.finalize();

        // Prover 1 with public1
        let proof1 = {
            let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
            prover.message_public_scalars(Label::new("public"), &[public1]);
            let mut chal = [Fr::from(0)];
            prover.challenge_scalars(Label::new("challenge"), &mut chal);
            prover.finalize()
        };

        // Prover 2 with public2
        let proof2 = {
            let mut prover = ProverState::<DefaultHash>::new(pattern.clone(), rand::rngs::OsRng);
            prover.message_public_scalars(Label::new("public"), &[public2]);
            let mut chal = [Fr::from(0)];
            prover.challenge_scalars(Label::new("challenge"), &mut chal);
            prover.finalize()
        };

        // Verifier 1 with public1
        let mut chal1 = [Fr::from(0)];
        {
            let mut verifier = VerifierState::<DefaultHash>::new(pattern.clone(), &proof1);
            verifier.message_public_scalars(Label::new("public"), &[public1]);
            verifier.challenge_scalars(Label::new("challenge"), &mut chal1);
            verifier.finalize();
        }

        // Verifier 2 with public2
        let mut chal2 = [Fr::from(0)];
        {
            let mut verifier = VerifierState::<DefaultHash>::new(pattern, &proof2);
            verifier.message_public_scalars(Label::new("public"), &[public2]);
            verifier.challenge_scalars(Label::new("challenge"), &mut chal2);
            verifier.finalize();
        }

        // Different public parameters should lead to different challenges
        assert_ne!(chal1[0], chal2[0]);

        // Both proofs should be empty (public params don't go in proof)
        assert_eq!(proof1.len(), 0);
        assert_eq!(proof2.len(), 0);
    }
}
