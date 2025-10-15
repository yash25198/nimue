use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField};
use ark_serialize::CanonicalSerialize;

use super::{CommonFieldToUnit, CommonGroupToUnit, UnitToField};
use crate::{
    codecs::bytes_uniform_modp,
    pattern::{Label, Length, PatternError},
    CommonUnitToBytes, DuplexSpongeInterface, UnitToBytes, UnitTranscript, VerifierState,
};

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR u8 (unit-basedoperations)
// ============================================================================

impl<G, H> CommonGroupToUnit<G> for VerifierState<'_, H, u8>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    type Repr = Vec<u8>;

    fn public_points(&mut self, label: Label, input: &[G]) -> Result<Self::Repr, PatternError> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.public_bytes(label, &buf);
        Ok(buf)
    }
}

impl<F, H> CommonFieldToUnit<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> Result<Self::Repr, PatternError> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.public_bytes(Label::Public, &buf);
        Ok(buf)
    }
}

impl<F, H> UnitToField<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn fill_challenge_scalars(&mut self, label: Label, output: &mut [F]) -> &mut Self {
        let base_field_size = bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let ext_degree = F::extension_degree() as usize;
        let element_size = ext_degree * base_field_size;
        let total_bytes = output.len() * element_size;

        let mut buf = vec![0u8; total_bytes];

        // These methods are now infallible
        self.begin_challenge::<F>(label.clone(), output.len());
        self.fill_challenge_bytes(Label::BaseFieldCoefficients, &mut buf);
        self.end_challenge::<F>(label, output.len());
        // Convert bytes to field elements by chunking the buffer
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

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR Fp<C, N> (field-native operations)
// ============================================================================

impl<H, C, const N: usize> UnitToField<Fp<C, N>> for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn fill_challenge_scalars(&mut self, label: Label, output: &mut [Fp<C, N>]) -> &mut Self {
        self.fill_challenge_units(label, output)
    }
}

impl<F, H, C, const N: usize> CommonFieldToUnit<F> for VerifierState<'_, H, Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    type Repr = ();

    fn public_scalars(&mut self, input: &[F]) -> Result<Self::Repr, PatternError> {
        let flattened: Vec<_> = input
            .iter()
            .flat_map(Field::to_base_prime_field_elements)
            .collect();
        self.public_units(Label::Public, &flattened);
        Ok(())
    }
}

// ============================================================================
// SHORT WEIERSTRASS CURVE IMPLEMENTATION FOR Fp<C, N>
// ============================================================================

impl<P, H, C, const N: usize> CommonGroupToUnit<ark_ec::short_weierstrass::Projective<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    P: ark_ec::short_weierstrass::SWCurveConfig<BaseField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    type Repr = ();

    fn public_points(
        &mut self,
        label: Label,
        input: &[ark_ec::short_weierstrass::Projective<P>],
    ) -> Result<Self::Repr, PatternError> {
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            self.public_units(label.clone(), &[x, y]);
        }
        Ok(())
    }
}

// ============================================================================
// TWISTED EDWARDS CURVE IMPLEMENTATION FOR Fp<C, N>
// ============================================================================

impl<P, H, C, const N: usize> CommonGroupToUnit<ark_ec::twisted_edwards::Projective<P>>
    for VerifierState<'_, H, Fp<C, N>>
where
    P: ark_ec::twisted_edwards::TECurveConfig<BaseField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    type Repr = ();

    fn public_points(
        &mut self,
        label: Label,
        input: &[ark_ec::twisted_edwards::Projective<P>],
    ) -> Result<Self::Repr, PatternError> {
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            self.public_units(label.clone(), &[x, y]);
        }
        Ok(())
    }
}

impl<H, C, const N: usize> CommonUnitToBytes for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> &mut Self {
        for &byte in input {
            self.public_units(label.clone(), &[Fp::from(byte)]);
        }
        self
    }
}

impl<H, C, const N: usize> UnitToBytes for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> &mut Self {
        if !output.is_empty() {
            let len_good = usize::min(
                crate::codecs::random_bytes_in_random_modp(Fp::<C, N>::MODULUS),
                output.len(),
            );
            let mut tmp = [Fp::from(0); 1];
            self.fill_challenge_units(label.clone(), &mut tmp);
            let buf = tmp[0].into_bigint().to_bytes_le();
            output[..len_good].copy_from_slice(&buf[..len_good]);

            // recursively fill the rest of the buffer
            self.fill_challenge_bytes(label, &mut output[len_good..]);
        }
        self
    }
}
#[cfg(test)]
#[cfg(feature = "arkworks-algebra")]
mod tests {
    use std::sync::Arc;

    use ark_curve25519::EdwardsProjective as Curve;
    use ark_ec::PrimeGroup;
    use ark_ff::{AdditiveGroup, Fp64, MontBackend, MontConfig, UniformRand};

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{
            FieldPattern, GroupPattern, ProverFieldMessageExt, ProverGroupMessageExt,
            VerifierFieldMessageExt, VerifierGroupMessageExt,
        },
        pattern::{Label, PatternState},
        DefaultHash, ProverState, Unit,
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
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut prover =
            ProverState::<DefaultHash>::new(Arc::new(pattern.clone()), rand::rngs::OsRng);
        let _ = prover.message_scalars(Label::from("tag"), &values);

        // Verify narg_string
        let mut expected_bytes = Vec::new();
        for v in &values {
            v.serialize_compressed(&mut expected_bytes).unwrap();
        }
        assert_eq!(prover.narg_string().unwrap(), expected_bytes);

        let proof = prover.finalize().unwrap();

        let mut verifier = VerifierState::<DefaultHash>::new(Arc::new(pattern), &proof);

        let _ = verifier
            .fill_message_scalars(Label::from("tag"), &mut values2)
            .unwrap();
        verifier.finalize().unwrap();
        assert_eq!(
            values2, values,
            "Serialized field elements should be deterministic"
        );
    }

    #[test]
    fn test_common_group_to_unit_curve_u8() {
        // Generator of the curve group
        let point = Curve::generator();

        // Manual serialization for comparison
        let mut expected = Vec::new();
        point.serialize_compressed(&mut expected).unwrap();

        let mut pattern = PatternState::new();
        pattern.message_points::<Curve>(Label::custom("generator"), 1);
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut prover =
            ProverState::<DefaultHash>::new(Arc::new(pattern.clone()), rand::rngs::OsRng);
        let _ = prover.message_points(Label::custom("generator"), &[point]);

        // Verify narg_string matches expected serialization
        assert_eq!(prover.narg_string().unwrap(), expected);

        let proof = prover.finalize().unwrap();

        let mut verifier = VerifierState::<DefaultHash>::new(Arc::new(pattern), &proof);

        let mut out = [Curve::ZERO];
        let _ = verifier
            .fill_message_points(Label::custom("generator"), &mut out)
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
        let pattern = Arc::new(pattern.finalize().expect("Failed to finalize pattern"));

        let mut prover = ProverState::<DefaultHash, u8>::new(pattern.clone(), rand::rngs::OsRng);

        let mut out = [BabyBear::ONE; 1];
        prover.message_scalars(Label::from("tag"), &mut out);

        // Verify narg_string
        let mut expected = Vec::new();
        BabyBear::ONE.serialize_compressed(&mut expected).unwrap();
        assert_eq!(prover.narg_string().unwrap(), expected);

        // Finalize the prover to get the proof
        let proof = prover.finalize().unwrap();

        let mut verifier = VerifierState::<DefaultHash>::new(pattern, &proof);

        let mut out = [BabyBear::ZERO; 1];
        let _ = verifier
            .fill_message_scalars(Label::from("tag"), &mut out)
            .unwrap();
        verifier.finalize().unwrap();

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
}
