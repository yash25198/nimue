use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField};

use super::{CommonFieldToUnit, CommonGroupToUnit, UnitToField};
use crate::{
    codecs::bytes_uniform_modp,
    pattern::{Label, PatternError},
    CommonUnitToBytes, DuplexSpongeInterface, UnitToBytes, UnitTranscript, VerifierState,
};

// Common implementations (no labels in public methods)

// Specific implementations for VerifierState with u8 unit type
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
        self.public_bytes(label, &buf)?;
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
        self.public_bytes(Label::custom("public"), &buf)?;
        Ok(buf)
    }
}

// Specific implementation for VerifierState with u8 unit type
impl<F, H> UnitToField<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn fill_challenge_scalars(&mut self, label: Label, output: &mut [F]) -> Result<&mut Self, PatternError> {
        let base_field_size = bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let mut buf = vec![0u8; F::extension_degree() as usize * base_field_size];

        for o in output.iter_mut() {
            self.fill_challenge_bytes(label.clone(), &mut buf)?;
            *o = F::from_base_prime_field_elems(
                buf.chunks(base_field_size)
                    .map(F::BasePrimeField::from_be_bytes_mod_order),
            )
            .expect("Could not convert");
        }
        Ok(self)
    }
}

impl<H, C, const N: usize> UnitToField<Fp<C, N>> for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn fill_challenge_scalars(&mut self, label: Label, output: &mut [Fp<C, N>]) -> Result<&mut Self, PatternError> {
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
        self.public_units(Label::custom("public"), &flattened)?;
        Ok(())
    }
}

impl<H, C, const N: usize, G> CommonGroupToUnit<G> for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    G: CurveGroup<BaseField = Fp<C, N>>,
{
    type Repr = ();

    fn public_points(&mut self, label: Label, input: &[G]) -> Result<Self::Repr, PatternError> {
        for point in input {
            let (x, y) = point.into_affine().xy().unwrap();
            self.public_units(label.clone(), &[x, y])?;
        }
        Ok(())
    }
}

impl<H, C, const N: usize> CommonUnitToBytes for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError> {
        for &byte in input {
            self.public_units(label.clone(), &[Fp::from(byte)])?;
        }
        Ok(self)
    }
}

impl<H, R, C, const N: usize> UnitToBytes for crate::ProverState<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: rand::CryptoRng + rand::RngCore,
{
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> Result<&mut Self, PatternError> {
        if !output.is_empty() {
            let len_good = usize::min(
                crate::codecs::random_bytes_in_random_modp(Fp::<C, N>::MODULUS),
                output.len(),
            );
            let mut tmp = [Fp::from(0); 1];
            self.fill_challenge_units(label.clone(), &mut tmp)?;
            let buf = tmp[0].into_bigint().to_bytes_le();
            output[..len_good].copy_from_slice(&buf[..len_good]);

            // recursively fill the rest of the buffer
            self.fill_challenge_bytes(label, &mut output[len_good..])?;
        }
        Ok(self)
    }
}

impl<H, C, const N: usize> UnitToBytes for VerifierState<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> Result<&mut Self, PatternError> {
        if !output.is_empty() {
            let len_good = usize::min(
                crate::codecs::random_bytes_in_random_modp(Fp::<C, N>::MODULUS),
                output.len(),
            );
            let mut tmp = [Fp::from(0); 1];
            self.fill_challenge_units(label.clone(), &mut tmp)?;
            let buf = tmp[0].into_bigint().to_bytes_le();
            output[..len_good].copy_from_slice(&buf[..len_good]);

            // recursively fill the rest of the buffer
            self.fill_challenge_bytes(label, &mut output[len_good..])?;
        }
        Ok(self)
    }
}
#[cfg(test)]
#[cfg(feature = "disable")]
mod tests {
    use ark_curve25519::EdwardsProjective as Curve;
    use ark_ec::PrimeGroup;
    use ark_ff::{AdditiveGroup, Fp64, MontBackend, MontConfig, UniformRand};

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{FieldPattern, GroupPattern},
        DefaultHash,
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

        // Append a "public scalars" directive into the transcript metadata:
        // - We're committing to 2 scalars with label "test"
        let domsep: DomainSeparator<DefaultHash, u8> = DomainSeparator::new("field");
        let domsep =
            <DomainSeparator as FieldDomainSeparator<BabyBear>>::add_scalars(domsep, 2, "test");

        // Initialize the prover state with this domain separator.
        let mut prover = domsep.to_prover_state();

        // Manually serialize the field elements to bytes using compressed encoding.
        let mut expected_bytes = Vec::new();
        for v in &values {
            v.serialize_compressed(&mut expected_bytes).unwrap();
        }

        // Absorb the scalars into the transcript using `CommonFieldToUnit`.
        let actual = prover.public_scalars(&values).unwrap();

        // Ensure the actual bytes match the expected bytes.
        assert_eq!(
            actual, expected_bytes,
            "Serialized field elements should match manual serialization"
        );

        // Now check determinism: a second prover with the same setup and inputs should produce the same output.
        let mut prover2 = domsep.to_prover_state();
        let actual2 = prover2.public_scalars(&values).unwrap();
        assert_eq!(
            actual, actual2,
            "Transcript encoding should be deterministic for the same inputs"
        );
    }

    #[test]
    fn test_common_group_to_unit_curve_u8() {
        // Generator of the curve group
        let point = Curve::generator();

        // Create a domain separator for 1 point
        let domsep = <DomainSeparator as GroupDomainSeparator<Curve>>::add_points(
            DomainSeparator::new("curve-pt"),
            1,
            "pt",
        );

        let mut prover = domsep.to_prover_state();

        // Serialize the point and absorb it
        let actual = prover.public_points(&[point]).unwrap();

        // Manual serialization for comparison
        let mut expected = Vec::new();
        point.serialize_compressed(&mut expected).unwrap();

        assert_eq!(
            actual, expected,
            "Group element should serialize and match compressed encoding"
        );
    }

    #[test]
    fn test_unit_to_field_fill_challenge_scalars_u8() {
        let domsep = <DomainSeparator as FieldDomainSeparator<BabyBear>>::challenge_scalars(
            DomainSeparator::new("chal"),
            1,
            "tag",
        );
        let mut prover = domsep.to_prover_state();

        let mut out = [BabyBear::ZERO; 1];
        prover.fill_challenge_scalars(&mut out).unwrap();

        // We expect at least some entropy in the output
        assert_ne!(out[0], BabyBear::ZERO, "Challenge should not be zero");
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
