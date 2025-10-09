use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField};
use ark_serialize::CanonicalSerialize;

use super::{CommonFieldToUnit, CommonGroupToUnit, UnitToField};
use crate::{
    codecs::bytes_uniform_modp,
    pattern::{Label, PatternError},
    duplex_sponge::Unit,
    CommonUnitToBytes, DuplexSpongeInterface, UnitToBytes, UnitTranscript, VerifierState,
};

// ============================================================================
// VERIFIER IMPLEMENTATIONS FOR u8 (byte-based operations)
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
        self.public_bytes(Label::PUBLIC, &buf)?;
        Ok(buf)
    }
}

impl<F, H> UnitToField<F> for VerifierState<'_, H, u8>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn fill_challenge_scalars(&mut self, label: Label, output: &mut [F]) -> Result<&mut Self, PatternError> {
        use crate::pattern::{Pattern, Length};
        
        let base_field_size = bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let total_bytes = output.len() * F::extension_degree() as usize * base_field_size;
        let mut buf = vec![0u8; total_bytes];

        Pattern::begin_challenge::<F>(self, label, Length::Fixed(output.len()))?;
        self.squeeze_challenge_bytes_nested(Label::BASE_FIELD_COEFFICIENTS_LITTLE_ENDIAN, &mut buf)?;
        Pattern::end_challenge::<F>(self, label, Length::Fixed(output.len()))?;

        // Convert bytes to field elements
        for (i, o) in output.iter_mut().enumerate() {
            let start = i * F::extension_degree() as usize * base_field_size;
            let end = start + F::extension_degree() as usize * base_field_size;
            *o = F::from_base_prime_field_elems(
                buf[start..end].chunks(base_field_size)
                    .map(F::BasePrimeField::from_be_bytes_mod_order),
            )
            .expect("Could not convert");
        }
        Ok(self)
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
        self.public_units(Label::PUBLIC, &flattened)?;
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
        input: &[ark_ec::short_weierstrass::Projective<P>]
    ) -> Result<Self::Repr, PatternError> {
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            self.public_units(label, &[x, y])?;
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
        input: &[ark_ec::twisted_edwards::Projective<P>]
    ) -> Result<Self::Repr, PatternError> {
        for point in input {
            let affine = point.into_affine();
            let (x, y) = affine.xy().unwrap();
            self.public_units(label, &[x, y])?;
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
            self.public_units(label, &[Fp::from(byte)])?;
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
            self.fill_challenge_units(label, &mut tmp)?;
            let buf = tmp[0].into_bigint().to_bytes_le();
            output[..len_good].copy_from_slice(&buf[..len_good]);

            // recursively fill the rest of the buffer
            self.fill_challenge_bytes(label, &mut output[len_good..])?;
        }
        Ok(self)
    }
}
#[cfg(test)]
mod tests {
    use ark_curve25519::EdwardsProjective as Curve;
    use ark_ec::PrimeGroup;
    use ark_ff::{AdditiveGroup, Fp64, MontBackend, MontConfig, UniformRand};
    use std::sync::Arc;

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{
            CommonFieldToUnit,
            CommonGroupToUnit,
        },
        codecs::unit::Pattern as UnitPattern,
        pattern::{PatternState, Label, Length, Pattern},
        DefaultHash, 
        ProverState,
    };

    /// Configuration for the BabyBear field
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

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

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        // Initialize the prover state
        let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);

        // Try to absorb the scalars - this should fail with the current pattern
        let result = prover.public_scalars(&values);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover.abort().expect("Failed to abort");
    }

    #[test]
    fn test_common_group_to_unit_curve_u8() {
        // Generator of the curve group
        let point = Curve::generator();

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);

        // Try to serialize the point - this should fail with the current pattern
        let result = prover.public_points(Label::custom("X"), &[point]);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover.abort().expect("Failed to abort");
    }

    #[test]
    fn test_unit_read_invalid_bytes() {
        // Provide malformed input that cannot be deserialized
        let mut buf = &[0xff, 0xff][..];
        let mut output = [BabyBear::ZERO; 1];

        let result = BabyBear::read(&mut buf, &mut output);

        assert!(
            result.is_err(),
            "Reading invalid compressed field bytes should fail"
        );
    }
}
