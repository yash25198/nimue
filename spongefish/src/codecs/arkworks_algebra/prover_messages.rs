use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Fp, FpConfig};
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};

use super::{CommonFieldToUnit, CommonGroupToUnit, FieldToUnitSerialize, GroupToUnitSerialize};
use crate::{
    pattern::{Hierarchy, Interaction, Kind, Label, Length, Pattern as _, PatternError},
    CommonUnitToBytes, DuplexSpongeInterface, ProverState, UnitTranscript,
};

impl<F: Field, H: DuplexSpongeInterface, R: RngCore + CryptoRng> FieldToUnitSerialize<F>
    for ProverState<H, u8, R>
{
    fn add_scalars(&mut self, label: Label, input: &[F]) -> Result<&mut Self, PatternError> {
        // Begin the outer field message
        self.pattern.begin_message::<F>(label.clone(), Length::Fixed(input.len()))?;
        
        // Serialize the scalars to bytes
        let mut buf = Vec::new();
        for f in input {
            f.serialize_compressed(&mut buf).expect("Serialization failed");
        }

        // This will handle: Begin Message "bytes" -> Atomic "units" -> End Message "bytes"
        self.add_units(Label::Bytes, &buf)?;
        
        // End the outer field message
        self.pattern.end_message::<F>(label, Length::Fixed(input.len()))?;
        
        Ok(self)
    }
}

impl<
        C: FpConfig<N>,
        H: DuplexSpongeInterface<Fp<C, N>>,
        R: RngCore + CryptoRng,
        const N: usize,
    > FieldToUnitSerialize<Fp<C, N>> for ProverState<H, Fp<C, N>, R>
{
    fn add_scalars(&mut self, label: Label, input: &[Fp<C, N>]) -> Result<&mut Self, PatternError> {
        // Begin the outer field message
        self.pattern.begin_message::<Fp<C, N>>(label.clone(), Length::Fixed(input.len()))?;
        
        // Use add_units which handles the inner hierarchy and serialization
        self.add_units(Label::custom("base-field-coefficients"), input)?;
        
        // End the outer field message
        self.pattern.end_message::<Fp<C, N>>(label, Length::Fixed(input.len()))?;
        
        Ok(self)
    }
}

impl<G, H, R> GroupToUnitSerialize<G> for ProverState<H, u8, R>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_points(&mut self, label: Label, input: &[G]) -> Result<&mut Self, PatternError> {
        // Begin the outer group message
        self.pattern.begin_message::<G>(label.clone(), Length::Fixed(input.len()))?;
        
        // Serialize
        let mut serialized = Vec::new();
        for p in input {
            p.serialize_compressed(&mut serialized).expect("Serialization failed");
        }

        // This will handle: Begin Message "bytes" -> Atomic "units" -> End Message "bytes"
        self.add_units(Label::Bytes, &serialized)?;

        // End the outer group message
        self.pattern.end_message::<G>(label, Length::Fixed(input.len()))?;
        
        Ok(self)
    }
}

impl<G, H, R, C: FpConfig<N>, const N: usize> GroupToUnitSerialize<G>
    for ProverState<H, Fp<C, N>, R>
where
    G: CurveGroup<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    Self: CommonGroupToUnit<G>,
{
    fn add_points(&mut self, label: Label, input: &[G]) -> Result<&mut Self, PatternError> {
        // Begin the outer group message
        self.pattern.begin_message::<G>(label.clone(), Length::Fixed(input.len()))?;
        
        // Extract coordinates into flat array
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let (x, y) = point.into_affine().xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        
        // Use add_units which handles inner hierarchy and serialization
        self.add_units(Label::custom("coordinates"), &coords)?;
        
        // End the outer group message
        self.pattern.end_message::<G>(label, Length::Fixed(input.len()))?;
        
        Ok(self)
    }
}


// Specific implementations for ProverState with u8 unit type
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
            i.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.public_bytes(label, &buf)?;
        Ok(buf)
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
            i.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.public_bytes(Label::custom("public"), &buf)?;
        Ok(buf)
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
        self.public_units(Label::custom("public"), &flattened)?;
        Ok(())
    }
}

impl<H, R, C, const N: usize, G> CommonGroupToUnit<G> for ProverState<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    R: RngCore + CryptoRng,
    H: DuplexSpongeInterface<Fp<C, N>>,
    G: CurveGroup<BaseField = Fp<C, N>>,
{
    type Repr = ();
    
    fn public_points(&mut self, label: Label, input: &[G]) -> Result<Self::Repr, PatternError> {
        // Flatten all coordinates into one array
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let (x, y) = point.into_affine().xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        // Single call to public_units for all coordinates
        self.public_units(label, &coords)?;
        Ok(())
    }
}

impl<H, R, C, const N: usize> CommonUnitToBytes for ProverState<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    R: CryptoRng + rand::RngCore,
{
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError> {
        for &byte in input {
            self.public_units(label.clone(), &[Fp::from(byte)])?;
        }
        Ok(self)
    }
}
#[cfg(test)]
#[cfg(feature = "disable")]
mod tests {
    use ark_bls12_381::Fr;
    use ark_curve25519::EdwardsProjective;
    use ark_ec::PrimeGroup;
    use ark_ff::{Fp64, MontBackend, MontConfig, UniformRand};

    use super::*;
    use crate::{
        codecs::arkworks_algebra::{FieldPattern, FieldToUnitSerialize, GroupPattern},
        ByteDomainSeparator, DefaultHash,
    };

    /// Curve used for tests
    type G = EdwardsProjective;

    /// Configuration for the BabyBear field (modulus = 2^31 - 2^27 + 1, generator = 21).
    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    /// Base field type using the BabyBear configuration.
    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    #[test]
    fn test_add_scalars() {
        // Create a domain separator with a fixed domain label
        let domsep = DomainSeparator::new("test");

        // Append an "absorb scalars" tag to the transcript:
        // - BabyBear has 31-bit modulus ⇒ bytes_modp(31) = 4
        // - 3 scalars * 4 bytes = 12 ⇒ "\0A12com" is added
        let domsep =
            <DomainSeparator as FieldDomainSeparator<BabyBear>>::add_scalars(domsep, 3, "com");

        // Create the prover state from the domain separator
        let mut prover_state = domsep.to_prover_state();

        // Sample 3 random BabyBear field elements to simulate public input
        let mut rng = ark_std::test_rng();
        let (f0, f1, f2) = (
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
        );

        // Add the scalars to the prover's transcript using the serialize logic
        prover_state.add_scalars(&[f0, f1, f2]).unwrap();

        // Serialize the scalars independently to verify `narg_string` content
        let mut expected_bytes = Vec::new();
        f0.serialize_compressed(&mut expected_bytes).unwrap();
        f1.serialize_compressed(&mut expected_bytes).unwrap();
        f2.serialize_compressed(&mut expected_bytes).unwrap();

        // The `narg_string` in the prover must match the manually serialized data
        assert_eq!(
            prover_state.narg_string, expected_bytes,
            "Transcript serialization mismatch"
        );

        // Repeat with a new prover and same domain separator to test determinism
        let mut prover_state2 = domsep.to_prover_state();
        prover_state2.add_scalars(&[f0, f1, f2]).unwrap();
        assert_eq!(
            prover_state.narg_string, prover_state2.narg_string,
            "Transcript encoding should be deterministic for same inputs"
        );
    }

    #[test]
    fn test_add_scalars_u8_unit() {
        // Construct a domain separator that absorbs 2 field elements
        let domsep = DomainSeparator::new("test-add-scalars-u8");
        let domsep = <DomainSeparator as FieldDomainSeparator<Fr>>::add_scalars(domsep, 2, "com");

        // Create prover state from domain separator
        let mut prover = domsep.to_prover_state();

        // Use two deterministic values for test
        let f0 = Fr::from(5u64);
        let f1 = Fr::from(42u64);

        // Add the scalars to the prover's transcript
        prover.add_scalars(&[f0, f1]).unwrap();

        // Serialize the expected bytes directly
        let mut expected = Vec::new();
        f0.serialize_compressed(&mut expected).unwrap();
        f1.serialize_compressed(&mut expected).unwrap();

        // Assert transcript encoding is correct
        assert_eq!(prover.narg_string, expected);
    }

    #[test]
    fn test_add_points_u8_unit() {
        // Use ark_curve25519 curve (compressed point = 32 bytes)
        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("curve25519"),
            1,
            "pt",
        );

        let mut prover = domsep.to_prover_state();
        let point = G::generator();

        // Add the point to the prover's transcript
        prover.add_points(&[point]).unwrap();

        assert!(!prover.narg_string.is_empty());
    }

    #[test]
    fn test_add_points_fp_unit() {
        let domsep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::new("curve-bb"),
            1,
            "pt",
        );

        let mut prover = domsep.to_prover_state();
        let point = G::generator();

        // This triggers `GroupToUnitSerialize<G> for ProverState<H, Fp<C, N>, R>`
        prover.add_points(&[point]).unwrap();

        // Expect compressed x/y coordinates in `narg_string`
        let mut expected = Vec::new();
        point.serialize_compressed(&mut expected).unwrap();
        assert_eq!(prover.narg_string, expected);
    }

    #[test]
    fn test_add_bytes_fp_unit() {
        let input = b"hello world!";

        // Domain separator that expects 12 bytes to be absorbed
        let domsep: DomainSeparator<DefaultHash, u8> = DomainSeparator::new("test-add-bytes-fp");
        let domsep = domsep.add_bytes(12, "com");

        let mut prover = domsep.to_prover_state();

        // Add the bytes to the prover's transcript
        prover.add_bytes(input).unwrap();

        // The bytes should be directly copied into the transcript `narg_string`
        assert_eq!(prover.narg_string, input);
    }

    #[test]
    fn test_fill_next_bytes_fp_unit() {
        let input = b"secret-msg";

        // Set up prover to absorb input bytes and record them in narg_string
        let domsep: DomainSeparator<DefaultHash, u8> = DomainSeparator::new("read-bytes");
        let domsep = domsep.add_bytes(input.len(), "msg");
        let mut prover = domsep.to_prover_state();
        prover.add_bytes(input).unwrap();

        // Reconstruct verifier state from same domain + transcript
        let mut verifier = domsep.to_verifier_state(&prover.narg_string);

        // Read the bytes from the verifier state
        let mut buf = [0u8; 10];
        verifier.fill_next_bytes(&mut buf).unwrap();

        assert_eq!(buf, *input);
    }
}
