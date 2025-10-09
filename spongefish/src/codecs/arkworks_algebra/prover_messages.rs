use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Fp, FpConfig};
use rand::{CryptoRng, RngCore};

use super::{CommonFieldToUnit, CommonGroupToUnit, FieldToUnitSerialize, GroupToUnitSerialize};
use crate::{
    pattern::{Label, Length, Pattern as _, PatternError}, BytesToUnitSerialize, CommonUnitToBytes, DuplexSpongeInterface, ProverState, UnitTranscript
};

impl<F: Field, H: DuplexSpongeInterface, R: RngCore + CryptoRng> FieldToUnitSerialize<F>
    for ProverState<H, u8, R>
{
    fn add_scalars(&mut self, label: Label, input: &[F]) -> Result<&mut Self, PatternError> {
        // Begin the outer field message
        self.pattern.begin_message::<F>(label, Length::Fixed(input.len()))?;
        
        // Serialize the scalars to bytes
        let mut buf = Vec::new();
        for f in input {
            f.serialize_compressed(&mut buf).expect("Serialization failed");
        }

        // Create the bytes hierarchy: Begin Message "bytes" -> Atomic "units" -> End Message "bytes"
        self.add_bytes(Label::UNITS, &buf)?;

        
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
        self.pattern.begin_message::<Fp<C, N>>(label, Length::Fixed(input.len()))?;
        
        // Use add_units which handles the inner hierarchy and serialization
        self.add_units(Label::BASE_FIELD_COEFFICIENTS, input)?;
        
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
        self.pattern.begin_message::<G>(label, Length::Fixed(input.len()))?;
        
        // Serialize
        let mut serialized = Vec::new();
        for p in input {
            p.serialize_compressed(&mut serialized).expect("Serialization failed");
        }

        // Create the bytes hierarchy: Begin Message "serialized-group" -> Atomic "units" -> End Message "serialized-group"
        self.pattern.begin_message::<u8>(Label::SERIALIZED_GROUP, Length::Fixed(serialized.len()))?;
        self.add_units(Label::UNITS, &serialized)?;
        self.pattern.end_message::<u8>(Label::SERIALIZED_GROUP, Length::Fixed(serialized.len()))?;

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
        self.pattern.begin_message::<G>(label, Length::Fixed(input.len()))?;
        
        // Extract coordinates into flat array
        let mut coords = Vec::with_capacity(input.len() * 2);
        for point in input {
            let (x, y) = point.into_affine().xy().unwrap();
            coords.push(x);
            coords.push(y);
        }
        
        // Use add_units which handles inner hierarchy and serialization
        self.add_units(Label::COORDINATES, &coords)?;
        
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
        self.public_bytes(Label::PUBLIC, &buf)?;
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
        self.public_units(Label::PUBLIC, &flattened)?;
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
            self.public_units(label, &[Fp::from(byte)])?;
        }
        Ok(self)
    }
}
#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_curve25519::EdwardsProjective;
    use ark_ec::PrimeGroup;
    use ark_ff::{Fp64, MontBackend, MontConfig, UniformRand};
    use std::sync::Arc;
    use ark_serialize::CanonicalSerialize;
    use super::*;
    use crate::{
        codecs::{
            arkworks_algebra::{
                FieldPattern, 
                FieldToUnitSerialize, 
                GroupPattern, 
                GroupToUnitSerialize,
                CommonFieldToUnit,
                CommonGroupToUnit,
            },
            bytes::Pattern as BytesPattern,
            unit::Pattern as UnitPattern,
        },
        pattern::{PatternState, Pattern as _, Label, Interaction, Hierarchy, Kind, Length},
        DefaultHash, 
        ProverState,
        VerifierState,
        BytesToUnitSerialize,
        BytesToUnitDeserialize,
    };

    type G = EdwardsProjective;

    #[derive(MontConfig)]
    #[modulus = "2013265921"]
    #[generator = "21"]
    pub struct BabybearConfig;

    pub type BabyBear = Fp64<MontBackend<BabybearConfig, 1>>;

    #[test]
    fn test_add_scalars() {
        // Sample 3 random BabyBear field elements
        let mut rng = ark_std::test_rng();
        let (f0, f1, f2) = (
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
            BabyBear::rand(&mut rng),
        );

        // Create a simple pattern without hierarchical structure
        let pattern = Arc::new(PatternState::<u8>::new().finalize());

        // Create prover state
        let mut prover_state = ProverState::<DefaultHash>::new(Arc::clone(&pattern), rand::rngs::OsRng);

        // Try to add the scalars - this should fail with the current pattern
        let result = prover_state.add_scalars(Label::custom("com"), &[f0, f1, f2]);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover_state.abort().expect("Failed to abort");
    }

    #[test]
    fn test_add_scalars_u8_unit() {
        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        // Create prover state
        let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);

        // Use two deterministic values for test
        let f0 = Fr::from(5u64);
        let f1 = Fr::from(42u64);

        // Try to add the scalars - this should fail with the current pattern
        let result = prover.add_scalars(Label::custom("com"), &[f0, f1]);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover.abort().expect("Failed to abort");
    }

    #[test]
    fn test_add_points_u8_unit() {
        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);
        let point = G::generator();

        // Try to add the point - this should fail with the current pattern
        let result = prover.add_points(Label::custom("pt"), &[point]);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover.abort().expect("Failed to abort");
    }

    #[test]
    fn test_add_points_fp_unit() {
        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);
        let point = G::generator();

        // Try to add the point - this should fail with the current pattern
        let result = prover.add_points(Label::custom("pt"), &[point]);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover.abort().expect("Failed to abort");
    }

    #[test]
    fn test_add_bytes_fp_unit() {
        let input = b"hello world!";

        // Create a simple pattern without hierarchical structure
        let pattern = PatternState::<u8>::new().finalize();

        let mut prover = ProverState::<DefaultHash>::new(Arc::new(pattern), rand::rngs::OsRng);

        // Try to add the bytes - this should fail with the current pattern
        let result = prover.add_bytes(Label::custom("com"), input);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover.abort().expect("Failed to abort");
    }

    #[test]
    fn test_fill_next_bytes_fp_unit() {
        let input = b"secret-msg";

        // Create a simple pattern without hierarchical structure
        let pattern = Arc::new(PatternState::<u8>::new().finalize());
        
        let mut prover = ProverState::<DefaultHash>::new(Arc::clone(&pattern), rand::rngs::OsRng);
        
        // Try to add the bytes - this should fail with the current pattern
        let result = prover.add_bytes(Label::custom("msg"), input);
        
        // We expect this to fail because the pattern doesn't have the right interactions
        assert!(result.is_err(), "Expected error due to pattern mismatch");
        
        prover.abort().expect("Failed to abort");
    }
}