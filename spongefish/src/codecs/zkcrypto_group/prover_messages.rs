use group::{ff::PrimeField, Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

use super::{CommonFieldToUnit, CommonGroupToUnit, FieldToUnitSerialize, GroupToUnitSerialize};
use crate::{
    pattern::{Hierarchy, Interaction, Kind, Label, Length, PatternError},
    CommonUnitToBytes, DuplexSpongeInterface, ProverState,
};

impl<F, H, R> FieldToUnitSerialize<F> for ProverState<H, u8, R>
where
    F: PrimeField,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_scalars(&mut self, label: Label, input: &[F]) -> Result<&mut Self, PatternError> {
        // Record the atomic interaction
        self.pattern.interact(Interaction::new::<F>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(input.len()),
        ))?;

        let mut buf = Vec::new();
        input.iter().for_each(|i| buf.extend(i.to_repr().as_ref()));

        self.duplex_sponge.absorb_unchecked(&buf);
        self.narg_string.extend(&buf);
        self.rng.ds.absorb_unchecked(&buf);
        Ok(self)
    }
}

impl<G, H, R> CommonGroupToUnit<G> for ProverState<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    type Repr = Vec<u8>;

    fn public_points(&mut self, input: &[G]) -> Result<Self::Repr, PatternError> {
        let mut buf = Vec::new();
        for p in input {
            buf.extend_from_slice(<G as GroupEncoding>::to_bytes(p).as_ref());
        }
        self.public_bytes(Label::PUBLIC, &buf)?;
        Ok(buf)
    }
}

impl<G, H, R> GroupToUnitSerialize<G> for ProverState<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_points(&mut self, label: Label, input: &[G]) -> Result<&mut Self, PatternError> {
        // Record the atomic interaction
        self.pattern.interact(Interaction::new::<G>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(input.len()),
        ))?;

        let mut buf = Vec::new();
        for p in input {
            buf.extend_from_slice(<G as GroupEncoding>::to_bytes(p).as_ref());
        }

        self.duplex_sponge.absorb_unchecked(&buf);
        self.narg_string.extend(&buf);
        self.rng.ds.absorb_unchecked(&buf);
        Ok(self)
    }
}

impl<F, T> CommonFieldToUnit<F> for T
where
    F: PrimeField,
    T: CommonUnitToBytes,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> Result<Self::Repr, PatternError> {
        let mut buf = Vec::new();
        input.iter().for_each(|i| buf.extend(i.to_repr().as_ref()));
        self.public_bytes(Label::PUBLIC, &buf)?;
        Ok(buf)
    }
}