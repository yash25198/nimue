use group::ff::PrimeField;

use super::FieldToUnitDeserialize;
use crate::{
    pattern::{Hierarchy, Interaction, Kind, Label, Length},
    DuplexSpongeInterface, ProofError, VerifierState,
};

impl<F, H, const N: usize> FieldToUnitDeserialize<F> for VerifierState<'_, H>
where
    H: DuplexSpongeInterface,
    F: PrimeField<Repr = [u8; N]>,
{
    fn fill_next_scalars(
        &mut self,
        label: impl AsRef<str>,
        output: &mut [F],
    ) -> crate::ProofResult<&mut Self> {
        // Record the atomic interaction
        self.pattern.interact(Interaction::new::<F>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(output.len()),
        ))?;

        let mut buf = [0u8; N];
        for o in output.iter_mut() {
            u8::read(&mut self.narg_string, &mut buf)?;
            *o = F::from_repr_vartime(buf).ok_or(ProofError::SerializationError)?;
            self.duplex_sponge.absorb_unchecked(&buf);
        }
        Ok(self)
    }
}
