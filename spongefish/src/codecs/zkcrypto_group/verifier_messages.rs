use group::ff::PrimeField;

use super::UnitToField;
use crate::{
    codecs::bytes_uniform_modp,
    pattern::{Label, PatternError},
    UnitToBytes,
};

fn from_bytes_mod_order<F: PrimeField>(bytes: &[u8]) -> F {
    let basis = F::from(256);
    bytes
        .iter()
        .fold(F::ZERO, |acc, &b| acc * basis + F::from(u64::from(b)))
}

impl<F, T> UnitToField<F> for T
where
    F: PrimeField,
    T: UnitToBytes,
{
    fn fill_challenge_scalars(
        &mut self,
        label: Label,
        output: &mut [F],
    ) -> Result<&mut Self, PatternError> {
        let mut buf = vec![0; bytes_uniform_modp(F::NUM_BITS)];

        for o in output {
            self.fill_challenge_bytes(label, &mut buf)?;
            *o = from_bytes_mod_order(&buf);
        }
        Ok(self)
    }
}
