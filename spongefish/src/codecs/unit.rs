use crate::{
    pattern::{Label, PatternError},
    Unit,
};

pub trait Pattern {
    type Unit: Unit;

    fn ratchet(&mut self) -> &mut Self;
    fn public_unit(&mut self, label: Label) -> &mut Self;
    fn public_units(&mut self, label: Label, size: usize) -> &mut Self;
    fn message_unit(&mut self, label: Label) -> &mut Self;
    fn message_units(&mut self, label: Label, size: usize) -> &mut Self;
    fn challenge_unit(&mut self, label: Label) -> &mut Self;
    fn challenge_units(&mut self, label: Label, size: usize) -> &mut Self;
    fn hint_bytes(&mut self, label: Label, size: usize) -> &mut Self;
    fn hint_bytes_dynamic(&mut self, label: Label) -> &mut Self;
}
