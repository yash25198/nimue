use crate::{pattern::Label, Unit};

pub trait Pattern {
    type Unit: Unit;

    fn ratchet(&mut self) -> &mut Self;
    fn message_public_unit(&mut self, label: impl AsRef<str>) -> &mut Self;
    fn message_public_units(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self;
    fn message_unit(&mut self, label: impl AsRef<str>) -> &mut Self;
    fn message_units(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self;
    fn challenge_unit(&mut self, label: impl AsRef<str>) -> &mut Self;
    fn challenge_units(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self;
    fn hint_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self;
    fn hint_bytes_dynamic(&mut self, label: impl AsRef<str>) -> &mut Self;
}
