use crate::{
    pattern::{Label, PatternError},
    Unit,
};

pub trait Pattern {
    type Unit: Unit;

    fn ratchet(&mut self) -> Result<&mut Self, PatternError>;
    fn public_unit(&mut self, label: Label) -> Result<&mut Self, PatternError>;
    fn public_units(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError>;
    fn message_unit(&mut self, label: Label) -> Result<&mut Self, PatternError>;
    fn message_units(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError>;
    fn challenge_unit(&mut self, label: Label) -> Result<&mut Self, PatternError>;
    fn challenge_units(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError>;
    fn hint_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError>;
    fn hint_bytes_dynamic(&mut self, label: Label) -> Result<&mut Self, PatternError>;
}
