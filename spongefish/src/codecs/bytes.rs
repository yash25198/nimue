use crate::{
    codecs::unit::Pattern as _,
    pattern::{Label, Length, Pattern as _, PatternError, PatternState},
};

/// Traits for patterns that handle byte arrays in a transcript.
pub trait Pattern {
    fn public_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError>;
    fn message_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError>;
    fn challenge_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError>;
}

/// Implementation where `Unit = u8`
impl Pattern for PatternState<u8> {
    fn public_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.begin_public::<u8>(label.clone(), Length::Fixed(size))?;
        self.public_units(Label::custom("units"), size)?;
        self.end_public::<u8>(label, Length::Fixed(size))?;
        Ok(self)
    }

    fn message_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.begin_message::<u8>(label.clone(), Length::Fixed(size))?;
        self.message_units(Label::custom("units"), size)?;
        self.end_message::<u8>(label, Length::Fixed(size))?;
        Ok(self)
    }

    fn challenge_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.begin_challenge::<u8>(label.clone(), Length::Fixed(size))?;
        self.challenge_units(Label::custom("units"), size)?;
        self.end_challenge::<u8>(label, Length::Fixed(size))?;
        Ok(self)
    }
}