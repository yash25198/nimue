use crate::{
    codecs::unit::Pattern as _,
    pattern::{labels, Length, Pattern as _, PatternState},
};

pub trait Pattern {
    fn message_public_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self;
    fn message_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self;
    fn challenge_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self;
}

impl Pattern for PatternState {
    fn message_public_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self {
        self.begin_public::<u8>(&label, Length::Fixed(size));
        self.message_public_units(labels::UNITS, size);
        self.end_public::<u8>(label, Length::Fixed(size));
        self
    }

    fn message_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self {
        self.begin_message::<u8>(&label, Length::Fixed(size));
        self.message_units(labels::UNITS, size);
        self.end_message::<u8>(label, Length::Fixed(size));
        self
    }

    fn challenge_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self {
        self.begin_challenge::<u8>(&label, Length::Fixed(size));
        self.challenge_units(labels::UNITS, size);
        self.end_challenge::<u8>(label, Length::Fixed(size));
        self
    }
}
