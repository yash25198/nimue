use crate::{
    codecs::unit::Pattern as _,
    pattern::{Label, Length, Pattern as _, PatternState},
};

/// Traits for patterns that handle byte arrays in a transcript.
pub trait Pattern {
    fn public_bytes(&mut self, label: Label, size: usize) -> &mut Self;
    fn message_bytes(&mut self, label: Label, size: usize) -> &mut Self;
    fn challenge_bytes(&mut self, label: Label, size: usize) -> &mut Self;
}

/// Implementation where `Unit = u8`
impl Pattern for PatternState<u8> {
    fn public_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        self.begin_public::<u8>(label, Length::Fixed(size))
            .public_units("units", size)
            .end_public::<u8>(label, Length::Fixed(size))
    }

    fn message_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        self.begin_message::<u8>(label, Length::Fixed(size))
            .message_units("units", size)
            .end_message::<u8>(label, Length::Fixed(size))
    }

    fn challenge_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        self.begin_challenge::<u8>(label, Length::Fixed(size))
            .challenge_units("units", size)
            .end_challenge::<u8>(label, Length::Fixed(size))
    }
}
