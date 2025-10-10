//! Abstract interaction patterns for interactive protocols.

mod interaction;
mod interaction_pattern;
mod pattern_player;
mod pattern_state;
mod errors;

pub use self::{
    interaction::{Hierarchy, Interaction, Kind, Label, Length},
    interaction_pattern::{InteractionPattern, TranscriptError},
    errors::PatternError,
    pattern_player::PatternPlayer,
    pattern_state::PatternState,
};

/// Trait for objects that implement hierarchy operations.
///
/// It does not offer any [`Kind::Atomic`] operations, these need to be implemented specifically./// Trait for objects that implement hierarchy operations.
pub trait Pattern {
    /// End a transcript without finalizing it.
    fn abort(&mut self) -> Result<(), PatternError>;

    /// Begin of a group of interactions.
    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError>;

    /// End of a group of interactions.
    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError>;

    /// Begin of a subprotocol.
    fn begin_protocol(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.begin::<()>(label, Kind::Protocol, Length::None)
    }

    /// End of a subprotocol.
    fn end_protocol(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.end::<()>(label, Kind::Protocol, Length::None)
    }

    /// Begin of a public message interaction.
    fn begin_public<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.begin::<T>(label, Kind::Public, length)
    }

    /// End of a public message interaction.
    fn end_public<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.end::<T>(label, Kind::Public, length)
    }

    /// Begin of a message interaction.
    fn begin_message<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.begin::<T>(label, Kind::Message, length)
    }

    /// End of a message interaction.
    fn end_message<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.end::<T>(label, Kind::Message, length)
    }

    /// Begin of a hint interaction.
    fn begin_hint<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.begin::<T>(label, Kind::Hint, length)
    }

    /// End of a hint interaction.
    fn end_hint<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.end::<T>(label, Kind::Hint, length)
    }

    /// Begin of a challenge interaction.
    fn begin_challenge<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.begin::<T>(label, Kind::Challenge, length)
    }

    /// End of a challenge interaction.
    fn end_challenge<T: ?Sized>(&mut self, label: Label, length: Length) -> Result<&mut Self, PatternError> {
        self.end::<T>(label, Kind::Challenge, length)
    }
}
/// Aliases offered for convenience.
pub use Pattern as Common;
/// Aliases offered for convenience.
pub use Pattern as Verifier;
/// Aliases offered for convenience.
pub use Pattern as Prover;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_playback() {
        // Record a new pattern
        let mut pattern = PatternState::<u8>::new();
        pattern.begin_protocol(Label::custom("Example protocol")).expect("Failed to begin protocol");
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        pattern.end_protocol(Label::custom("Example protocol")).expect("Failed to end protocol");
        let pattern = pattern.finalize();

        // Play it back exactly
        let mut playback = PatternPlayer::new(pattern.into());
        playback.begin_protocol(Label::custom("Example protocol")).expect("Failed to begin protocol");
        playback.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        playback.end_protocol(Label::custom("Example protocol")).expect("Failed to end protocol");
        playback.finalize().expect("Failed to finalize");
    }

    #[test]
    #[should_panic(expected = "Dropped unfinalized transcript.")]
    fn panics_if_playback_not_finalized() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
            Label::PROTOCOL,
            Length::None,
        )).expect("Failed to interact with pattern");
    }

    #[test]

    fn panics_if_record_begin_end_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.begin_protocol(Label::custom("Example protocol")).expect("Failed to begin protocol");
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        let result = pattern.end_protocol(Label::custom("Invalid example protocol"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PatternError::MismatchedBeginEnd { .. }));
    }

    #[test]

    fn panics_if_type_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
            Label::PROTOCOL,
            Length::None,
        )).expect("Failed to interact with pattern");
        let result = playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        ));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PatternError::UnexpectedInteraction { .. }));
    }

    #[test]
 
    fn panics_if_kind_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Message,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
            Label::PROTOCOL,
            Length::None,
        )).expect("Failed to interact with pattern");
        let result = playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Public,
            Label::custom("nonce"),
            Length::Scalar,
        ));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PatternError::UnexpectedInteraction { .. }));
    }

    #[test]
  
    fn panics_if_label_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
            Label::PROTOCOL,
            Length::None,
        )).expect("Failed to interact with pattern");
        let result = playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("invalid"),
            Length::Scalar,
        ));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PatternError::UnexpectedInteraction { .. }));
    }

    #[test]

    fn panics_if_length_mismatch() {
        let mut pattern = PatternState::<u8>::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Scalar,
        )).expect("Failed to interact with pattern");
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
            Label::PROTOCOL,
            Length::None,
        )).expect("Failed to interact with pattern");
        let result = playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("nonce"),
            Length::Fixed(1),
        ));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PatternError::UnexpectedInteraction { .. })); 
    }
}
