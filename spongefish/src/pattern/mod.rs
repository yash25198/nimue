//! Abstract interaction patterns for interactive protocols.
//!
//! # Overview
//!
//! The pattern system provides a structured way to define and enforce the interaction structure
//! of cryptographic protocols. It ensures that provers and verifiers follow the same protocol
//! structure, preventing mismatches that could compromise security.
//!
//! # Core Concepts
//!
//! ## Pattern Hierarchy
//!
//! The pattern system has three main components:
//!
//! 1. **[`PatternState`]**: Records interactions during protocol definition
//!    - Used to define the protocol structure
//!    - Validates proper nesting of interactions
//!    - Produces an [`InteractionPattern`] when finalized
//!
//! 2. **[`InteractionPattern`]**: Immutable protocol structure
//!    - Represents a finalized, validated protocol
//!    - Can be shared between prover and verifier
//!    - Generates domain separators for cryptographic operations
//!
//! 3. **[`PatternPlayer`]**: Validates execution against a pattern
//!    - Ensures runtime execution matches the defined pattern
//!    - Used internally by [`ProverState`](crate::ProverState) and [`VerifierState`](crate::VerifierState)
//!    - Returns errors on pattern mismatches
//!
//! ## Interaction Types
//!
//! - **Protocol**: Container for mixed interactions (begins/ends a sub-protocol)
//! - **Public**: Data agreed upon by both prover and verifier
//! - **Message**: Prover-to-verifier communication (appears in proof)
//! - **Hint**: Out-of-band prover-to-verifier information (not cryptographically bound)
//! - **Challenge**: Verifier-to-prover randomness (generated via Fiat-Shamir)
//!
//! ## Hierarchy Levels
//!
//! - **Atomic**: Single interaction (e.g., one message, one challenge)
//! - **Begin/End**: Marks boundaries of grouped interactions
//!
//! # Example
//!
//! ```ignore
//! use spongefish::pattern::{PatternState, Label};
//! use spongefish::codecs::bytes::Pattern;
//!
//! // Define a protocol pattern
//! let mut pattern = PatternState::<u8>::new();
//! pattern.begin_protocol(Label::custom("Schnorr"))?;
//! pattern.message_bytes(Label::custom("commitment"), 32)?;
//! pattern.challenge_bytes(Label::custom("challenge"), 32)?;
//! pattern.message_bytes(Label::custom("response"), 32)?;
//! pattern.end_protocol(Label::custom("Schnorr"))?;
//!
//! // Finalize to get immutable pattern
//!  let pattern = pattern.finalize().expect("Failed to finalize pattern");
//!
//! // Use pattern with prover/verifier
//! let mut prover = ProverState::from(&pattern);
//! // ... protocol execution ...
//! ```
//!
//! # Safety Invariants
//!
//! - Interactions must be properly nested (each `begin_*` matched with corresponding `end_*`)
//! - Maximum nesting depth is enforced to prevent stack overflow
//! - Type information is tracked to ensure type safety across protocol execution
//! - Labels must match between definition and execution

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

/// Trait for objects that implement hierarchical protocol operations.
///
/// This trait provides the foundation for managing protocol structure through hierarchical
/// begin/end operations. It does not offer any atomic [`Kind`] operations (like individual
/// messages or challenges); those must be implemented by specific protocol types.
///
/// # Design
///
/// The trait separates hierarchy management (this trait) from data operations (implemented
/// elsewhere). This allows for flexible composition where different data types can reuse
/// the same hierarchical structure.
///
/// # Example Implementation
///
/// ```ignore
/// impl Pattern for MyProtocol {
///     fn begin<T>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
///         // Track that we're beginning a new interaction group
///         self.hierarchy_stack.push(Interaction::new::<T>(Hierarchy::Begin, kind, label, length));
///         Ok(self)
///     }
///
///     fn end<T>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
///         // Validate and pop from hierarchy stack
///         // ...
///         Ok(self)
///     }
/// }
/// ```
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
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

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
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

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
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

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
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

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
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

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
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

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
