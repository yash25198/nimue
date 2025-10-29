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
//! let mut pattern = PatternState::new();
//! pattern.begin_protocol(Label::new("Schnorr"))?;
//! pattern.message_bytes(Label::new("commitment"), 32)?;
//! pattern.challenge_bytes(Label::new("challenge"), 32)?;
//! pattern.message_bytes(Label::new("response"), 32)?;
//! pattern.end_protocol(Label::new("Schnorr"))?;
//!
//! // Finalize to get immutable pattern
//!  let pattern = pattern.finalize();
//!
//! // Use pattern with prover/verifier
//! let mut prover = ProverState::from(pattern);
//! // ... protocol execution ...
//! ```
//!
//! # Safety Invariants
//!
//! - Interactions must be properly nested (each `begin_*` matched with corresponding `end_*`)
//! - Maximum nesting depth is enforced to prevent stack overflow
//! - Type information is tracked to ensure type safety across protocol execution
//! - Labels must match between definition and execution

mod errors;
mod interaction;
mod interaction_pattern;
mod pattern_player;
mod pattern_state;

pub use self::{
    errors::PatternError,
    interaction::{labels, Hierarchy, Interaction, Kind, Label, Length},
    interaction_pattern::{InteractionPattern, TranscriptError},
    pattern_player::{PatternPlayer, PatternPlayerInner},
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
///     fn begin<T>(&mut self, label: impl AsRef<str>, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
///         // Track that we're beginning a new interaction group
///         self.hierarchy_stack.push(Interaction::new::<T>(Hierarchy::Begin, kind, label, length));
///         Ok(self)
///     }
///
///     fn end<T>(&mut self, label: impl AsRef<str>, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
///         // Validate and pop from hierarchy stack
///         // ...
///         Ok(self)
///     }
/// }
/// ```
pub trait Pattern {
    /// End a transcript without finalizing it.
    fn abort(&mut self) -> &mut Self;

    /// Begin of a group of interactions.
    fn begin<T: ?Sized>(&mut self, label: impl AsRef<str>, kind: Kind, length: Length) -> &mut Self;

    /// End of a group of interactions.
    fn end<T: ?Sized>(&mut self, label: impl AsRef<str>, kind: Kind, length: Length) -> &mut Self;

    /// Begin of a subprotocol.
    fn begin_protocol(&mut self, label: impl AsRef<str>) -> &mut Self {
        self.begin::<()>(label, Kind::Protocol, Length::None)
    }

    /// End of a subprotocol.
    fn end_protocol(&mut self, label: impl AsRef<str>) -> &mut Self {
        self.end::<()>(label, Kind::Protocol, Length::None)
    }

    /// Begin of a public message interaction.
    fn begin_public<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
        self.begin::<T>(label, Kind::Public, length)
    }

    /// End of a public message interaction.
    fn end_public<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
        self.end::<T>(label, Kind::Public, length)
    }

    /// Begin of a message interaction.
    fn begin_message<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
        self.begin::<T>(label, Kind::Message, length)
    }

    /// End of a message interaction.
    fn end_message<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
        self.end::<T>(label, Kind::Message, length)
    }

    /// Begin of a hint interaction.
    fn begin_hint<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
        self.begin::<T>(label, Kind::Hint, length)
    }

    /// End of a hint interaction.
    fn end_hint<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
        self.end::<T>(label, Kind::Hint, length)
    }

    /// Begin of a challenge interaction.
    fn begin_challenge<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
        self.begin::<T>(label, Kind::Challenge, length)
    }

    /// End of a challenge interaction.
    fn end_challenge<T: ?Sized>(&mut self, label: impl AsRef<str>, length: Length) -> &mut Self {
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
    use crate::codecs::unit::Pattern as _;

    #[test]
    fn test_record_playback() {
        // Record a new pattern
        let mut pattern = PatternState::new();
        pattern.begin_protocol(labels::PROTOCOL);
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
        pattern.end_protocol(labels::PROTOCOL);
        let pattern = pattern.finalize();

        // Play it back exactly
        let mut playback = PatternPlayer::new(pattern.into());
        playback.begin_protocol(labels::PROTOCOL);
        playback.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
        playback.end_protocol(labels::PROTOCOL);
        playback.finalize();
    }

    #[test]
    #[should_panic(expected = "Dropped unfinalized transcript.")]
    fn panics_if_playback_not_finalized() {
        // Create a simple pattern with just a ratchet
        let mut pattern = PatternState::new();
        pattern.ratchet();
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.begin_protocol(labels::PROTOCOL);
        playback.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            labels::RATCHET,
            Length::None,
        ));
        playback.end_protocol(labels::PROTOCOL);
    }

    #[test]
    #[should_panic(expected = "Mismatched begin and end")]
    fn panics_if_record_begin_end_mismatch() {
        let mut pattern = PatternState::new();
        pattern.begin_protocol(labels::PROTOCOL);
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
        pattern.end_protocol(labels::PROTOCOL);
        pattern.finalize();
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]
    fn panics_if_type_mismatch() {
        let mut pattern = PatternState::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
             labels::PROTOCOL,
            Length::None,
        ));
        // This should panic
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]
    fn panics_if_kind_mismatch() {
        let mut pattern = PatternState::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Message,
            "message",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
             labels::PROTOCOL,
            Length::None,
        ));
        // This should panic
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Public,
            "public",
            Length::Scalar,
        ));
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]
    fn panics_if_label_mismatch() {
        let mut pattern = PatternState::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
             labels::PROTOCOL,
            Length::None,
        ));
        // This should panic
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]
    fn panics_if_length_mismatch() {
        let mut pattern = PatternState::new();
        pattern.interact(Interaction::new::<u64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Scalar,
        ));
        let pattern = pattern.finalize();

        let mut playback = PatternPlayer::new(pattern.into());
        playback.interact(Interaction::new::<()>(
            Hierarchy::Begin,
            Kind::Protocol,
             labels::PROTOCOL,
            Length::None,
        ));
        // This should panic
        playback.interact(Interaction::new::<f64>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "challenge",
            Length::Fixed(1),
        ));
    }
}
