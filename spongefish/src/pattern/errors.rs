use thiserror::Error;

use super::Interaction;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PatternError {
    #[error("Transcript is already finalized.")]
    AlreadyFinalized,
    #[error("No more expected interactions: {got}")]
    NoMoreExpected { got: Interaction },
    #[error("Unexpected interaction {got}, expected {expected}")]
    UnexpectedInteraction { expected: Interaction, got: Interaction },
    #[error("Missing Begin for {end}")]
    MissingBegin { end: Interaction },
    #[error("Mismatched begin and end: {begin}, {end}")]
    MismatchedBeginEnd { begin: Interaction, end: Interaction },
    #[error("Invalid kind {interaction} inside {begin}")]
    InvalidKind { begin: Interaction, interaction: Interaction },
    #[error("Maximum nesting depth exceeded: {limit}")]
    DepthExceeded { limit: usize },
    #[error("Transcript not finished, expecting {expected}")]
    TranscriptNotFinished { expected: Interaction },
    #[error("Deserialization error")]
    DeserializationError,
}