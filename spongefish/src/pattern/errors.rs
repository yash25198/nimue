use thiserror::Error;

use super::Interaction;

#[derive(Debug, Error)]
pub enum PatternError {
    #[error("Transcript is already finalized.")]
    AlreadyFinalized,
    #[error("No more expected interactions: {got}")]
    NoMoreExpected { got: Interaction },
    #[error("Unexpected interaction {got}, expected {expected}")]
    UnexpectedInteraction {
        expected: Interaction,
        got: Interaction,
    },
    #[error("Missing Begin for {end}")]
    MissingBegin { end: Interaction },
    #[error("Mismatched begin and end: {begin}, {end}")]
    MismatchedBeginEnd {
        begin: Interaction,
        end: Interaction,
    },
    #[error("Invalid kind {interaction} inside {begin}")]
    InvalidKind {
        begin: Interaction,
        interaction: Interaction,
    },
    #[error("Maximum nesting depth exceeded: {limit}")]
    DepthExceeded { limit: usize },
    #[error("Transcript not finished, expecting {expected}")]
    TranscriptNotFinished { expected: Interaction },
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("IO error: {0}")]
    IoError(std::io::Error),
    #[error("Size error: {0}")]
    SizeError(String),
    #[error("Transcript error: {0}")]
    TranscriptError(String),
}
