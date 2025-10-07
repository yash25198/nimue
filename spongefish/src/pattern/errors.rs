use thiserror::Error;

use super::Interaction;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PatternError {
    #[error("Transcript is already finalized.")]
    AlreadyFinalized,
    #[error("Received interaction, but no more expected interactions: {got}")]
    NoMoreExpected { got: Interaction },
    #[error("Received interaction {got}, but expected {expected}")]
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
    #[error("Unclosed hierarchical interactions remain")]
    UnclosedHierarchy,
    #[error("Error validating interaction pattern: {0}")]
    ValidationError(String),
    #[error("Protocol structure validation failed: unmatched begin/end protocol calls (depth: {depth})")]
    UnmatchedProtocolCalls { depth: usize },
    #[error("Protocol structure validation failed: protocol must start with begin_protocol() call")]
    MissingBeginProtocol,
    #[error("Protocol structure validation failed: protocol must end with end_protocol() call")]
    MissingEndProtocol,
}


