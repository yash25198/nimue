use std::sync::Arc;

use super::{
    Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, PatternError, PatternResult,
};

/// Inner state for pattern playback.
///
/// This type contains the actual logic for playing back an interaction pattern
/// and validating that runtime execution matches the defined pattern.
///
/// Use [`PatternPlayer`] (the wrapper type) for method chaining.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PatternPlayerInner {
    /// Shared reference to the transcript.
    pattern: Arc<InteractionPattern>,
    /// Current position in the interaction pattern.
    position: usize,
    /// Stack to track the hierarchy of interactions.
    hierarchy_stack: Vec<usize>,
    /// Whether the transcript playback has been finalized.
    finalized: bool,
}

impl PatternPlayerInner {
    /// Maximum nesting depth for hierarchical interactions.
    const MAX_NESTING_DEPTH: usize = 64;

    /// Create a new pattern player.
    #[must_use]
    pub const fn new(pattern: Arc<InteractionPattern>) -> Self {
        Self {
            pattern,
            position: 0,
            hierarchy_stack: Vec::new(),
            finalized: false,
        }
    }

    /// Get a reference to the underlying pattern.
    #[must_use]
    pub fn pattern(&self) -> &Arc<InteractionPattern> {
        &self.pattern
    }

    /// Play the next interaction in the pattern.
    pub fn interact(&mut self, interaction: Interaction) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }

        let expected = self
            .pattern
            .interactions()
            .get(self.position)
            .ok_or_else(|| PatternError::NoMoreExpected {
                got: interaction.clone(),
            })?;

        // Validate the interaction matches the expected one first
        if expected != &interaction {
            self.finalized = true;
            return Err(PatternError::UnexpectedInteraction {
                expected: expected.clone(),
                got: interaction.clone(),
            });
        }

        // Validate hierarchy tracking
        match interaction.hierarchy() {
            Hierarchy::Begin => {
                if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
                    self.finalized = true;
                    return Err(PatternError::DepthExceeded {
                        limit: Self::MAX_NESTING_DEPTH,
                    });
                }
                self.hierarchy_stack.push(self.position);
            }
            Hierarchy::End => {
                let begin_pos =
                    self.hierarchy_stack
                        .pop()
                        .ok_or_else(|| PatternError::MissingBegin {
                            end: interaction.clone(),
                        })?;

                if let Some(begin) = self.pattern.interactions().get(begin_pos) {
                    if !interaction.closes(begin) {
                        self.finalized = true;
                        return Err(PatternError::MismatchedBeginEnd {
                            begin: begin.clone(),
                            end: interaction.clone(),
                        });
                    }
                }
            }
            Hierarchy::Atomic => {
                // Already validated above
            }
        }
        self.position += 1;
        Ok(())
    }

    /// Mark the pattern playback as aborted.
    pub fn abort(&mut self) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }
        self.finalized = true;
        Ok(())
    }

    /// Finalize the sequence of interactions. Returns an error if there
    /// are unfinished interactions.
    pub fn finalize_inner(&mut self) -> Result<(), PatternError> {
        if self.position > self.pattern.interactions().len() {
            return Err(PatternError::DepthExceeded {
                limit: self.position,
            });
        }

        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }

        if self.position < self.pattern.interactions().len() {
            let expected = self.pattern.interactions()[self.position].clone();
            return Err(PatternError::TranscriptNotFinished { expected });
        }

        self.finalized = true;
        Ok(())
    }
}

impl Drop for PatternPlayerInner {
    fn drop(&mut self) {
        if !self.finalized && self.pattern.interactions().len() > 0 {
            // Always panic for non-empty patterns that weren't finalized
            // This catches all programmer bugs: never used, incomplete, or forgot to finalize
            // The escape hatch: call abort() explicitly to mark as finalized
            panic!("Dropped unfinalized transcript.");
        }
    }
}

/// Play back an interaction pattern and make sure all interactions match up.
///
/// This is a wrapper around [`PatternPlayerInner`] that provides ergonomic method chaining
/// with automatic error propagation.
///
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions (the inner `PatternPlayerInner`
/// is not properly finalized).
pub type PatternPlayer = PatternResult<PatternPlayerInner>;

impl PatternPlayer {
    /// Create a new pattern player.
    #[must_use]
    pub fn new(pattern: Arc<InteractionPattern>) -> Self {
        PatternResult::from_value(PatternPlayerInner::new(pattern))
    }

    /// Get a reference to the underlying pattern.
    pub fn pattern(&self) -> Option<&Arc<InteractionPattern>> {
        self.inner().map(|inner| inner.pattern())
    }

    /// Finalize the sequence of interactions. Returns an error if there
    /// are unfinished interactions.
    pub fn finalize(mut self) -> Result<(), PatternError> {
        let inner = self.inner_mut().ok_or(PatternError::AlreadyFinalized)?;
        inner.finalize_inner()?;
        // Don't call PatternResult::finalize() because we want to consume self
        // and let the inner Drop handler run to check finalization
        Ok(())
    }
}

impl super::Pattern for PatternPlayer {
    fn abort(&mut self) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.abort() {
                self.set_error(e);
            }
        }
        self
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) =
                inner.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))
            {
                self.set_error(e);
            }
        }
        self
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) =
                inner.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))
            {
                self.set_error(e);
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codecs::unit::Pattern as _,
        pattern::{Pattern as _, PatternState},
    };

    #[test]
    fn test_pattern_player_new() {
        let pattern = PatternState::new().finalize().unwrap();
        let mut player = PatternPlayer::new(Arc::new(pattern));
        // Just test that creation succeeds
        // PatternState::new().finalize() creates an empty pattern with just protocol begin/end
        // We can finalize immediately
        player.finalize().unwrap();
    }

    #[test]
    fn test_pattern_player_simple_playback() {
        // Test that a player can be created and track a simple interaction
        let mut pattern_state = PatternState::new();
        pattern_state.ratchet();
        let pattern = Arc::new(pattern_state.finalize().unwrap());

        let mut player = PatternPlayer::new(pattern);
        player.begin_protocol(Label::Protocol);
        player
            .inner_mut()
            .unwrap()
            .interact(crate::pattern::interaction::Interaction::new::<()>(
                crate::pattern::interaction::Hierarchy::Atomic,
                crate::pattern::interaction::Kind::Protocol,
                Label::Ratchet,
                crate::pattern::Length::None,
            ))
            .unwrap();
        player.end_protocol(Label::Protocol);
        player.finalize().unwrap();
    }

    #[test]
    fn test_pattern_player_unexpected_interaction() {
        // Test that mismatched interactions are detected
        let mut pattern_state = PatternState::new();
        pattern_state.ratchet();
        let pattern = Arc::new(pattern_state.finalize().unwrap());

        let mut player = PatternPlayer::new(pattern);
        player.begin_protocol(Label::Protocol);

        // Try to interact with wrong kind (message instead of ratchet)
        player.begin_message::<u8>(Label::from("msg"), crate::pattern::Length::Fixed(32));

        // Should have error due to pattern mismatch
        assert!(player.has_error());
        let _ = player.abort();
    }

    #[test]
    fn test_pattern_player_finalize_incomplete() {
        let mut pattern_state = PatternState::new();
        pattern_state.ratchet();
        let pattern = Arc::new(pattern_state.finalize().unwrap());

        let mut player = PatternPlayer::new(pattern);
        player.begin_protocol(Label::Protocol);

        assert!(!player.has_error());
        player.abort();
    }
}
