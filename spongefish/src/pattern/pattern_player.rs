use std::sync::Arc;

use super::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length};

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
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The interaction doesn't match the expected pattern interaction
    /// - Maximum nesting depth is exceeded
    /// - There's a mismatched begin/end pair
    /// - The pattern is already finalized
    pub fn interact(&mut self, interaction: Interaction) {
        if self.finalized {
            panic!("Pattern player is already finalized");
        }

        let expected = self
            .pattern
            .interactions()
            .get(self.position)
            .unwrap_or_else(|| {
                panic!(
                    "No more expected interactions in pattern, got: {:?}",
                    interaction
                )
            });

        // Validate the interaction matches the expected one first
        if expected != &interaction {
            self.finalized = true;
            panic!(
                "Unexpected interaction: got {:?}, expected {:?}",
                interaction, expected
            );
        }

        // Validate hierarchy tracking
        match interaction.hierarchy() {
            Hierarchy::Begin => {
                if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
                    self.finalized = true;
                    panic!(
                        "Maximum nesting depth exceeded: {}",
                        Self::MAX_NESTING_DEPTH
                    );
                }
                self.hierarchy_stack.push(self.position);
            }
            Hierarchy::End => {
                let begin_pos = self
                    .hierarchy_stack
                    .pop()
                    .unwrap_or_else(|| panic!("Missing Begin for {:?}", interaction));

                if let Some(begin) = self.pattern.interactions().get(begin_pos) {
                    if !interaction.closes(begin) {
                        self.finalized = true;
                        panic!(
                            "Mismatched begin and end: begin {:?}, end {:?}",
                            begin, interaction
                        );
                    }
                }
            }
            Hierarchy::Atomic => {
                // Already validated above
            }
        }
        self.position += 1;
    }

    /// Mark the pattern playback as aborted.
    pub fn abort(&mut self) {
        if self.finalized {
            panic!("Pattern player is already finalized");
        }
        self.finalized = true;
    }

    /// Check if the pattern player is finalized.
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Finalize the pattern player.
    ///
    /// # Panics
    ///
    /// Panics if there are unfinished interactions.
    pub fn finalize(mut self) {
        if self.position > self.pattern.interactions().len() {
            panic!(
                "Pattern position {} exceeds pattern length {}",
                self.position,
                self.pattern.interactions().len()
            );
        }

        if self.finalized {
            panic!("Pattern player is already finalized");
        }

        if self.position < self.pattern.interactions().len() {
            let expected = &self.pattern.interactions()[self.position];
            panic!("Transcript not finished, expecting {:?}", expected);
        }

        self.finalized = true;
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
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions.
pub type PatternPlayer = PatternPlayerInner;

impl super::Pattern for PatternPlayer {
    fn abort(&mut self) -> &mut Self {
        self.abort();
        self
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length));
        self
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length));
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
        let pattern = PatternState::new().finalize();
        let player = PatternPlayer::new(Arc::new(pattern));
        // Just test that creation succeeds
        // PatternState::new().finalize() creates an empty pattern with just protocol begin/end
        // We can finalize immediately
        player.finalize();
    }

    #[test]
    fn test_pattern_player_simple_playback() {
        // Test that a player can be created and track a simple interaction
        let mut pattern_state = PatternState::new();
        pattern_state.ratchet();
        let pattern = Arc::new(pattern_state.finalize());

        let mut player = PatternPlayer::new(pattern);
        player.begin_protocol(Label::Protocol);
        player.interact(crate::pattern::interaction::Interaction::new::<()>(
            crate::pattern::interaction::Hierarchy::Atomic,
            crate::pattern::interaction::Kind::Protocol,
            Label::Ratchet,
            crate::pattern::Length::None,
        ));
        player.end_protocol(Label::Protocol);
        player.finalize();
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]
    fn test_pattern_player_unexpected_interaction() {
        // Test that mismatched interactions are detected
        let mut pattern_state = PatternState::new();
        pattern_state.ratchet();
        let pattern = Arc::new(pattern_state.finalize());

        let mut player = PatternPlayer::new(pattern);
        player.begin_protocol(Label::Protocol);

        // Try to interact with wrong kind (message instead of ratchet)
        player.begin_message::<u8>(Label::from("msg"), crate::pattern::Length::Fixed(32));
    }

    #[test]
    fn test_pattern_player_finalize_incomplete() {
        let mut pattern_state = PatternState::new();
        pattern_state.ratchet();
        let pattern = Arc::new(pattern_state.finalize());

        let mut player = PatternPlayer::new(pattern);
        player.begin_protocol(Label::Protocol);

        player.abort();
    }
}
