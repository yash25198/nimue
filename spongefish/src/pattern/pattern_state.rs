use super::{
    Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, PatternError, PatternResult,
};
use crate::codecs::unit;

/// Inner state for pattern construction.
///
/// This type contains the actual logic for recording interactions and validating
/// the pattern structure. It uses explicit `Result` returns for all operations
/// that can fail.
///
/// Use [`PatternState`] (the wrapper type) for ergonomic method chaining.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct PatternStateInner {
    /// Recorded interactions.
    interactions: Vec<Interaction>,
    /// Stack of open hierarchical interactions
    hierarchy_stack: Vec<usize>,
    /// Whether the transcript playback has been finalized.
    finalized: bool,
}

impl PatternStateInner {
    /// Maximum nesting depth for hierarchical interactions.
    const MAX_NESTING_DEPTH: usize = 64;

    /// Create a new pattern state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            interactions: Vec::new(),
            hierarchy_stack: Vec::new(),
            finalized: false,
        }
    }

    /// Add a new interaction to the pattern, returning an error on mismatch.
    pub fn interact(&mut self, interaction: Interaction) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }

        match interaction.hierarchy() {
            Hierarchy::Begin => {
                if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
                    return Err(PatternError::DepthExceeded {
                        limit: Self::MAX_NESTING_DEPTH,
                    });
                }
                self.hierarchy_stack.push(self.interactions.len());
            }
            Hierarchy::End => {
                let Some(begin_idx) = self.hierarchy_stack.pop() else {
                    return Err(PatternError::MissingBegin {
                        end: interaction.clone(),
                    });
                };
                let begin = &self.interactions[begin_idx];
                if !interaction.closes(begin) {
                    return Err(PatternError::MismatchedBeginEnd {
                        begin: begin.clone(),
                        end: interaction.clone(),
                    });
                }
            }
            Hierarchy::Atomic => {
                // Atomic interactions are valid at any level
            }
        }

        self.interactions.push(interaction);
        Ok(())
    }

    /// Mark the pattern as aborted.
    pub fn abort(&mut self) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }
        self.finalized = true;
        Ok(())
    }

    /// Convert to immutable [`InteractionPattern`].
    ///
    /// This method validates the pattern and wraps it in a protocol begin/end if needed.
    pub fn into_pattern(mut self) -> Result<InteractionPattern, PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }

        if !self.hierarchy_stack.is_empty() {
            return Err(PatternError::MismatchedBeginEnd {
                begin: self.interactions[*self.hierarchy_stack.last().unwrap()].clone(),
                end: self.interactions.last().cloned().unwrap_or_else(|| {
                    Interaction::new::<()>(
                        Hierarchy::End,
                        Kind::Protocol,
                        Label::Protocol,
                        Length::None,
                    )
                }),
            });
        }

        // Check if the pattern already has a protocol Begin/End at the top level
        let has_protocol_wrapper = self
            .interactions
            .first()
            .map(|i| i.hierarchy() == Hierarchy::Begin && i.kind() == Kind::Protocol)
            .unwrap_or(false)
            && self
                .interactions
                .last()
                .map(|i| i.hierarchy() == Hierarchy::End && i.kind() == Kind::Protocol)
                .unwrap_or(false);

        // If not wrapped in a protocol, wrap it automatically
        if !has_protocol_wrapper && !self.interactions.is_empty() {
            let mut wrapped = Vec::with_capacity(self.interactions.len() + 2);
            wrapped.push(Interaction::new::<()>(
                Hierarchy::Begin,
                Kind::Protocol,
                Label::Protocol,
                Length::None,
            ));
            wrapped.extend(self.interactions);
            wrapped.push(Interaction::new::<()>(
                Hierarchy::End,
                Kind::Protocol,
                Label::Protocol,
                Length::None,
            ));
            self.interactions = wrapped;
        }

        InteractionPattern::new(self.interactions)
            .map_err(|e| PatternError::TranscriptError(e.to_string()))
    }
}

/// Builder for constructing interaction patterns.
///
/// This is a wrapper around [`PatternStateInner`] that provides ergonomic method chaining
/// with automatic error propagation. Errors are accumulated and checked when [`finalize`]
/// is called.
///
/// # Example
///
/// ```ignore
/// use spongefish::pattern::{PatternState, Label};
/// use spongefish::codecs::bytes::Pattern;
///
/// let pattern = PatternState::new()
///     .message_bytes(Label::from("msg"), 32)
///     .challenge_bytes(Label::from("chal"), 32)
///     .finalize()?; // Check for errors here
/// ```
pub type PatternState = PatternResult<PatternStateInner>;

impl PatternState {
    /// Create a new pattern state.
    #[must_use]
    pub fn new() -> Self {
        PatternResult::from_value(PatternStateInner::new())
    }

    /// Finalize the pattern state into an immutable [`InteractionPattern`].
    ///
    /// This method consumes the `PatternState` and produces a validated [`InteractionPattern`]
    /// that can be used by both prover and verifier. It automatically wraps the interactions
    /// in a protocol begin/end if not already wrapped.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any previous operation failed (error was accumulated)
    /// - The pattern is already finalized
    /// - There are unclosed hierarchical interactions (unmatched begin/end pairs)
    /// - The interaction pattern validation fails
    pub fn finalize(self) -> Result<InteractionPattern, PatternError> {
        let inner = self.into_result()?;
        inner.into_pattern()
    }
}

impl Default for PatternState {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Pattern for PatternState {
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

impl unit::Pattern for PatternState {
    type Unit = u8;

    fn ratchet(&mut self) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<()>(
                Hierarchy::Atomic,
                Kind::Protocol,
                Label::Ratchet,
                Length::None,
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn public_unit(&mut self, label: Label) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Public,
                label,
                Length::Scalar,
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn public_units(&mut self, label: Label, size: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Public,
                label,
                Length::Fixed(size),
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn message_unit(&mut self, label: Label) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Message,
                label,
                Length::Scalar,
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn message_units(&mut self, label: Label, size: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Message,
                label,
                Length::Fixed(size),
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn challenge_unit(&mut self, label: Label) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Challenge,
                label,
                Length::Scalar,
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn challenge_units(&mut self, label: Label, size: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Challenge,
                label,
                Length::Fixed(size),
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn hint_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Hint,
                label,
                Length::Fixed(size),
            )) {
                self.set_error(e);
            }
        }
        self
    }

    fn hint_bytes_dynamic(&mut self, label: Label) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Hint,
                label,
                Length::Dynamic,
            )) {
                self.set_error(e);
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codecs::unit::Pattern as _, pattern::Pattern as _};

    #[test]
    fn test_pattern_state_new() {
        let state = PatternState::new();
        assert!(!state.has_error());
    }

    #[test]
    fn test_pattern_state_simple_message() {
        let mut state = PatternState::new();
        state.message_units(Label::from("msg"), 32);
        let pattern = state.finalize().unwrap();
        assert!(!pattern.interactions().is_empty());
    }

    #[test]
    fn test_pattern_state_chaining() {
        let mut state = PatternState::new();
        state.message_units(Label::from("msg"), 32);
        state.challenge_units(Label::from("chal"), 32);
        let pattern = state.finalize().unwrap();

        assert!(pattern.interactions().len() >= 2);
    }

    #[test]
    fn test_pattern_state_error_propagation() {
        let mut state = PatternState::new();
        // Create an unmatched end
        state.end::<()>(Label::Protocol, Kind::Protocol, Length::None);
        // Error is stored, check at finalize
        assert!(state.has_error());
    }

    #[test]
    fn test_pattern_state_nested_hierarchy() {
        let mut state = PatternState::new();
        state.begin_protocol(Label::from("test"));
        state.message_units(Label::from("msg"), 32);
        state.end_protocol(Label::from("test"));
        let pattern = state.finalize().unwrap();

        assert!(!pattern.interactions().is_empty());
    }

    #[test]
    fn test_pattern_state_unmatched_begin_error() {
        let mut state = PatternState::new();
        state.begin_protocol(Label::from("test"));
        state.message_units(Label::from("msg"), 32);
        // Don't call end_protocol
        let result = state.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_state_depth_exceeded() {
        let mut state = PatternState::new();
        // Try to exceed max nesting depth
        for i in 0..=PatternStateInner::MAX_NESTING_DEPTH {
            let label = Label::from(format!("level{}", i).as_str());
            state.begin_protocol(label);
            if i == PatternStateInner::MAX_NESTING_DEPTH {
                assert!(state.has_error());
                break;
            }
        }
    }
}
