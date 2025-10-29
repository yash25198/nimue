use super::{labels, Hierarchy, Interaction, InteractionPattern, Kind, Label, Length};
use crate::codecs::unit;

/// Builder for constructing interaction patterns.
///
/// Errors during pattern construction (e.g., mismatched begin/end, already finalized)
/// will panic. This is intentional since it indicates a programming error.
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
///     .finalize();
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PatternState {
    /// Recorded interactions.
    interactions: Vec<Interaction>,
    /// Stack of open hierarchical interactions
    hierarchy_stack: Vec<usize>,
    /// Whether the transcript playback has been finalized.
    finalized: bool,
}

impl PatternState {
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

    /// Add a new interaction to the pattern.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The pattern is already finalized
    /// - Nesting depth exceeds maximum
    /// - Begin/end interactions are mismatched
    pub fn interact(&mut self, interaction: Interaction) {
        if self.finalized {
            panic!("Pattern is already finalized");
        }

        match interaction.hierarchy() {
            Hierarchy::Begin => {
                if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
                    panic!(
                        "Nesting depth exceeded maximum of {}",
                        Self::MAX_NESTING_DEPTH
                    );
                }
                self.hierarchy_stack.push(self.interactions.len());
            }
            Hierarchy::End => {
                let Some(begin_idx) = self.hierarchy_stack.pop() else {
                    panic!("End interaction without matching Begin: {:?}", interaction);
                };
                let begin = &self.interactions[begin_idx];
                if !interaction.closes(begin) {
                    panic!(
                        "Mismatched begin and end: Begin {:?} End {:?}",
                        begin, interaction
                    );
                }
            }
            Hierarchy::Atomic => {
                // Atomic interactions are valid at any level
            }
        }

        self.interactions.push(interaction);
    }

    /// Mark the pattern as aborted.
    ///
    /// # Panics
    ///
    /// Panics if the pattern is already finalized.
    pub fn abort(&mut self) {
        if self.finalized {
            panic!("Pattern is already finalized");
        }
        self.finalized = true;
    }

    /// Convert to immutable [`InteractionPattern`].
    ///
    /// This method validates the pattern and wraps it in a protocol begin/end if needed.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The pattern is already finalized
    /// - There are unclosed hierarchical interactions
    fn into_pattern(mut self) -> InteractionPattern {
        if self.finalized {
            panic!("Pattern is already finalized");
        }

        if !self.hierarchy_stack.is_empty() {
            let begin = &self.interactions[*self.hierarchy_stack.last().unwrap()];
            panic!("Unclosed hierarchical interaction: Begin {:?}", begin);
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
                labels::PROTOCOL,
                Length::None,
            ));
            wrapped.extend(self.interactions);
            wrapped.push(Interaction::new::<()>(
                Hierarchy::End,
                Kind::Protocol,
                labels::PROTOCOL,
                Length::None,
            ));
            self.interactions = wrapped;
        }

        InteractionPattern::new(self.interactions)
            .unwrap_or_else(|e| panic!("Pattern validation error: {}", e))
    }

    /// Finalize the pattern state into an immutable [`InteractionPattern`].
    ///
    /// This method consumes the `PatternState` and produces a validated [`InteractionPattern`]
    /// that can be used by both prover and verifier. It automatically wraps the interactions
    /// in a protocol begin/end if not already wrapped.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The pattern is already finalized
    /// - There are unclosed hierarchical interactions (unmatched begin/end pairs)
    /// - The interaction pattern validation fails
    pub fn finalize(self) -> InteractionPattern {
        self.into_pattern()
    }
}

impl Default for PatternState {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Pattern for PatternState {
    fn abort(&mut self) -> &mut Self {
        PatternState::abort(self);
        self
    }

    fn begin<T: ?Sized>(&mut self, label: impl AsRef<str>, kind: Kind, length: Length) -> &mut Self {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length));
        self
    }

    fn end<T: ?Sized>(&mut self, label: impl AsRef<str>, kind: Kind, length: Length) -> &mut Self {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length));
        self
    }
}

impl unit::Pattern for PatternState {
    type Unit = u8;

    fn ratchet(&mut self) -> &mut Self {
        self.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            labels::RATCHET,
            Length::None,
        ));
        self
    }

    fn message_public_unit(&mut self, label: impl AsRef<str>) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Scalar,
        ));
        self
    }

    fn message_public_units(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(size),
        ));
        self
    }

    fn message_unit(&mut self, label: impl AsRef<str>) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ));
        self
    }

    fn message_units(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(size),
        ));
        self
    }

    fn challenge_unit(&mut self, label: impl AsRef<str>) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ));
        self
    }

    fn challenge_units(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(size),
        ));
        self
    }

    fn hint_bytes(&mut self, label: impl AsRef<str>, size: usize) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(size),
        ));
        self
    }

    fn hint_bytes_dynamic(&mut self, label: impl AsRef<str>) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codecs::unit::Pattern as _, pattern::Pattern as _};

    #[test]
    fn test_pattern_state_new() {
        let _state = PatternState::new();
    }

    #[test]
    fn test_pattern_state_simple_message() {
        let mut state = PatternState::new();
        state.message_units(Label::from("msg"), 32);
        let pattern = state.finalize();
        assert!(!pattern.interactions().is_empty());
    }

    #[test]
    fn test_pattern_state_chaining() {
        let mut state = PatternState::new();
        state.message_units(Label::from("msg"), 32);
        state.challenge_units(Label::from("chal"), 32);
        let pattern = state.finalize();

        assert!(pattern.interactions().len() >= 2);
    }

    #[test]
    #[should_panic(expected = "End interaction without matching Begin")]
    fn test_pattern_state_error_propagation() {
        let mut state = PatternState::new();
        // Create an unmatched end
        state.end::<()>(labels::PROTOCOL, Kind::Protocol, Length::None);
        state.finalize();
    }

    #[test]
    fn test_pattern_state_nested_hierarchy() {
        let mut state = PatternState::new();
        state.begin_protocol(Label::from("test"));
        state.message_units(Label::from("msg"), 32);
        state.end_protocol(Label::from("test"));
        let pattern = state.finalize();

        assert!(!pattern.interactions().is_empty());
    }

    #[test]
    #[should_panic(expected = "Unclosed hierarchical interaction")]
    fn test_pattern_state_unmatched_begin_error() {
        let mut state = PatternState::new();
        state.begin_protocol(Label::from("test"));
        state.message_units(Label::from("msg"), 32);
        // Don't call end_protocol
        state.finalize();
    }

    #[test]
    #[should_panic(expected = "Nesting depth exceeded")]
    fn test_pattern_state_depth_exceeded() {
        let mut state = PatternState::new();
        // Try to exceed max nesting depth
        for i in 0..=PatternState::MAX_NESTING_DEPTH {
            let label = Label::from(format!("level{}", i).as_str());
            state.begin_protocol(label);
        }
        state.finalize();
    }
}
