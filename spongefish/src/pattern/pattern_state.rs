use std::marker::PhantomData;

use super::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, PatternError};
use crate::{codecs::unit, Unit};

/// Records an interaction pattern.
///
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct PatternState<U = u8>
where
    U: Unit,
{
    /// Recorded interactions.
    interactions: Vec<Interaction>,
    /// Stack of open hierarchical interactions
    hierarchy_stack: Vec<usize>, // Track hierarchy
    /// Whether the transcript playback has been finalized.
    finalized: bool,
    _unit: PhantomData<U>,
}

impl<U> PatternState<U>
where
    U: Unit,
{
    /// Maximum nesting depth for hierarchical interactions.
    const MAX_NESTING_DEPTH: usize = 64;
    #[must_use]
    pub const fn new() -> Self {
        Self {
            interactions: Vec::new(),
            hierarchy_stack: Vec::new(),
            finalized: false,
            _unit: PhantomData,
        }
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
    /// - The pattern is already finalized
    /// - There are unclosed hierarchical interactions (unmatched begin/end pairs)
    /// - The interaction pattern validation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut pattern = PatternState::<u8>::new();
    /// pattern.message_bytes(Label::custom("msg"), 32)?;
    /// let pattern = pattern.finalize()?;
    /// ```
    pub fn finalize(mut self) -> Result<InteractionPattern, PatternError> {
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

        match InteractionPattern::new(self.interactions) {
            Ok(transcript) => Ok(transcript),
            Err(e) => Err(PatternError::TranscriptError(e.to_string())),
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
}

impl<U> super::Pattern for PatternState<U>
where
    U: Unit,
{
    fn abort(&mut self) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }
        self.finalized = true;
        Ok(())
    }

    fn begin<T: ?Sized>(
        &mut self,
        label: Label,
        kind: Kind,
        length: Length,
    ) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))?;
        Ok(self)
    }

    fn end<T: ?Sized>(
        &mut self,
        label: Label,
        kind: Kind,
        length: Length,
    ) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))?;
        Ok(self)
    }
}

impl<U> unit::Pattern for PatternState<U>
where
    U: Unit,
{
    type Unit = U;

    fn ratchet(&mut self) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            Label::Ratchet,
            Length::None,
        ))?;
        Ok(self)
    }

    fn public_unit(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Scalar,
        ))?;
        Ok(self)
    }

    fn public_units(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(size),
        ))?;
        Ok(self)
    }

    fn message_unit(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ))?;
        Ok(self)
    }

    fn message_units(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(size),
        ))?;
        Ok(self)
    }

    fn challenge_unit(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ))?;
        Ok(self)
    }

    fn challenge_units(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(size),
        ))?;
        Ok(self)
    }

    fn hint_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(size),
        ))?;
        Ok(self)
    }

    fn hint_bytes_dynamic(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ))?;
        Ok(self)
    }
}
