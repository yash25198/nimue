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
    /// Queued interactions to be validated on finalize.
    queued_interactions: Vec<Interaction>,
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
    const MAX_NESTING_DEPTH: usize = 64;
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queued_interactions: Vec::new(),
            hierarchy_stack: Vec::new(),
            finalized: false,
            _unit: PhantomData,
        }
    }

    #[must_use]
    pub fn finalize(self) -> Result<InteractionPattern, PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }
        if !self.hierarchy_stack.is_empty() {
            return Err(PatternError::UnclosedHierarchy);
        }
        match InteractionPattern::new(self.queued_interactions) {
            Ok(transcript) => Ok(transcript),
            Err(e) => Err(PatternError::ValidationError(e.to_string())),
        }
    }


    /// Add a new interaction to the pattern, panicking on validation errors.
    pub fn interact(&mut self, interaction: Interaction) -> &mut Self {
        if self.finalized {
            panic!("Cannot add interactions to finalized pattern");
        }

        match interaction.hierarchy() {
            Hierarchy::Begin => {
                if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
                    panic!("Maximum nesting depth exceeded: {}", Self::MAX_NESTING_DEPTH);
                }
                self.hierarchy_stack.push(self.queued_interactions.len());
            }
            Hierarchy::End => {
                let Some(begin_idx) = self.hierarchy_stack.pop() else {
                    panic!("Missing Begin for {}", interaction);
                };
                let begin = &self.queued_interactions[begin_idx];
                if !interaction.closes(begin) {
                    panic!("Mismatched begin and end: {}, {}", begin, interaction);
                }
            }
            Hierarchy::Atomic => {
                // Atomic interactions are valid at any level
            }
        }

        self.queued_interactions.push(interaction);
        self
    }


    /// Return the last unclosed [`Hierachy::Begin`] interaction.
    fn last_open_begin(&self) -> Option<&Interaction> {
        self.hierarchy_stack
            .last()
            .map(|&idx| &self.queued_interactions[idx])
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

    fn in_hierarchy(&self) -> bool {
        !self.hierarchy_stack.is_empty()
    }

    fn depth(&self) -> usize {
        self.hierarchy_stack.len()
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
        let interaction = Interaction::new::<T>(Hierarchy::Begin, kind, label, length);
        
        // Validate the interaction
        if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
            return Err(PatternError::DepthExceeded { limit: Self::MAX_NESTING_DEPTH });
        }
        
        self.hierarchy_stack.push(self.queued_interactions.len());
        self.queued_interactions.push(interaction);
        Ok(self)
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
        let interaction = Interaction::new::<T>(Hierarchy::End, kind, label, length);
        
        // Validate the interaction
        let Some(begin_idx) = self.hierarchy_stack.pop() else {
            return Err(PatternError::MissingBegin { end: interaction });
        };
        let begin = &self.queued_interactions[begin_idx];
        if !interaction.closes(begin) {
            return Err(PatternError::MismatchedBeginEnd { begin: begin.clone(), end: interaction });
        }
        
        self.queued_interactions.push(interaction);
        Ok(self)
    }
}

// TODO: We will turn this into `unit::Pattern` later.
impl<U> unit::Pattern for PatternState<U>
where
    U: Unit,
{
    type Unit = U;

    fn ratchet(&mut self) -> &mut Self {
        self.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            "ratchet",
            Length::None,
        ))
    }

    fn public_unit(&mut self, label: Label) -> &mut Self {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Scalar,
        ))
    }

    fn public_units(&mut self, label: Label, size: usize) -> &mut Self {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(size),
        ))
    }

    fn message_unit(&mut self, label: Label) -> &mut Self {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ))
    }

    fn message_units(&mut self, label: Label, size: usize) -> &mut Self {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(size),
        ))
    }

    fn challenge_unit(&mut self, label: Label) -> &mut Self {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ))
    }

    fn challenge_units(&mut self, label: Label, size: usize) -> &mut Self {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(size),
        ))
    }

    fn hint_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(size),
        ))
    }

    fn hint_bytes_dynamic(&mut self, label: Label) -> &mut Self {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ))
    }
}
