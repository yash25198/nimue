use std::marker::PhantomData;

use super::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length};
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
    #[must_use]
    pub const fn new() -> Self {
        Self {
            interactions: Vec::new(),
            hierarchy_stack: Vec::new(),
            finalized: false,
            _unit: PhantomData,
        }
    }

    #[must_use]
    pub fn finalize(self) -> InteractionPattern {
        assert!(!self.finalized, "Transcript is already finalized.");
        assert!(
            self.hierarchy_stack.is_empty(),
            "Unclosed hierarchical interactions remain"
        );
        match InteractionPattern::new(self.interactions) {
            Ok(transcript) => transcript,
            Err(e) => panic!("Error validating interaction pattern: {e}"),
        }
    }

    /// Add a new interaction to the pattern.
    ///
    /// # Panics
    ///
    /// Panics if
    /// - the interaction does not match the parent kind and
    ///   the parent kind is not [`Kind::Protocol`],
    /// - the it is an [`Hierarchy::End`], but there is either no
    ///   [`Hierarchy::Begin`] or it does not match the end.being
    pub fn interact(&mut self, interaction: Interaction) {
        assert!(!self.finalized, "Transcript is already finalized.");

        match interaction.hierarchy() {
            Hierarchy::Begin => {
                self.hierarchy_stack.push(self.interactions.len());
            }
            Hierarchy::End => {
                let Some(begin_idx) = self.hierarchy_stack.pop() else {
                    panic!("Missing begin for {interaction}");
                };
                let begin = &self.interactions[begin_idx];
                assert!(
                    interaction.closes(begin),
                    "Mismatched begin and end: {begin}, {interaction}"
                );
            }
            Hierarchy::Atomic => {
                // Atomic interactions are valid at any level
            }
        }

        self.interactions.push(interaction);
    }

    /// Return the last unclosed [`Hierachy::Begin`] interaction.
    fn last_open_begin(&self) -> Option<&Interaction> {
        self.hierarchy_stack
            .last()
            .map(|&idx| &self.interactions[idx])
    }
}

impl<U> super::Pattern for PatternState<U>
where
    U: Unit,
{
    fn abort(&mut self) {
        assert!(!self.finalized, "Transcript is already finalized.");
        self.finalized = true;
    }

    fn in_hierarchy(&self) -> bool {
        !self.hierarchy_stack.is_empty()
    }

    fn depth(&self) -> usize {
        self.hierarchy_stack.len()
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length));
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length));
    }
}

// TODO: We will turn this into `unit::Pattern` later.
impl<U> unit::Pattern for PatternState<U>
where
    U: Unit,
{
    type Unit = U;

    fn ratchet(&mut self) {
        self.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            "ratchet",
            Length::None,
        ));
    }

    fn public_unit(&mut self, label: Label) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Scalar,
        ));
    }

    fn public_units(&mut self, label: Label, size: usize) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(size),
        ));
    }

    fn message_unit(&mut self, label: Label) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Scalar,
        ));
    }

    fn message_units(&mut self, label: Label, size: usize) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(size),
        ));
    }

    fn challenge_unit(&mut self, label: Label) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Scalar,
        ));
    }

    fn challenge_units(&mut self, label: Label, size: usize) {
        self.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(size),
        ));
    }

    fn hint_bytes(&mut self, label: Label, size: usize) {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Fixed(size),
        ));
    }

    fn hint_bytes_dynamic(&mut self, label: Label) {
        self.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ));
    }
}
