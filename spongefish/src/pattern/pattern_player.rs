use std::sync::Arc;

use super::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, PatternError};

/// Play back an interaction pattern and make sure all interactions match up.
///
/// # Panics
///
/// Panics on [`Drop`] if there are unfinished interactions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PatternPlayer {
    /// Shared reference to the transcript.
    pattern: Arc<InteractionPattern>,
    /// Current position in the interaction pattern.
    position: usize,
    /// Stack to track the hierarchy of interactions.
    hierarchy_stack: Vec<usize>,
    finalized: bool,
}

impl PatternPlayer {
    const MAX_NESTING_DEPTH: usize = 64;
    #[must_use]
    pub const fn new(pattern: Arc<InteractionPattern>) -> Self {
        Self {
            pattern,
            position: 0,
            hierarchy_stack: Vec::new(),
            finalized: false,
        }
    }

    pub fn peek_next(&self) -> Option<&Interaction> {
        self.pattern.interactions().get(self.position)
    }

    pub fn position(&self) -> usize {
        self.position
    }

    /// Consume all interactions of a specific hierarchy and kind
    pub fn consume_hierarchy(&mut self, hierarchy: Hierarchy, kind: Kind) -> Result<usize, PatternError> {
        let mut consumed = 0;
        while let Some(next) = self.peek_next() {
            if next.hierarchy() == hierarchy && next.kind() == kind {
                self.interact(next.clone())?;
                consumed += 1;
            } else {
                break;
            }
        }
        Ok(consumed)
    }

    /// Consume Begin interactions of a specific kind
    pub fn consume_begin(&mut self, kind: Kind) -> Result<usize, PatternError> {
        self.consume_hierarchy(Hierarchy::Begin, kind)
    }

    /// Consume End interactions of a specific kind
    pub fn consume_end(&mut self, kind: Kind) -> Result<usize, PatternError> {
        self.consume_hierarchy(Hierarchy::End, kind)
    }

    pub fn finalize(mut self) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }

        while !self.hierarchy_stack.is_empty() {
            // Skip to the matching End
            self.skip_to_matching_end();
        }

        if self.position < self.pattern.interactions().len() {
            let expected = self.pattern.interactions()[self.position].clone();
            self.finalized = true;
            return Err(PatternError::TranscriptNotFinished { expected });
        }
        self.finalized = true;
        Ok(())
    }

    /// Skip forward to the matching End for the current Begin
    fn skip_to_matching_end(&mut self) {
        if let Some(begin_pos) = self.hierarchy_stack.pop() {
            let begin = &self.pattern.interactions()[begin_pos];

            // Find the matching End
            let mut depth = 1;
            self.position = begin_pos + 1;

            while self.position < self.pattern.interactions().len() && depth > 0 {
                let current = &self.pattern.interactions()[self.position];
                match current.hierarchy() {
                    Hierarchy::Begin if current.kind() == begin.kind() => depth += 1,
                    Hierarchy::End if current.kind() == begin.kind() => {
                        depth -= 1;
                        if depth == 0 {
                            // Found matching End
                            self.position += 1;
                            return;
                        }
                    }
                    _ => {}
                }
                self.position += 1;
            }
        }
    }


    pub fn interact(&mut self, interaction: Interaction) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }

        let Some(expected) = self.pattern.interactions().get(self.position) else {
            self.finalized = true;
            return Err(PatternError::NoMoreExpected { got: interaction });
        };


        if expected != &interaction {
            self.finalized = true;
            return Err(PatternError::UnexpectedInteraction { expected: expected.clone(), got: interaction });
        }

        // Update hierarchy tracking
        match interaction.hierarchy() {
            Hierarchy::Begin => {
                if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
                    return Err(PatternError::DepthExceeded { limit: Self::MAX_NESTING_DEPTH });
                }
                self.hierarchy_stack.push(self.position);
            }
            Hierarchy::End => {
                if let Some(&begin_pos) = self.hierarchy_stack.last() {
                    let begin = &self.pattern.interactions()[begin_pos];
                    assert!(
                        interaction.closes(begin),
                        "End does not close the top Begin: expected same kind and label",
                    );
                }
                self.hierarchy_stack
                    .pop()
                    .expect("Pattern validation should ensure matching Begin/End");
            }
            Hierarchy::Atomic => {}
        }

        self.position += 1;
        Ok(())
    }
}

impl Drop for PatternPlayer {
    fn drop(&mut self) {
        debug_assert!(self.finalized, "Dropped unfinalized transcript.");
    }
}

impl super::Pattern for PatternPlayer {
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
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))?;
        Ok(self)
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))?;
        Ok(self)
    }
}
