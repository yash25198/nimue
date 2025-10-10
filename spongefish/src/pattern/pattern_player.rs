use std::sync::Arc;

use super::{Interaction, InteractionPattern, Kind, Label, Length};
use crate::pattern::{Hierarchy, PatternError};

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
    /// Maximum nesting depth for hierarchical interactions.
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

    /// Get a reference to the underlying pattern
    #[must_use]
    pub fn pattern(&self) -> &Arc<InteractionPattern> {
        &self.pattern
    }

    /// Finalize the sequence of interactions. Returns an error if there
    /// are unfinished interactions.
    pub fn finalize(mut self) -> Result<(), PatternError> {
        if self.position > self.pattern.interactions().len() {
            return Err(PatternError::DepthExceeded { limit: self.position });
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

    /// Play the next interaction in the pattern.
    pub fn interact(&mut self, interaction: Interaction) -> Result<(), PatternError> {
        if self.finalized {
            return Err(PatternError::AlreadyFinalized);
        }
        
        let expected = self.pattern.interactions().get(self.position)
            .ok_or_else(|| PatternError::NoMoreExpected { got: interaction.clone() })?;
        
        // Validate the interaction matches the expected one first
        if expected != &interaction {
            self.finalized = true;
            return Err(PatternError::UnexpectedInteraction { 
                expected: expected.clone(), 
                got: interaction.clone() 
            });
        }
        
        // Validate hierarchy tracking
        match interaction.hierarchy() {
            Hierarchy::Begin => {
                if self.hierarchy_stack.len() >= Self::MAX_NESTING_DEPTH {
                    self.finalized = true;
                    return Err(PatternError::DepthExceeded { limit: Self::MAX_NESTING_DEPTH });
                }
                self.hierarchy_stack.push(self.position);

            }
            Hierarchy::End => {
                let begin_pos = self.hierarchy_stack.pop()
                    .ok_or_else(|| PatternError::MissingBegin { end: interaction.clone() })?;
                
                if let Some(begin) = self.pattern.interactions().get(begin_pos) {
                    if !interaction.closes(begin) {
                        self.finalized = true;
                        return Err(PatternError::MismatchedBeginEnd { 
                            begin: begin.clone(), 
                            end: interaction.clone() 
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
}

impl Drop for PatternPlayer {
    fn drop(&mut self) {
        assert!(self.finalized, "Dropped unfinalized transcript.");
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

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut PatternPlayer, PatternError> {
        self.interact(Interaction::new::<T>(Hierarchy::Begin, kind, label, length))?;
        Ok(self)
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut PatternPlayer, PatternError> {
        self.interact(Interaction::new::<T>(Hierarchy::End, kind, label, length))?;
        Ok(self)
    }
}