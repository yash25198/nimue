use std::sync::Arc;

use super::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length};

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

    /// Consume all interactions of a specific hierarchy and kind
    pub fn consume_hierarchy(&mut self, hierarchy: Hierarchy, kind: Kind) -> usize {
        let mut consumed = 0;
        while let Some(next) = self.peek_next() {
            if next.hierarchy() == hierarchy && next.kind() == kind {
                self.interact(next.clone());
                consumed += 1;
            } else {
                break;
            }
        }
        consumed
    }

    /// Consume Begin interactions of a specific kind
    pub fn consume_begin(&mut self, kind: Kind) {
        self.consume_hierarchy(Hierarchy::Begin, kind);
    }

    /// Consume End interactions of a specific kind
    pub fn consume_end(&mut self, kind: Kind) {
        self.consume_hierarchy(Hierarchy::End, kind);
    }

    pub fn finalize(mut self) {
        assert!(!self.finalized, "Transcript is already finalized.");

        while !self.hierarchy_stack.is_empty() {
            // Skip to the matching End
            self.skip_to_matching_end();
        }

        assert!(
            self.position >= self.pattern.interactions().len(),
            "Transcript not finished, expecting {}",
            self.pattern.interactions()[self.position]
        );
        self.finalized = true;
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

    /// Find the deepest atomic interaction within the current hierarchy
    fn find_nested_atomic(&self, start: usize) -> Option<usize> {
        let mut pos = start;
        let mut depth = 0;

        while pos < self.pattern.interactions().len() {
            let interaction = &self.pattern.interactions()[pos];
            match interaction.hierarchy() {
                Hierarchy::Begin => depth += 1,
                Hierarchy::End => {
                    depth -= 1;
                    if depth < 0 {
                        return None; // We've gone past the hierarchy
                    }
                }
                Hierarchy::Atomic => return Some(pos),
            }
            pos += 1;
        }
        None
    }

    pub fn interact(&mut self, interaction: Interaction) {
        assert!(!self.finalized, "Transcript is already finalized.");

        let Some(expected) = self.pattern.interactions().get(self.position) else {
            self.finalized = true;
            panic!("Received interaction, but no more expected interactions: {interaction}");
        };

        // Smart matching when auto_traverse is enabled
        // Case 1: We expect a Begin but receive an Atomic
        if expected.hierarchy() == Hierarchy::Begin && interaction.hierarchy() == Hierarchy::Atomic
        {
            // Find the atomic interaction nested within this hierarchy
            if let Some(atomic_pos) = self.find_nested_atomic(self.position + 1) {
                let nested_atomic = &self.pattern.interactions()[atomic_pos];

                // Check if it matches (relaxed matching - just kind and hierarchy)
                if nested_atomic.kind() == interaction.kind()
                    && nested_atomic.hierarchy() == interaction.hierarchy()
                {
                    // Record that we entered this hierarchy
                    self.hierarchy_stack.push(self.position);

                    // Jump to after the atomic interaction
                    self.position = atomic_pos + 1;

                    // Now skip to the end of all open hierarchies
                    while !self.hierarchy_stack.is_empty() {
                        self.skip_to_matching_end();
                    }

                    return;
                }
            }
        }

        // Case 2: We expect an End but receive something else (auto-skip)
        if expected.hierarchy() == Hierarchy::End && interaction.hierarchy() != Hierarchy::End {
            // Skip this End and try matching again
            self.position += 1;
            self.interact(interaction);
            return;
        }

        // Normal exact matching
        if expected != &interaction {
            self.finalized = true;
            panic!("Received interaction {interaction}, but expected {expected}");
        }

        // Update hierarchy tracking
        match interaction.hierarchy() {
            Hierarchy::Begin => {
                self.hierarchy_stack.push(self.position);
            }
            Hierarchy::End => {
                self.hierarchy_stack
                    .pop()
                    .expect("Pattern validation should ensure matching Begin/End");
            }
            Hierarchy::Atomic => {}
        }

        self.position += 1;
    }
}

impl Drop for PatternPlayer {
    fn drop(&mut self) {
        assert!(self.finalized, "Dropped unfinalized transcript.");
    }
}

impl super::Pattern for PatternPlayer {
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
