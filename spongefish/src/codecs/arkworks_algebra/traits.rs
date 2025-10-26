/// Transcript operations for field elements.
///
/// Provides both low-level (`*_unchecked`) and high-level methods.
/// Most users should use the high-level methods.
use ark_ec::CurveGroup;
use ark_ff::Field;

use crate::{
    pattern::{Label, Length, Pattern, PatternError},
    ProofError,
};

/// Transcript operations for field elements.
pub trait FieldTranscript<F: Field>: Pattern {
    /// Add field elements to transcript without pattern management.
    fn message_scalars_unchecked(&mut self, input: &[F]) -> &mut Self;

    /// Add public field elements without pattern management (absorb only, no proof write).
    fn message_public_scalars_unchecked(&mut self, input: &[F]) -> &mut Self;

    /// Generate field challenges without pattern management.
    fn challenge_scalars_unchecked(&mut self, output: &mut [F]) -> &mut Self;

    /// Add field elements with automatic pattern management.
    fn message_scalars(&mut self, label: Label, input: &[F]) -> &mut Self {
        self.begin_message::<F>(label.clone(), Length::Fixed(input.len()));
        self.message_scalars_unchecked(input);
        self.end_message::<F>(label, Length::Fixed(input.len()));
        self
    }

    /// Generate field challenges with automatic pattern management.
    fn challenge_scalars(&mut self, label: Label, output: &mut [F]) -> &mut Self {
        self.begin_challenge::<F>(label.clone(), Length::Fixed(output.len()));
        self.challenge_scalars_unchecked(output);
        self.end_challenge::<F>(label, Length::Fixed(output.len()));
        self
    }

    /// Absorb public field elements with automatic pattern management.
    fn message_public_scalars(&mut self, label: Label, input: &[F]) -> &mut Self {
        self.begin_public::<F>(label.clone(), Length::Fixed(input.len()));
        self.message_public_scalars_unchecked(input);
        self.end_public::<F>(label, Length::Fixed(input.len()));
        self
    }
}

/// Verifier-specific field operations.
pub trait VerifierFieldTranscript<F: Field>: FieldTranscript<F> {
    /// Read field elements from proof without pattern management.
    fn read_message_scalars_unchecked(&mut self, output: &mut [F])
        -> Result<&mut Self, ProofError>;

    /// Read field elements from proof with automatic pattern management.
    fn read_message_scalars(
        &mut self,
        label: Label,
        output: &mut [F],
    ) -> Result<&mut Self, ProofError> {
        self.begin_message::<F>(label.clone(), Length::Fixed(output.len()));
        self.read_message_scalars_unchecked(output)?;
        self.end_message::<F>(label, Length::Fixed(output.len()));
        Ok(self)
    }
}

/// Transcript operations for group elements.
pub trait GroupTranscript<G: CurveGroup>: Pattern {
    /// Add group elements to transcript without pattern management.
    fn message_points_unchecked(&mut self, input: &[G]) -> &mut Self;

    /// Add public group elements without pattern management (absorb only, no proof write).
    fn message_public_points_unchecked(&mut self, input: &[G]) -> &mut Self;

    /// Add group elements with automatic pattern management.
    fn message_points(&mut self, label: Label, input: &[G]) -> &mut Self {
        self.begin_message::<G>(label.clone(), Length::Fixed(input.len()));
        self.message_points_unchecked(input);
        self.end_message::<G>(label, Length::Fixed(input.len()));
        self
    }

    /// Absorb public group elements with automatic pattern management.
    fn message_public_points(&mut self, label: Label, input: &[G]) -> &mut Self {
        self.begin_public::<G>(label.clone(), Length::Fixed(input.len()));
        self.message_public_points_unchecked(input);
        self.end_public::<G>(label, Length::Fixed(input.len()));
        self
    }
}

/// Verifier-specific group operations.
pub trait VerifierGroupTranscript<G: CurveGroup>: GroupTranscript<G> {
    /// Read group elements from proof without pattern management.
    fn read_message_points_unchecked(&mut self, output: &mut [G]) -> Result<&mut Self, ProofError>;

    /// Read group elements from proof with automatic pattern management.
    fn read_message_points(
        &mut self,
        label: Label,
        output: &mut [G],
    ) -> Result<&mut Self, ProofError> {
        self.begin_message::<G>(label.clone(), Length::Fixed(output.len()));
        self.read_message_points_unchecked(output)?;
        self.end_message::<G>(label, Length::Fixed(output.len()));
        Ok(self)
    }
}
