use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::{CryptoRng, RngCore};

use crate::{
    pattern::{Label, PatternError, Pattern},
    duplex_sponge::{Unit, DuplexSpongeInterface},
    ProverState, VerifierState, ProofResult,
};

use super::{
    FieldToUnitSerialize, GroupToUnitSerialize, 
    FieldToUnitDeserialize, GroupToUnitDeserialize,
};

// ============================================================================
// PROVER EXTENSION TRAITS
// ============================================================================

/// Extension trait for adding field messages with automatic pattern handling
pub trait ProverFieldMessageExt<F: Field> {
    /// Add field scalars as a message (handles begin/add/end automatically)
    fn add_message_scalars(&mut self, label: Label, input: &[F]) -> Result<&mut Self, PatternError>;
}

/// Extension trait for adding group messages with automatic pattern handling
pub trait ProverGroupMessageExt<G: CurveGroup> {
    /// Add group points as a message (handles begin/add/end automatically)
    fn add_message_points(&mut self, label: Label, input: &[G]) -> Result<&mut Self, PatternError>;
}

// ============================================================================
// PROVER IMPLEMENTATIONS
// ============================================================================

impl<F, H, U, R> ProverFieldMessageExt<F> for ProverState<H, U, R>
where
    F: Field,
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
    Self: FieldToUnitSerialize<F> + Pattern,
{
    fn add_message_scalars(&mut self, label: Label, input: &[F]) -> Result<&mut Self, PatternError> {
        // Call Pattern trait methods with correct type parameters
        use crate::pattern::{Pattern, Length};
        Pattern::begin_message::<F>(self, label, Length::Fixed(input.len()))?;
        self.add_scalars(label, crate::pattern::Kind::Message, input)?;
        Pattern::end_message::<F>(self, label, Length::Fixed(input.len()))?;
        Ok(self)
    }
}

impl<G, H, U, R> ProverGroupMessageExt<G> for ProverState<H, U, R>
where
    G: CurveGroup,
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
    Self: GroupToUnitSerialize<G> + Pattern,
{
    fn add_message_points(&mut self, label: Label, input: &[G]) -> Result<&mut Self, PatternError> {
        // Call Pattern trait methods with correct type parameters
        use crate::pattern::{Pattern, Length};
        Pattern::begin_message::<G>(self, label, Length::Fixed(input.len()))?;
        self.add_points(label, crate::pattern::Kind::Message, input)?;
        Pattern::end_message::<G>(self, label, Length::Fixed(input.len()))?;
        Ok(self)
    }
}

// ============================================================================
// VERIFIER EXTENSION TRAITS
// ============================================================================

/// Extension trait for reading field messages with automatic pattern handling
pub trait VerifierFieldMessageExt<F: Field> {
    /// Read field scalars from a message (handles begin/fill/end automatically)
    fn read_message_scalars(&mut self, label: Label, output: &mut [F]) -> ProofResult<&mut Self>;
}

/// Extension trait for reading group messages with automatic pattern handling
pub trait VerifierGroupMessageExt<G: CurveGroup> {
    /// Read group points from a message (handles begin/fill/end automatically)
    fn read_message_points(&mut self, label: Label, output: &mut [G]) -> ProofResult<&mut Self>;
}

// ============================================================================
// VERIFIER IMPLEMENTATIONS
// ============================================================================

impl<'a, F, H, U> VerifierFieldMessageExt<F> for VerifierState<'a, H, U>
where
    F: Field,
    U: Unit,
    H: DuplexSpongeInterface<U>,
    Self: FieldToUnitDeserialize<F>,
{
    fn read_message_scalars(&mut self, label: Label, output: &mut [F]) -> ProofResult<&mut Self> {
        // Use Pattern trait methods with correct type parameters
        use crate::pattern::{Pattern, Length};
        Pattern::begin_message::<F>(self, label, Length::Fixed(output.len()))?;
        self.fill_next_scalars(label, output)?;
        Pattern::end_message::<F>(self, label, Length::Fixed(output.len()))?;
        Ok(self)
    }
}

impl<'a, G, H, U> VerifierGroupMessageExt<G> for VerifierState<'a, H, U>
where
    G: CurveGroup,
    U: Unit,
    H: DuplexSpongeInterface<U>,
    Self: GroupToUnitDeserialize<G>,
{
    fn read_message_points(&mut self, label: Label, output: &mut [G]) -> ProofResult<&mut Self> {
        // Use Pattern trait methods with correct type parameters
        use crate::pattern::{Pattern, Length};
        Pattern::begin_message::<G>(self, label, Length::Fixed(output.len()))?;
        self.fill_next_points(label, output)?;
        Pattern::end_message::<G>(self, label, Length::Fixed(output.len()))?;
        Ok(self)
    }
}