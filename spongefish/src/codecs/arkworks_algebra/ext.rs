use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::{CryptoRng, RngCore};

use super::{
    FieldToUnitDeserialize, FieldToUnitSerialize, GroupToUnitDeserialize, GroupToUnitSerialize,
};
use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    pattern::{Label, Pattern, PatternError},
    ProofResult, ProverState, VerifierState,
};

// ============================================================================
// PROVER EXTENSION TRAITS
// ============================================================================

/// Extension trait for adding field messages with automatic pattern handling.
///
/// This trait provides a convenience layer over the low-level [`FieldToUnitSerialize`] trait
/// by automatically handling the pattern hierarchy (`begin_message`/`end_message`). Use this
/// trait when you want a simple API that manages protocol structure automatically.
///
/// ## Core vs Extension Traits
///
/// - **Core traits** ([`FieldToUnitSerialize`]): Low-level serialization without pattern management.
///   Use these when you need fine-grained control over the protocol structure.
///
/// - **Extension traits** (this trait): High-level API with automatic pattern management.
///   Use these for typical use cases where you want clean, simple code.
///
/// ## Example
///
/// ```ignore
/// use spongefish::codecs::arkworks_algebra::ProverFieldMessageExt;
///
/// // Extension trait handles begin/end automatically
/// prover.message_scalars(Label::custom("my_scalars"), &scalars)?;
/// ```
pub trait ProverFieldMessageExt<F: Field> {
    /// Add field scalars as a message (handles begin/add/end automatically).
    ///
    /// This is equivalent to:
    /// ```ignore
    /// prover.begin_message::<F>(label, Length::Fixed(input.len()))?;
    /// prover.add_scalars(label, Kind::Message, input)?;
    /// prover.end_message::<F>(label, Length::Fixed(input.len()))?;
    /// ```
    fn message_scalars(&mut self, label: Label, input: &[F]) -> Result<&mut Self, PatternError>;
}

/// Extension trait for adding group messages with automatic pattern handling.
///
/// This trait provides a convenience layer over the low-level [`GroupToUnitSerialize`] trait
/// by automatically handling the pattern hierarchy (`begin_message`/`end_message`). Use this
/// trait when you want a simple API that manages protocol structure automatically.
///
/// See [`ProverFieldMessageExt`] for more details on the relationship between core and extension traits.
pub trait ProverGroupMessageExt<G: CurveGroup> {
    /// Add group points as a message (handles begin/add/end automatically).
    ///
    /// This is equivalent to:
    /// ```ignore
    /// prover.begin_message::<G>(label, Length::Fixed(input.len()))?;
    /// prover.add_points(label, Kind::Message, input)?;
    /// prover.end_message::<G>(label, Length::Fixed(input.len()))?;
    /// ```
    fn message_points(&mut self, label: Label, input: &[G]) -> Result<&mut Self, PatternError>;
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
    fn message_scalars(&mut self, label: Label, input: &[F]) -> Result<&mut Self, PatternError> {
        // Call Pattern trait methods with correct type parameters
        use crate::pattern::{Length, Pattern};
        Pattern::begin_message::<F>(self, label.clone(), Length::Fixed(input.len()))?;
        self.add_scalars(input)?;
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
    fn message_points(&mut self, label: Label, input: &[G]) -> Result<&mut Self, PatternError> {
        // Call Pattern trait methods with correct type parameters
        use crate::pattern::{Length, Pattern};
        Pattern::begin_message::<G>(self, label.clone(), Length::Fixed(input.len()))?;
        self.add_points(input)?;
        Pattern::end_message::<G>(self, label, Length::Fixed(input.len()))?;
        Ok(self)
    }
}

// ============================================================================
// VERIFIER EXTENSION TRAITS
// ============================================================================

/// Extension trait for reading field messages with automatic pattern handling.
///
/// This trait provides a convenience layer over the low-level [`FieldToUnitDeserialize`] trait
/// by automatically handling the pattern hierarchy (`begin_message`/`end_message`). Use this
/// trait when you want a simple API that manages protocol structure automatically.
///
/// See [`ProverFieldMessageExt`] for more details on the relationship between core and extension traits.
pub trait VerifierFieldMessageExt<F: Field> {
    /// Read field scalars from a message (handles begin/fill/end automatically).
    ///
    /// This is equivalent to:
    /// ```ignore
    /// verifier.begin_message::<F>(label, Length::Fixed(output.len()))?;
    /// verifier.fill_next_scalars(label, output)?;
    /// verifier.end_message::<F>(label, Length::Fixed(output.len()))?;
    /// ```
    fn fill_message_scalars(&mut self, label: Label, output: &mut [F]) -> ProofResult<&mut Self>;
}

/// Extension trait for reading group messages with automatic pattern handling.
///
/// This trait provides a convenience layer over the low-level [`GroupToUnitDeserialize`] trait
/// by automatically handling the pattern hierarchy (`begin_message`/`end_message`). Use this
/// trait when you want a simple API that manages protocol structure automatically.
///
/// See [`ProverFieldMessageExt`] for more details on the relationship between core and extension traits.
pub trait VerifierGroupMessageExt<G: CurveGroup> {
    /// Read group points from a message (handles begin/fill/end automatically).
    ///
    /// This is equivalent to:
    /// ```ignore
    /// verifier.begin_message::<G>(label, Length::Fixed(output.len()))?;
    /// verifier.fill_next_points(label, output)?;
    /// verifier.end_message::<G>(label, Length::Fixed(output.len()))?;
    /// ```
    fn fill_message_points(&mut self, label: Label, output: &mut [G]) -> ProofResult<&mut Self>;
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
    fn fill_message_scalars(&mut self, label: Label, output: &mut [F]) -> ProofResult<&mut Self> {
        // Use Pattern trait methods with correct type parameters
        use crate::pattern::{Length, Pattern};
        Pattern::begin_message::<F>(self, label.clone(), Length::Fixed(output.len()))?;
        self.fill_next_scalars(output)?;
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
    fn fill_message_points(&mut self, label: Label, output: &mut [G]) -> ProofResult<&mut Self> {
        // Use Pattern trait methods with correct type parameters
        use crate::pattern::{Length, Pattern};
        Pattern::begin_message::<G>(self, label.clone(), Length::Fixed(output.len()))?;
        self.fill_next_points(output)?;
        Pattern::end_message::<G>(self, label, Length::Fixed(output.len()))?;
        Ok(self)
    }
}
