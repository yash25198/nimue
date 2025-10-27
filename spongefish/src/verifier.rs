use std::{marker::PhantomData, sync::Arc};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    errors::ProofError,
    pattern::{
        Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, Pattern, PatternPlayer,
    },
    ByteTranscript, DefaultHash, MessageReader, UnitTranscript, VerifierByteTranscript,
};

/// Error type for verifier operations.
///
/// These errors indicate issues with proof data (I/O failures), not pattern mismatches.
/// Pattern mismatches panic since they indicate programming errors.
#[derive(Debug, Clone)]
pub enum VerifierError {
    /// Insufficient data in proof.
    InsufficientData,
    /// Failed to deserialize proof data.
    DeserializationError(String),
    /// Proof contains unconsumed data after verification.
    UnconsumedData,
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientData => write!(f, "Insufficient data in proof"),
            Self::DeserializationError(s) => write!(f, "Deserialization error: {}", s),
            Self::UnconsumedData => write!(f, "Proof contains unconsumed data"),
        }
    }
}

impl std::error::Error for VerifierError {}

impl From<VerifierError> for ProofError {
    fn from(e: VerifierError) -> Self {
        match e {
            VerifierError::InsufficientData => ProofError::InvalidProof,
            VerifierError::DeserializationError(_) => ProofError::SerializationError,
            VerifierError::UnconsumedData => ProofError::InvalidProof,
        }
    }
}

impl From<ProofError> for VerifierError {
    fn from(e: ProofError) -> Self {
        match e {
            ProofError::InvalidProof => VerifierError::InsufficientData,
            ProofError::SerializationError => {
                VerifierError::DeserializationError("Serialization error".to_string())
            }
            ProofError::PatternError(s) => VerifierError::DeserializationError(s),
        }
    }
}

/// [`VerifierState`] is the verifier state.
///
/// Internally, it simply contains a stateful hash.
/// Given as input an [`InteractionPattern`] and a NARG string, it allows to
/// de-serialize elements from the NARG string and make them available to the zero-knowledge verifier.
pub struct VerifierState<'a, H = DefaultHash, U = u8>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    pub(crate) pattern: PatternPlayer,
    pub(crate) duplex_sponge: H,
    pub(crate) narg_string: &'a [u8],
    pub(crate) cursor: usize,
    pub(crate) _unit_type: PhantomData<U>,
}

impl<'a, U: Unit, H: DuplexSpongeInterface<U>> VerifierState<'a, H, U> {
    /// Create a new verifier state.
    #[must_use]
    pub fn new(pattern: InteractionPattern, narg_string: &'a [u8]) -> Self {
        let pattern = Arc::new(pattern);
        let iv = pattern.domain_separator();
        let mut state = Self {
            pattern: PatternPlayer::new(pattern.clone()),
            duplex_sponge: H::new(iv),
            narg_string,
            cursor: 0,
            _unit_type: PhantomData,
        };

        // Handle the automatic protocol wrapping that PatternState::finalize() adds
        let interactions = pattern.interactions();
        let has_protocol_wrapper = interactions
            .first()
            .map(|i| {
                i.hierarchy() == Hierarchy::Begin
                    && i.kind() == Kind::Protocol
                    && *i.label() == Label::Protocol
            })
            .unwrap_or(false);

        if has_protocol_wrapper {
            state
                .pattern
                .begin::<()>(Label::Protocol, Kind::Protocol, Length::None);
        }
        state
    }

    /// Read units from the proof.
    ///
    /// # Errors
    ///
    /// Returns `VerifierError::InsufficientData` if not enough data in proof.
    /// Returns `VerifierError::DeserializationError` if deserialization fails.
    ///
    /// # Panics
    ///
    /// Panics if the interaction doesn't match the expected pattern.
    pub fn fill_next_units(&mut self, label: Label, output: &mut [U]) -> Result<(), VerifierError> {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(output.len()),
        ));

        // Read from narg_string and update cursor
        let bytes_needed = output.len() * std::mem::size_of::<U>();
        if self.cursor + bytes_needed > self.narg_string.len() {
            return Err(VerifierError::InsufficientData);
        }

        U::read(
            &mut &self.narg_string[self.cursor..self.cursor + bytes_needed],
            output,
        )
        .map_err(|e| {
            VerifierError::DeserializationError(format!("Deserialization error: {}", e))
        })?;

        self.cursor += bytes_needed;

        // Also absorb into the duplex sponge for challenge generation
        self.duplex_sponge.absorb_unchecked(output);

        Ok(())
    }

    /// Ratchet the sponge state.
    ///
    /// # Panics
    ///
    /// Panics if the interaction doesn't match the expected pattern.
    pub fn ratchet(&mut self) {
        self.pattern.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            Label::Ratchet,
            Length::None,
        ));
        self.duplex_sponge.ratchet_unchecked();
    }

    /// Read a hint from the proof.
    ///
    /// # Errors
    ///
    /// Returns `VerifierError::InsufficientData` if not enough data in proof.
    ///
    /// # Panics
    ///
    /// Panics if the interaction doesn't match the expected pattern.
    pub fn hint_bytes(&mut self, label: Label, output: &mut Vec<u8>) -> Result<(), VerifierError> {
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ));

        if self.narg_string[self.cursor..].len() < 4 {
            return Err(VerifierError::InsufficientData);
        }

        let len = u32::from_le_bytes(
            self.narg_string[self.cursor..self.cursor + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        self.cursor += 4;

        let rest = &self.narg_string[self.cursor..];

        if rest.len() < len {
            return Err(VerifierError::InsufficientData);
        }

        output.clear();
        output.extend_from_slice(&rest[..len]);
        self.cursor += len;
        Ok(())
    }

    /// Add public units to the transcript.
    ///
    /// # Panics
    ///
    /// Panics if the interaction doesn't match the expected pattern.
    pub fn public_units(&mut self, label: Label, input: &[U]) {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(input.len()),
        ));

        self.duplex_sponge.absorb_unchecked(input);
    }

    /// Fill output buffer with challenge units.
    ///
    /// # Panics
    ///
    /// Panics if the interaction doesn't match the expected pattern.
    pub fn fill_challenge_units(&mut self, label: Label, output: &mut [U]) {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(output.len()),
        ));

        self.duplex_sponge.squeeze_unchecked(output);
    }

    pub fn read_message_units(
        &mut self,
        label: Label,
        output: &mut [U],
    ) -> Result<&mut Self, VerifierError> {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(output.len()),
        ));

        let bytes_needed = output.len() * std::mem::size_of::<U>();
        if self.cursor + bytes_needed > self.narg_string.len() {
            return Err(VerifierError::InsufficientData);
        }

        let slice = &self.narg_string[self.cursor..self.cursor + bytes_needed];
        U::read(&mut &*slice, output)
            .map_err(|e| VerifierError::DeserializationError(e.to_string()))?;

        self.cursor += bytes_needed;
        self.duplex_sponge.absorb_unchecked(output);
        Ok(self)
    }

    pub fn message_public_units(&mut self, label: Label, input: &[U]) -> &mut Self {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(input.len()),
        ));

        self.duplex_sponge.absorb_unchecked(input);
        self
    }

    pub fn challenge_units(&mut self, label: Label, output: &mut [U]) -> &mut Self {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(output.len()),
        ));

        self.duplex_sponge.squeeze_unchecked(output);
        self
    }

    /// Finalize the verifier and check that the proof is fully consumed.
    ///
    /// # Errors
    ///
    /// Returns `VerifierError::UnconsumedData` if proof has remaining data.
    pub fn finalize(mut self) -> Result<(), VerifierError> {
        let pattern = self.pattern.pattern().clone();
        
        // Handle the automatic protocol wrapping that PatternState::finalize() adds
        let interactions = pattern.interactions();
        let has_protocol_end = interactions
            .last()
            .map(|i| {
                i.hierarchy() == Hierarchy::End
                    && i.kind() == Kind::Protocol
                    && *i.label() == Label::Protocol
            })
            .unwrap_or(false);

        if has_protocol_end {
            self.pattern
                .end::<()>(Label::Protocol, Kind::Protocol, Length::None);
        }

        self.pattern.finalize();

        // Check if proof is fully consumed
        if self.cursor != self.narg_string.len() {
            return Err(VerifierError::UnconsumedData);
        }

        Ok(())
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> core::fmt::Debug for VerifierState<'_, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifierState")
            .field("pattern", &self.pattern)
            .finish()
    }
}

// Implements Pattern trait for VerifierState by delegating to the internal PatternPlayer
impl<'a, H, U> Pattern for VerifierState<'a, H, U>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn abort(&mut self) -> &mut Self {
        self.pattern.abort();
        self
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        self.pattern.begin::<T>(label, kind, length);
        self
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        self.pattern.end::<T>(label, kind, length);
        self
    }
}

// Trait implementations
impl<H: DuplexSpongeInterface<U>, U: Unit> UnitTranscript<U> for VerifierState<'_, H, U> {
    fn message_public_units(&mut self, label: Label, input: &[U]) -> &mut Self {
        VerifierState::message_public_units(self, label, input);
        self
    }

    fn challenge_units(&mut self, label: Label, output: &mut [U]) -> &mut Self {
        VerifierState::challenge_units(self, label, output);
        self
    }
}
impl<H: DuplexSpongeInterface<u8>> ByteTranscript for VerifierState<'_, H, u8> {
    fn message_bytes_unchecked(&mut self, _input: &[u8]) -> &mut Self {
        panic!("Verifier cannot send messages");
    }

    fn message_public_bytes_unchecked(&mut self, input: &[u8]) -> &mut Self {
        // Only absorb into sponge, don't read from proof
        VerifierState::message_public_units(self, Label::Units, input);
        self
    }

    fn challenge_bytes_unchecked(&mut self, output: &mut [u8]) -> &mut Self {
        self.challenge_units(Label::Units, output)
    }

    fn message_bytes(&mut self, label: Label, input: &[u8]) -> &mut Self {
        self.begin_message::<u8>(label.clone(), Length::Fixed(input.len()));
        self.message_bytes_unchecked(input);
        self.end_message::<u8>(label, Length::Fixed(input.len()));
        self
    }

    fn challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> &mut Self {
        self.begin_challenge::<u8>(label.clone(), Length::Fixed(output.len()));
        self.challenge_bytes_unchecked(output);
        self.end_challenge::<u8>(label, Length::Fixed(output.len()));
        self
    }

    fn message_public_bytes(&mut self, label: Label, input: &[u8]) -> &mut Self {
        self.begin_public::<u8>(label.clone(), Length::Fixed(input.len()));
        self.message_public_bytes_unchecked(input);
        self.end_public::<u8>(label, Length::Fixed(input.len()));
        self
    }
}

impl<H: DuplexSpongeInterface<u8>> VerifierByteTranscript for VerifierState<'_, H, u8> {
    fn read_message_bytes_unchecked(&mut self, output: &mut [u8]) -> &mut Self {
        self.read_message_units(Label::Units, output)
            .unwrap_or_else(|e| panic!("Failed to read message bytes: {}", e))
    }

    fn read_message_bytes(&mut self, label: Label, output: &mut [u8]) -> &mut Self {
        self.begin_message::<u8>(label.clone(), Length::Fixed(output.len()));
        self.read_message_bytes_unchecked(output);
        self.end_message::<u8>(label, Length::Fixed(output.len()));
        self
    }
}

impl<H: DuplexSpongeInterface<u8>> MessageReader<u8> for VerifierState<'_, H, u8> {
    fn read_message_units(&mut self, label: Label, output: &mut [u8]) -> &mut Self {
        // Note: This method can't return Result, so we need to panic on error
        // This is acceptable since the trait doesn't support Result
        VerifierState::read_message_units(self, label, output)
            .unwrap_or_else(|e| panic!("Failed to read message units: {}", e))
    }
}
#[cfg(test)]
mod test_utils {
    use std::{cell::RefCell, rc::Rc};

    use crate::duplex_sponge::DuplexSpongeInterface;

    #[derive(Default, Clone)]
    pub struct DummySponge {
        pub absorbed: Rc<RefCell<Vec<u8>>>,
        pub squeezed: Rc<RefCell<Vec<u8>>>,
        pub ratcheted: Rc<RefCell<bool>>,
    }

    impl zeroize::Zeroize for DummySponge {
        fn zeroize(&mut self) {
            self.absorbed.borrow_mut().clear();
            self.squeezed.borrow_mut().clear();
            *self.ratcheted.borrow_mut() = false;
        }
    }

    impl DummySponge {
        fn new_inner() -> Self {
            Self {
                absorbed: Rc::new(RefCell::new(Vec::new())),
                squeezed: Rc::new(RefCell::new(Vec::new())),
                ratcheted: Rc::new(RefCell::new(false)),
            }
        }
    }

    impl DuplexSpongeInterface<u8> for DummySponge {
        fn new(_iv: [u8; 32]) -> Self {
            Self::new_inner()
        }

        fn absorb_unchecked(&mut self, input: &[u8]) -> &mut Self {
            self.absorbed.borrow_mut().extend_from_slice(input);
            self
        }

        fn squeeze_unchecked(&mut self, output: &mut [u8]) -> &mut Self {
            for (i, byte) in output.iter_mut().enumerate() {
                *byte = i as u8;
            }
            self.squeezed.borrow_mut().extend_from_slice(output);
            self
        }

        fn ratchet_unchecked(&mut self) -> &mut Self {
            *self.ratcheted.borrow_mut() = true;
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use test_utils::DummySponge;

    use super::*;
    use crate::{
        codecs::{bytes::Pattern as BytesPattern, unit::Pattern as UnitPattern},
        pattern::{Pattern, PatternState},
        prover::ProverState,
    };

    #[test]
    fn test_fill_next_units_with_message() {
        let mut pattern = PatternState::new();
        let _ = pattern.message_units(Label::Units, 3);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"abc");
        let mut buf = [0u8; 3];

        vs.fill_next_units(Label::Units, &mut buf).unwrap();
        assert_eq!(buf, *b"abc");
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), b"abc");
        vs.finalize().unwrap();
    }

    #[test]
    fn test_new_verifier_state_constructs_correctly() {
        let pattern = PatternState::new().finalize();
        let transcript = b"abc";
        let vs = VerifierState::<DummySponge>::new(pattern, transcript);
        assert_eq!(vs.narg_string, b"abc");
        assert_eq!(vs.cursor, 0);
        let _ = vs.finalize();
    }

    #[test]
    fn test_fill_next_units_with_insufficient_data_errors() {
        let mut pattern = PatternState::new();
        let _ = pattern.message_units(Label::Units, 4);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"xy");
        // Pattern expects atomic interaction, so don't call begin_message
        let mut buf = [0u8; 4];

        let result = vs.fill_next_units(Label::Units, &mut buf);
        assert!(result.is_err());
        // Manually abort and forget to avoid panic on drop
        vs.abort();
        std::mem::forget(vs);
    }

    #[test]
    fn test_ratcheting_success() {
        let mut pattern = PatternState::new();
        let _ = pattern.ratchet();
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), &[]);
        vs.ratchet();
        assert!(*vs.duplex_sponge.ratcheted.borrow());
        vs.finalize().unwrap();
    }

    #[test]

    fn test_unit_transcript_public_units() {
        let mut pattern = PatternState::new();
        let _ = pattern.message_public_units(Label::from("public_units"), 2);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"");
        let _ = vs.message_public_units(Label::from("public_units"), &[1, 2]);
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), &[1, 2]);
        vs.finalize().unwrap();
    }

    #[test]
    fn test_unit_transcript_fill_challenge_units() {
        let mut pattern = PatternState::new();
        let _ = pattern.challenge_units(Label::from("challenge"), 4);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"");

        let mut out = [0u8; 4];
        vs.challenge_units(Label::from("challenge"), &mut out);

        assert_eq!(out, [0, 1, 2, 3]);
        vs.finalize().unwrap();
    }

    #[test]

    fn test_fill_next_bytes_impl() {
        let mut pattern = PatternState::new();
        pattern.message_bytes(Label::from("bytes"), 3);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"xyz");
        let mut out = [0u8; 3];

        // message_bytes creates a hierarchical pattern, so we need to navigate it
        vs.begin_message::<u8>(Label::from("bytes"), Length::Fixed(3));
        vs.fill_next_units(Label::Units, &mut out).unwrap();
        vs.end_message::<u8>(Label::from("bytes"), Length::Fixed(3));
        assert_eq!(out, *b"xyz");
        let _ = vs.finalize();
    }

    #[test]
    fn test_hint_bytes_verifier_valid_hint() {
        let mut pattern = PatternState::new();
        let _ = pattern.hint_bytes_dynamic(Label::from("hint_bytes"));
        let pattern = pattern.finalize();

        let hint = b"abc123";

        let mut prover: ProverState = ProverState::from(pattern.clone());
        prover.hint_bytes(Label::from("hint_bytes"), hint);

        let narg = prover.finalize();

        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        vs.hint_bytes(Label::from("hint_bytes"), &mut result)
            .unwrap();

        assert_eq!(result, hint);
        vs.finalize().unwrap();
    }

    #[test]
    fn test_hint_bytes_verifier_empty_hint() {
        let mut pattern = PatternState::new();
        let _ = pattern.hint_bytes_dynamic(Label::from("hint_bytes"));
        let pattern = pattern.finalize();

        let hint = b"";

        let mut prover: ProverState = ProverState::from(pattern.clone());
        prover.hint_bytes(Label::from("hint_bytes"), hint);
        let narg = prover.finalize();

        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        vs.hint_bytes(Label::from("hint_bytes"), &mut result)
            .unwrap();

        assert_eq!(result.as_slice(), b"");
        vs.finalize().unwrap();
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]

    fn test_hint_bytes_verifier_no_hint_op() {
        let mut pattern = PatternState::new();
        pattern.message_public_bytes(Label::custom("public_bytes"), 2);
        let pattern = pattern.finalize();
        let narg = hex::decode("06000000616263313233").unwrap();
        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        // Should panic because there's no hint operation in the pattern
        vs.hint_bytes(Label::custom("hint_bytes"), &mut result)
            .unwrap();
    }

    #[test]

    fn test_hint_bytes_verifier_length_prefix_too_short() {
        let mut pattern = PatternState::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let narg = &[1, 2, 3];
        let mut vs: VerifierState = VerifierState::new(pattern, narg);
        let mut result = Vec::new();
        let err = vs.hint_bytes(Label::custom("hint_bytes"), &mut result);

        assert!(err.is_err());
        assert!(format!("{:?}", err.unwrap_err()).contains("Insufficient"));
        // Abort and forget to avoid panic on drop
        vs.abort();
        std::mem::forget(vs);
    }

    #[test]

    fn test_hint_bytes_verifier_declared_hint_too_long() {
        let mut pattern = PatternState::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let narg = [5u8, 0, 0, 0, b'a', b'b'];
        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        let err = vs.hint_bytes(Label::custom("hint_bytes"), &mut result);

        assert!(err.is_err());
        assert!(format!("{:?}", err.unwrap_err()).contains("Insufficient"));
        // Abort and forget to avoid panic on drop
        vs.abort();
        std::mem::forget(vs);
    }
}
