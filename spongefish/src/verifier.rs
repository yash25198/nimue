use std::{marker::PhantomData, sync::Arc};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    pattern::{
        Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, Pattern, PatternError,
        PatternPlayer, PatternResult,
    },
    traits::BytesToUnitDeserialize,
    CommonUnitToBytes, DefaultHash, UnitToBytes, UnitTranscript,
};

/// Inner state for the verifier.
///
/// This type contains the actual logic for verifier operations with explicit error returns.
///
/// Use [`VerifierState`] (the wrapper type) for ergonomic method chaining.
pub struct VerifierStateInner<'a, H = DefaultHash, U = u8>
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

impl<'a, U: Unit, H: DuplexSpongeInterface<U>> VerifierStateInner<'a, H, U> {
    /// Create a new verifier state.
    #[must_use]
    pub fn new(pattern: Arc<InteractionPattern>, narg_string: &'a [u8]) -> Self {
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
            // Check if error occurred
            if state.pattern.has_error() {
                panic!("Failed to begin protocol");
            }
        }
        state
    }

    /// Read units from the proof.
    pub fn fill_next_units(&mut self, label: Label, output: &mut [U]) -> Result<(), PatternError> {
        self.pattern
            .inner_mut()
            .ok_or(PatternError::AlreadyFinalized)?
            .interact(Interaction::new::<U>(
                Hierarchy::Atomic,
                Kind::Message,
                label,
                Length::Fixed(output.len()),
            ))?;

        // Read from narg_string and update cursor
        let bytes_needed = output.len() * std::mem::size_of::<U>();
        if self.cursor + bytes_needed > self.narg_string.len() {
            return Err(PatternError::SizeError(
                "Insufficient transcript remaining for deserialization".to_string(),
            ));
        }

        U::read(
            &mut &self.narg_string[self.cursor..self.cursor + bytes_needed],
            output,
        )
        .map_err(|e| PatternError::DeserializationError(format!("Deserialization error: {}", e)))?;

        self.cursor += bytes_needed;

        // Also absorb into the duplex sponge for challenge generation
        self.duplex_sponge.absorb_unchecked(output);

        Ok(())
    }

    /// Ratchet the sponge state.
    pub fn ratchet(&mut self) -> Result<(), PatternError> {
        self.pattern
            .inner_mut()
            .ok_or(PatternError::AlreadyFinalized)?
            .interact(Interaction::new::<()>(
                Hierarchy::Atomic,
                Kind::Protocol,
                Label::Ratchet,
                Length::None,
            ))?;
        self.duplex_sponge.ratchet_unchecked();
        Ok(())
    }

    /// Read a hint from the proof.
    pub fn hint_bytes(&mut self, label: Label, output: &mut Vec<u8>) -> Result<(), PatternError> {
        self.pattern
            .inner_mut()
            .ok_or(PatternError::AlreadyFinalized)?
            .interact(Interaction::new::<u8>(
                Hierarchy::Atomic,
                Kind::Hint,
                label,
                Length::Dynamic,
            ))?;

        if self.narg_string[self.cursor..].len() < 4 {
            return Err(PatternError::SizeError(
                "Insufficient transcript remaining for hint".to_string(),
            ));
        }

        let len = u32::from_le_bytes(
            self.narg_string[self.cursor..self.cursor + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        self.cursor += 4;

        let rest = &self.narg_string[self.cursor..];

        if rest.len() < len {
            return Err(PatternError::SizeError(format!(
                "Insufficient transcript remaining, got {}, need {len}",
                rest.len()
            )));
        }

        output.clear();
        output.extend_from_slice(&rest[..len]);
        self.cursor += len;
        Ok(())
    }

    /// Add public units to the transcript.
    pub fn public_units(&mut self, label: Label, input: &[U]) -> Result<(), PatternError> {
        self.pattern
            .inner_mut()
            .ok_or(PatternError::AlreadyFinalized)?
            .interact(Interaction::new::<U>(
                Hierarchy::Atomic,
                Kind::Public,
                label,
                Length::Fixed(input.len()),
            ))?;

        self.duplex_sponge.absorb_unchecked(input);

        Ok(())
    }

    /// Fill output buffer with challenge units.
    pub fn fill_challenge_units(
        &mut self,
        label: Label,
        output: &mut [U],
    ) -> Result<(), PatternError> {
        self.pattern
            .inner_mut()
            .ok_or(PatternError::AlreadyFinalized)?
            .interact(Interaction::new::<U>(
                Hierarchy::Atomic,
                Kind::Challenge,
                label,
                Length::Fixed(output.len()),
            ))?;

        self.duplex_sponge.squeeze_unchecked(output);

        Ok(())
    }

    /// Abort the verifier.
    pub fn abort_inner(&mut self) -> Result<(), PatternError> {
        self.pattern.abort();
        if self.pattern.has_error() {
            Err(PatternError::AlreadyFinalized)
        } else {
            Ok(())
        }
    }

    /// Finalize the verifier.
    pub fn finalize_inner(mut self, pattern: &Arc<InteractionPattern>) -> Result<(), PatternError> {
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

        if self.pattern.has_error() {
            return Err(PatternError::AlreadyFinalized);
        }

        self.pattern.finalize()
    }
}

/// [`VerifierState`] is the verifier state.
///
/// Internally, it simply contains a stateful hash.
/// Given as input an [`InteractionPattern`] and a NARG string, it allows to
/// de-serialize elements from the NARG string and make them available to the zero-knowledge verifier.
pub type VerifierState<'a, H = DefaultHash, U = u8> = PatternResult<VerifierStateInner<'a, H, U>>;

impl<'a, U: Unit, H: DuplexSpongeInterface<U>> VerifierState<'a, H, U> {
    /// Create a new [`VerifierState`] instance with the given pattern and NARG string.
    #[must_use]
    pub fn new(pattern: InteractionPattern, narg_string: &'a [u8]) -> Self {
        PatternResult::from_value(VerifierStateInner::new(Arc::new(pattern), narg_string))
    }

    /// Read units from the proof.
    pub fn fill_next_units(
        &mut self,
        label: Label,
        output: &mut [U],
    ) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.fill_next_units(label, output) {
                self.set_error(e.into());
            }
        }
        self
    }

    /// Begin a message interaction.
    pub fn begin_message<T: ?Sized>(&mut self, label: Label, count: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .begin_message::<T>(label, Length::Fixed(count));
        }
        self
    }

    /// End a message interaction.
    pub fn end_message<T: ?Sized>(&mut self, label: Label, count: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.end_message::<T>(label, Length::Fixed(count));
        }
        self
    }

    /// Begin a challenge interaction.
    pub fn begin_challenge<T>(&mut self, label: Label, count: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .begin_challenge::<T>(label, Length::Fixed(count));
        }
        self
    }

    /// End a challenge interaction.
    pub fn end_challenge<T>(&mut self, label: Label, count: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .end_challenge::<T>(label, Length::Fixed(count));
        }
        self
    }

    /// Begin a public interaction.
    pub fn begin_public<T: ?Sized>(&mut self, label: Label, count: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.begin_public::<T>(label, Length::Fixed(count));
        }
        self
    }

    /// End a public interaction.
    pub fn end_public<T: ?Sized>(&mut self, label: Label, count: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.end_public::<T>(label, Length::Fixed(count));
        }
        self
    }

    /// Begin a protocol.
    pub fn begin_protocol(&mut self, label: Label) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.begin_protocol(label);
        }
        self
    }

    /// End a protocol.
    pub fn end_protocol(&mut self, label: Label) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.end_protocol(label);
        }
        self
    }

    /// Ratchet the sponge state.
    #[inline]
    pub fn ratchet(&mut self) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.ratchet() {
                self.set_error(e.into());
            }
        }
        self
    }

    /// Read a hint from the proof.
    pub fn hint_bytes(&mut self, label: Label, output: &mut Vec<u8>) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.hint_bytes(label, output) {
                self.set_error(e.into());
            }
        }
        self
    }

    /// Abort the verifier.
    pub fn abort(mut self) -> Result<(), PatternError> {
        if self.has_error() {
            // Already has an error, just mark as finalized to prevent drop panic
            // Access inner directly since inner_mut() returns None when there's an error
            if let Some(inner) = self.inner.as_mut() {
                inner.pattern.abort();
            }
            return Ok(());
        }

        let inner = self.inner_mut_or_err()?;
        inner.abort_inner()
    }

    /// Finalize the verifier.
    pub fn finalize(self) -> Result<(), PatternError> {
        let inner = self.into_result()?;
        let pattern = inner
            .pattern
            .pattern()
            .ok_or(PatternError::AlreadyFinalized)?
            .clone();
        inner.finalize_inner(&pattern)
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> UnitTranscript<U> for VerifierState<'_, H, U> {
    fn public_units(&mut self, label: Label, input: &[U]) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.public_units(label, input) {
                self.set_error(e.into());
            }
        }
        self
    }

    #[inline]
    fn fill_challenge_units(&mut self, label: Label, output: &mut [U]) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            if let Err(e) = inner.fill_challenge_units(label, output) {
                self.set_error(e.into());
            }
        }
        self
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> core::fmt::Debug for VerifierState<'_, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(inner) = self.inner() {
            f.debug_tuple("VerifierState")
                .field(&inner.pattern)
                .finish()
        } else {
            write!(f, "VerifierState(finalized)")
        }
    }
}

// Implements Pattern trait for VerifierState by delegating to the internal PatternPlayer
impl<'a, H, U> Pattern for VerifierState<'a, H, U>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn abort(&mut self) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.abort();
        }
        self
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.begin::<T>(label, kind, length);
        }
        self
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner.pattern.end::<T>(label, kind, length);
        }
        self
    }
}

impl<H: DuplexSpongeInterface<u8>> BytesToUnitDeserialize for VerifierState<'_, H, u8> {
    #[inline]
    fn fill_next_bytes(
        &mut self,
        label: Label,
        output: &mut [u8],
    ) -> &mut Self {
        let error = if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .begin_message::<u8>(label.clone(), Length::Fixed(output.len()));
            let result = inner.fill_next_units(Label::Units, output);
            inner
                .pattern
                .end_message::<u8>(label, Length::Fixed(output.len()));
            result.err()
        } else {
            None
        };
        
        if let Some(e) = error {
            self.set_error(e.into());
        }
        self
    }
}

impl<H: DuplexSpongeInterface<u8>> CommonUnitToBytes for VerifierState<'_, H, u8> {
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> &mut Self {
        self.public_units(label, input)
    }
}

impl<H: DuplexSpongeInterface<u8>> UnitToBytes for VerifierState<'_, H, u8> {
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .begin_challenge::<u8>(label.clone(), Length::Fixed(output.len()));
            let result = inner.fill_challenge_units(Label::Units, output);
            inner
                .pattern
                .end_challenge::<u8>(label, Length::Fixed(output.len()));
            if let Err(e) = result {
                self.set_error(e.into());
            }
        }
        self
    }
}

// Implements Pattern trait for byte operations
impl<H> crate::codecs::bytes::Pattern for VerifierState<'_, H, u8>
where
    H: DuplexSpongeInterface<u8>,
{
    fn public_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .begin_public::<u8>(label.clone(), Length::Fixed(size));
            let result = inner
                .pattern
                .inner_mut()
                .ok_or(PatternError::AlreadyFinalized)
                .and_then(|i| {
                    i.interact(Interaction::new::<u8>(
                        Hierarchy::Atomic,
                        Kind::Public,
                        Label::Units,
                        Length::Fixed(size),
                    ))
                });
            inner.pattern.end_public::<u8>(label, Length::Fixed(size));
            if let Err(e) = result {
                self.set_error(e.into());
            }
        }
        self
    }

    fn message_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .begin_message::<u8>(label.clone(), Length::Fixed(size));
            let result = inner
                .pattern
                .inner_mut()
                .ok_or(PatternError::AlreadyFinalized)
                .and_then(|i| {
                    i.interact(Interaction::new::<u8>(
                        Hierarchy::Atomic,
                        Kind::Message,
                        Label::Units,
                        Length::Fixed(size),
                    ))
                });
            inner.pattern.end_message::<u8>(label, Length::Fixed(size));
            if let Err(e) = result {
                self.set_error(e.into());
            }
        }
        self
    }

    fn challenge_bytes(&mut self, label: Label, size: usize) -> &mut Self {
        if let Some(inner) = self.inner_mut() {
            inner
                .pattern
                .begin_challenge::<u8>(label.clone(), Length::Fixed(size));
            let result = inner
                .pattern
                .inner_mut()
                .ok_or(PatternError::AlreadyFinalized)
                .and_then(|i| {
                    i.interact(Interaction::new::<u8>(
                        Hierarchy::Atomic,
                        Kind::Challenge,
                        Label::Units,
                        Length::Fixed(size),
                    ))
                });
            inner
                .pattern
                .end_challenge::<u8>(label, Length::Fixed(size));
            if let Err(e) = result {
                self.set_error(e.into());
            }
        }
        self
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
        codecs::{bytes::Pattern as BytesPattern, unit::Pattern},
        pattern::PatternState,
        prover::ProverState,
    };

    #[test]
    fn test_fill_next_units_with_message() {
        let mut pattern = PatternState::new();
        let _ = pattern.message_units(Label::Units, 3);
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"abc");
        let mut buf = [0u8; 3];

        vs.fill_next_units(Label::Units, &mut buf);
        assert!(!vs.has_error());
        assert_eq!(buf, *b"abc");
        assert_eq!(*vs.inner().unwrap().duplex_sponge.absorbed.borrow(), b"abc");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_new_verifier_state_constructs_correctly() {
        let pattern = PatternState::new()
            .finalize()
            .expect("Failed to finalize pattern");
        let transcript = b"abc";
        let vs = VerifierState::<DummySponge>::new(pattern, transcript);
        assert_eq!(vs.inner().unwrap().narg_string, b"abc");
        assert_eq!(vs.inner().unwrap().cursor, 0);
        let _ = vs.finalize();
    }

    #[test]
    fn test_fill_next_units_with_insufficient_data_errors() {
        let mut pattern = PatternState::new();
        let _ = pattern.message_units(Label::Units, 4);
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"xy");
        let mut buf = [0u8; 4];

        vs.fill_next_units(Label::Units, &mut buf);
        assert!(vs.has_error());
        vs.abort().expect("Failed to abort");
    }

    #[test]
    fn test_ratcheting_success() {
        let mut pattern = PatternState::new();
        let _ = pattern.ratchet();
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), &[]);
        vs.ratchet();
        assert!(!vs.has_error());
        assert!(*vs.inner().unwrap().duplex_sponge.ratcheted.borrow());
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_unit_transcript_public_units() {
        let mut pattern = PatternState::new();
        let _ = pattern.public_units(Label::from("public_units"), 2);
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"..");
        let _ = vs.public_units(Label::from("public_units"), &[1, 2]);
        assert_eq!(
            *vs.inner().unwrap().duplex_sponge.absorbed.borrow(),
            &[1, 2]
        );
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_unit_transcript_fill_challenge_units() {
        let mut pattern = PatternState::new();
        let _ = pattern.challenge_units(Label::from("challenge"), 4);
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"");

        let mut out = [0u8; 4];
        vs.fill_challenge_units(Label::from("challenge"), &mut out);

        assert_eq!(out, [0, 1, 2, 3]);
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_fill_next_bytes_impl() {
        let mut pattern = PatternState::new();
        pattern.message_bytes(Label::from("bytes"), 3);
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let mut vs = VerifierState::<DummySponge>::new(pattern.clone(), b"xyz");
        let mut out = [0u8; 3];

        vs.fill_next_bytes(Label::from("bytes"), &mut out);
        assert!(!vs.has_error());
        assert_eq!(out, *b"xyz");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_hint_bytes_verifier_valid_hint() {
        let mut pattern = PatternState::new();
        let _ = pattern.hint_bytes_dynamic(Label::from("hint_bytes"));
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let hint = b"abc123";

        let mut prover: ProverState = ProverState::from(pattern.clone());
        prover.hint_bytes(Label::from("hint_bytes"), hint);

        let narg = prover.finalize().expect("Failed to finalize prover");

        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        vs.hint_bytes(Label::from("hint_bytes"), &mut result);

        assert_eq!(result, hint);
        vs.finalize().expect("Failed to finalize verifier");
    }

    #[test]
    fn test_hint_bytes_verifier_empty_hint() {
        let mut pattern = PatternState::new();
        let _ = pattern.hint_bytes_dynamic(Label::from("hint_bytes"));
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let hint = b"";

        let mut prover: ProverState = ProverState::from(pattern.clone());
        prover.hint_bytes(Label::from("hint_bytes"), hint);
        let narg = prover.finalize().expect("Failed to finalize");

        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        vs.hint_bytes(Label::from("hint_bytes"), &mut result);

        assert_eq!(result.as_slice(), b"");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_hint_bytes_verifier_no_hint_op() {
        let mut pattern = PatternState::new();
        pattern.public_bytes(Label::custom("public_bytes"), 2);
        let pattern = pattern.finalize().expect("Failed to finalize pattern");
        let narg = hex::decode("06000000616263313233").unwrap();
        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        vs.hint_bytes(Label::custom("hint_bytes"), &mut result);
        assert!(vs.has_error());
    }

    #[test]
    fn test_hint_bytes_verifier_length_prefix_too_short() {
        let mut pattern = PatternState::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let narg = &[1, 2, 3];
        let mut vs: VerifierState = VerifierState::new(pattern, narg);
        let mut result = Vec::new();
        vs.hint_bytes(Label::custom("hint_bytes"), &mut result);

        assert!(vs.has_error());
        let err = vs.get_error().unwrap();
        assert!(format!("{err}").contains("Insufficient transcript remaining for hint"));
        vs.abort().expect("Failed to abort");
    }

    #[test]
    fn test_hint_bytes_verifier_declared_hint_too_long() {
        let mut pattern = PatternState::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize().expect("Failed to finalize pattern");

        let narg = [5u8, 0, 0, 0, b'a', b'b'];
        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let mut result = Vec::new();
        vs.hint_bytes(Label::custom("hint_bytes"), &mut result);

        assert!(vs.has_error());
        let err = vs.get_error().unwrap();
        assert!(format!("{err}").contains("Insufficient transcript remaining"));
        vs.abort().expect("Failed to abort");
    }
}
