use std::{marker::PhantomData, sync::Arc};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit}, 
    pattern::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, Pattern, PatternError, PatternPlayer}, 
    traits::{BytesToUnitDeserialize, UnitTranscript}, 
    CommonUnitToBytes, DefaultHash, ProofResult, UnitToBytes
};

/// [`VerifierState`] is the verifier state.
///
/// Internally, it simply contains a stateful hash.
/// Given as input an [`DomainSeparator`] and a NARG string, it allows to
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
    /// Creates a new [`VerifierState`] instance with the given sponge and domain separator.
    #[must_use]
    pub fn new(pattern: Arc<InteractionPattern>, narg_string: &'a [u8]) -> Self {
        let iv = pattern.domain_separator();
        let mut state = Self {
            pattern: PatternPlayer::new(pattern.clone()),
            duplex_sponge: H::new(iv),
            narg_string,
            cursor: 0, // Index of the next byte to read from the NARG string
            _unit_type: PhantomData,
        };
        // Handle the automatic protocol wrapping that PatternState::finalize() adds
        // The pattern starts with Begin Protocol, so we need to consume it
        if pattern.interactions().first()
            .map(|i| i.hierarchy() == Hierarchy::Begin && i.kind() == Kind::Protocol && *i.label() == Label::PROTOCOL)
            .unwrap_or(false)
        {
            if let Err(e) = state.pattern.begin::<()>(Label::PROTOCOL, Kind::Protocol, Length::None) {
                // If we fail to begin, mark as finalized to avoid panic in Drop
                let _ = state.pattern.abort();
                panic!("Failed to begin protocol: {e}");
            }
        }
        state
    }

    /// Read units from the proof
    pub fn fill_next_units(&mut self, label: Label, output: &mut [U]) -> Result<&mut Self, PatternError> {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(output.len()),
        ))?;

        // Read from narg_string and update cursor
        let bytes_needed = output.len() * std::mem::size_of::<U>();
        if self.cursor + bytes_needed > self.narg_string.len() {
            return Err(PatternError::SizeError(format!("Insufficient transcript remaining for deserialization")).into());
        }

        U::read(&mut &self.narg_string[self.cursor..self.cursor + bytes_needed], output).map_err(|e| PatternError::DeserializationError(format!("Deserialization error: {}", e)))?;
        
        self.cursor += bytes_needed;
        
        // Also absorb into the duplex sponge for challenge generation
        self.duplex_sponge.absorb_unchecked(output);
        
        Ok(self)
    }

    /// Begin a message interaction
    pub fn begin_message(&mut self, label: Label, count: usize) -> ProofResult<&mut Self> {
        self.pattern.begin_message::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// End a message interaction
    pub fn end_message(&mut self, label: Label, count: usize) -> ProofResult<&mut Self> {
        self.pattern.end_message::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// Begin a challenge interaction
    pub fn begin_challenge<T>(&mut self, label: Label, count: usize) -> ProofResult<&mut Self> {
        self.pattern.begin_challenge::<T>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// End a challenge interaction
    pub fn end_challenge<T>(&mut self, label: Label, count: usize) -> ProofResult<&mut Self> {
        self.pattern.end_challenge::<T>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// Begin a public interaction
    pub fn begin_public(&mut self, label: Label, count: usize) -> ProofResult<&mut Self> {
        self.pattern.begin_public::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// End a public interaction
    pub fn end_public(&mut self, label: Label, count: usize) -> ProofResult<&mut Self> {
        self.pattern.end_public::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// Begin a protocol
    pub fn begin_protocol(&mut self, label: Label) -> ProofResult<&mut Self> {
        self.pattern.begin_protocol(label)?;
        Ok(self)
    }

    /// End a protocol
    pub fn end_protocol(&mut self, label: Label) -> ProofResult<&mut Self> {
        self.pattern.end_protocol(label)?;
        Ok(self)
    }

    #[inline]
    pub fn ratchet(&mut self) -> ProofResult<&mut Self> {
        self.pattern.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            Label::RATCHET,
            Length::None,
        ))?;
        self.duplex_sponge.ratchet_unchecked();
        Ok(self)
    }

    pub fn hint_bytes(&mut self, label: Label) -> Result<&'a [u8], std::io::Error> {
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        )).map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Pattern error"))?;
        
        if self.narg_string[self.cursor..].len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Insufficient transcript remaining for hint",
            ));
        }
        
        let len = u32::from_le_bytes(
            self.narg_string[self.cursor..self.cursor + 4]
                .try_into()
                .unwrap()
        ) as usize;
        self.cursor += 4;
        
        let rest = &self.narg_string[self.cursor..];
        
        if rest.len() < len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Insufficient transcript remaining, got {}, need {len}", rest.len()),
            ));
        }
        
        let hint = &rest[..len];
        self.cursor += len;
        Ok(hint)
    }

    pub fn abort(mut self) -> Result<(), PatternError> {
        self.pattern.abort()?;
        Ok(())
    }

    pub fn finalize(mut self) -> Result<(), PatternError> {
        // Handle the automatic protocol wrapping that PatternState::finalize() adds
        // The pattern ends with End Protocol, so we need to consume it
        let arc_pattern = self.pattern.pattern().clone();
        if arc_pattern.interactions().last()
            .map(|i| i.hierarchy() == Hierarchy::End && i.kind() == Kind::Protocol && *i.label() == Label::PROTOCOL)
            .unwrap_or(false)
        {
            self.pattern.end::<()>(Label::PROTOCOL, Kind::Protocol, Length::None)?;
        }
        
        self.pattern.finalize()?;
        Ok(())
    }
}


impl<H: DuplexSpongeInterface<U>, U: Unit> UnitTranscript<U> for VerifierState<'_, H, U> {
    fn public_units(&mut self, label: Label, input: &[U]) -> Result<&mut Self, PatternError> {
        // Record single atomic interaction for public units
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(input.len()),
        ))?;
        
        self.duplex_sponge.absorb_unchecked(input);
        
        Ok(self)
    }

    #[inline]
    fn fill_challenge_units(&mut self, label: Label, output: &mut [U]) -> Result<&mut Self, PatternError> {
        // Record single atomic interaction for challenge units
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            label,
            Length::Fixed(output.len()),
        ))?;
        
        self.duplex_sponge.squeeze_unchecked(output);
        
        Ok(self)
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> core::fmt::Debug for VerifierState<'_, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifierState").field(&self.pattern).finish()
    }
}

// Implements Pattern trait for VerifierState by delegating to the internal PatternPlayer
impl<'a, H, U> Pattern for VerifierState<'a, H, U>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn abort(&mut self) -> Result<(), PatternError> {
        self.pattern.abort()
    }

    fn begin<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
        self.pattern.begin::<T>(label, kind, length)?;
        Ok(self)
    }

    fn end<T: ?Sized>(&mut self, label: Label, kind: Kind, length: Length) -> Result<&mut Self, PatternError> {
        self.pattern.end::<T>(label, kind, length)?;
        Ok(self)
    }
}


impl<H: DuplexSpongeInterface<u8>> BytesToUnitDeserialize for VerifierState<'_, H, u8> {
    #[inline]
    fn fill_next_bytes(&mut self, label: Label, output: &mut [u8]) -> Result<&mut Self, PatternError> {
        self.pattern.begin_message::<u8>(label, Length::Fixed(output.len()))?;
        self.fill_next_units(Label::UNITS, output)?;
        
        self.pattern.end_message::<u8>(label, Length::Fixed(output.len()))?;
        
        Ok(self)
    }
}

impl<H: DuplexSpongeInterface<u8>> CommonUnitToBytes for VerifierState<'_, H, u8> {
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError> {
        self.public_units(label, input)
    }
}

impl<H: DuplexSpongeInterface<u8>> UnitToBytes for VerifierState<'_, H, u8> {
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> Result<&mut Self, PatternError> {
        self.pattern.begin_challenge::<u8>(label, Length::Fixed(output.len()))?;
        self.fill_challenge_units(Label::UNITS, output)?;
        self.pattern.end_challenge::<u8>(label, Length::Fixed(output.len()))?;
        Ok(self)
    }
}

// Implements Pattern trait for byte operations
impl<H> crate::codecs::bytes::Pattern for VerifierState<'_, H, u8>
where
    H: DuplexSpongeInterface<u8>,
{
    fn public_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.pattern.begin_public::<u8>(label, Length::Fixed(size))?;
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Public,
            Label::UNITS,
            Length::Fixed(size),
        ))?;
        self.pattern.end_public::<u8>(label, Length::Fixed(size))?;
        Ok(self)
    }

    fn message_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.pattern.begin_message::<u8>(label, Length::Fixed(size))?;
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Message,
            Label::UNITS,
            Length::Fixed(size),
        ))?;
        self.pattern.end_message::<u8>(label, Length::Fixed(size))?;
        Ok(self)
    }

    fn challenge_bytes(&mut self, label: Label, size: usize) -> Result<&mut Self, PatternError> {
        self.pattern.begin_challenge::<u8>(label, Length::Fixed(size))?;
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::UNITS,
            Length::Fixed(size),
        ))?;
        self.pattern.end_challenge::<u8>(label, Length::Fixed(size))?;
        Ok(self)
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
    use super::*;
    use crate::{
        codecs::{bytes::Pattern as BytesPattern, unit::Pattern},
        pattern::PatternState,
        prover::ProverState,
    };
    use test_utils::DummySponge;

    #[test]
    fn test_fill_next_units_with_message() {
        // Create pattern using high-level method
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.message_units(Label::UNITS, 3);
        let pattern = Arc::new(pattern.finalize());
        
        let mut vs = VerifierState::<DummySponge>::new(Arc::clone(&pattern), b"abc");
        let mut buf = [0u8; 3];
        
        assert!(vs.fill_next_units(Label::UNITS, &mut buf).is_ok());
        assert_eq!(buf, *b"abc");
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), b"abc");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_new_verifier_state_constructs_correctly() {
        let pattern = PatternState::<u8>::new().finalize();
        let transcript = b"abc";
        let vs = VerifierState::<DummySponge>::new(Arc::new(pattern), transcript);
        assert_eq!(vs.narg_string, b"abc");
        assert_eq!(vs.cursor, 0);
        let _ = vs.finalize();
    }

    #[test]
    fn test_fill_next_units_with_insufficient_data_errors() {
        // Create pattern with more data than available
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.message_units(Label::UNITS, 4);
        let pattern = Arc::new(pattern.finalize());
        
        let mut vs = VerifierState::<DummySponge>::new(Arc::clone(&pattern), b"xy");
        let mut buf = [0u8; 4];
        
        assert!(vs.fill_next_units(Label::UNITS, &mut buf).is_err());
        vs.abort().expect("Failed to abort");
    }

    #[test]
    fn test_ratcheting_success() {
        // Create pattern with ratchet
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.ratchet();
        let pattern = Arc::new(pattern.finalize());
        
        let mut vs = VerifierState::<DummySponge>::new(Arc::clone(&pattern), &[]);
        vs.ratchet().expect("Failed to ratchet");
        assert!(*vs.duplex_sponge.ratcheted.borrow());
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_unit_transcript_public_units() {
        // Create pattern with public units
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.public_units(Label::from("public_units"), 2);
        let pattern = Arc::new(pattern.finalize());
        
        let mut vs = VerifierState::<DummySponge>::new(Arc::clone(&pattern), b"..");
        let _ = vs.public_units(Label::from("public_units"), &[1, 2]);
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), &[1, 2]);
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_unit_transcript_fill_challenge_units() {
        // Create pattern with challenge
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.challenge_units(Label::from("challenge"), 4);
        let pattern = Arc::new(pattern.finalize());
        
        let mut vs = VerifierState::<DummySponge>::new(Arc::clone(&pattern), b"");
        
        let mut out = [0u8; 4];
        vs.fill_challenge_units(Label::from("challenge"), &mut out)
            .expect("Failed to fill challenge units");
        
        assert_eq!(out, [0, 1, 2, 3]);
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_fill_next_bytes_impl() {
        // Create pattern with message bytes
        let mut pattern = PatternState::<u8>::new();
        pattern.message_bytes(Label::from("bytes"), 3).expect("Failed to create pattern");
        let pattern = Arc::new(pattern.finalize());
        
        let mut vs = VerifierState::<DummySponge>::new(Arc::clone(&pattern), b"xyz");
        let mut out = [0u8; 3];
        
        assert!(vs.fill_next_bytes(Label::from("bytes"), &mut out).is_ok());
        assert_eq!(out, *b"xyz");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_hint_bytes_verifier_valid_hint() {
        // Create pattern with hint
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.hint_bytes_dynamic(Label::from("hint_bytes"));
        let pattern = Arc::new(pattern.finalize());
        
        let hint = b"abc123";
        
        // Create prover and add hint
        let mut prover: ProverState = ProverState::from(pattern.as_ref());
        prover.hint_bytes(Label::from("hint_bytes"), hint).expect("Failed to add hint bytes");
        
        let narg = prover.finalize().expect("Failed to finalize prover");
        
        // Verify with verifier
        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let result = vs.hint_bytes(Label::from("hint_bytes")).unwrap();
        
        assert_eq!(result, hint);
        vs.finalize().expect("Failed to finalize verifier");
    }

    #[test]
    fn test_hint_bytes_verifier_empty_hint() {
        // Create pattern with hint
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.hint_bytes_dynamic(Label::from("hint_bytes"));
        let pattern = Arc::new(pattern.finalize());
        
        let hint = b"";
        
        // Create prover and add empty hint
        let mut prover: ProverState = ProverState::from(pattern.as_ref());
        prover.hint_bytes(Label::from("hint_bytes"), hint).expect("Failed to add hint bytes");
        let narg = prover.finalize().expect("Failed to finalize");
        
        // Verify with verifier
        let mut vs: VerifierState = VerifierState::new(pattern, &narg);
        let result = vs.hint_bytes(Label::from("hint_bytes")).unwrap();
        
        assert_eq!(result, b"");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_hint_bytes_verifier_no_hint_op() {
        let mut pattern = PatternState::<u8>::new();
        pattern.public_bytes(Label::custom("public_bytes"), 2).unwrap();
        let pattern = pattern.finalize();
        // Manually construct a hint buffer (length = 6, followed by bytes)
        let narg = hex::decode("06000000616263313233").unwrap();
        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), &narg);
        let err = vs.hint_bytes(Label::custom("hint_bytes"));
        assert!(err.is_err());
    }

    #[test]
    fn test_hint_bytes_verifier_length_prefix_too_short() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes")).expect("Failed to add hint bytes to pattern");
        let pattern = pattern.finalize();
        
        // Provide only 3 bytes, which is not enough for a u32 length
        let narg = &[1, 2, 3]; // less than 4 bytes
        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), narg);
        let err = vs.hint_bytes(Label::custom("hint_bytes")).unwrap_err();
        
        assert!(format!("{err}").contains("Insufficient transcript remaining for hint"));
        vs.abort().expect("Failed to abort");
    }

    #[test]
    fn test_hint_bytes_verifier_declared_hint_too_long() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes")).expect("Failed to add hint bytes to pattern");
        let pattern = pattern.finalize();
        
        let narg = [5u8, 0, 0, 0, b'a', b'b'];
        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), &narg);
        let err = vs.hint_bytes(Label::custom("hint_bytes")).unwrap_err();
        
        assert!(format!("{err}").contains("Insufficient transcript remaining"));
        vs.abort().expect("Failed to abort");
    }
}