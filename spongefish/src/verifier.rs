use std::{marker::PhantomData, sync::Arc};

use ark_ff::{Fp, FpConfig};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit}, pattern::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, Pattern, PatternError, PatternPlayer}, traits::{BytesToUnitDeserialize, UnitTranscript}, CommonUnitToBytes, DefaultHash, ProofResult, UnitToBytes
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
    pub(crate) _unit_type: PhantomData<U>,
}

impl<'a, U: Unit, H: DuplexSpongeInterface<U>> VerifierState<'a, H, U> {
    /// Creates a new [`VerifierState`] instance with the given sponge and domain separator.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    ///
    /// ```
    /// # use spongefish::*;
    ///
    /// let domsep = DomainSeparator::<DefaultHash>::new("📝").absorb(1, "inhale 🫁").squeeze(32, "exhale 🎏");
    /// // A silly NARG string for the example.
    /// let narg_string = &[0x42];
    /// let mut verifier_state = domsep.to_verifier_state(narg_string);
    /// assert_eq!(verifier_state.next_bytes().unwrap(), [0x42]);
    /// let challenge = verifier_state.challenge_bytes::<32>();
    /// assert!(challenge.is_ok());
    /// assert_ne!(challenge.unwrap(), [0; 32]);
    /// ```
    #[must_use]
    pub fn new(pattern: Arc<InteractionPattern>, narg_string: &'a [u8]) -> Self {
        let iv = pattern.domain_separator();
        Self {
            pattern: PatternPlayer::new(pattern),
            duplex_sponge: H::new(iv),
            narg_string,
            _unit_type: PhantomData,
        }
    }

    #[inline]
    pub fn fill_next_units(&mut self, label: Label, input: &mut [U]) -> Result<&mut Self, std::io::Error> {
        // Use proper begin_message to match the pattern
        self.pattern.begin_message::<U>(label.clone(), Length::Fixed(input.len()))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to begin message"))?;

        // Process the atomic interaction
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            Label::custom("units"),
            Length::Fixed(input.len()),
        )).map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to interact"))?;

        U::read(&mut self.narg_string, input)?;
        self.duplex_sponge.absorb_unchecked(input);

        // Use proper end_message to match the pattern
        self.pattern.end_message::<U>(label, Length::Fixed(input.len()))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to end message"))?;

        Ok(self)
    }

    /// Begin a message interaction
    pub fn begin_message(&mut self, label: Label, count: usize) -> Result<&mut Self, PatternError> {
        self.pattern.begin_message::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// End a message interaction
    pub fn end_message(&mut self, label: Label, count: usize) -> Result<&mut Self, PatternError> {
        self.pattern.end_message::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// Begin a challenge interaction
    pub fn begin_challenge(&mut self, label: Label, count: usize) -> Result<&mut Self, PatternError> {
        self.pattern.begin_challenge::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// End a challenge interaction
    pub fn end_challenge(&mut self, label: Label, count: usize) -> Result<&mut Self, PatternError> {
        self.pattern.end_challenge::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// Begin a public interaction
    pub fn begin_public(&mut self, label: Label, count: usize) -> Result<&mut Self, PatternError> {
        self.pattern.begin_public::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// End a public interaction
    pub fn end_public(&mut self, label: Label, count: usize) -> Result<&mut Self, PatternError> {
        self.pattern.end_public::<U>(label, Length::Fixed(count))?;
        Ok(self)
    }

    /// Begin a protocol
    pub fn begin_protocol(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.pattern.begin_protocol::<()>(label)?;
        Ok(self)
    }

    /// End a protocol
    pub fn end_protocol(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.pattern.end_protocol::<()>(label)?;
        Ok(self)
    }

    /// Signals the end of the statement.
    #[inline]
    pub fn ratchet(&mut self) -> Result<&mut Self, PatternError> {
        self.pattern.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            Label::custom("ratchet"),
            Length::None,
        ))?;
        self.duplex_sponge.ratchet_unchecked();
        Ok(self)
    }

    /// Read a hint from the NARG string.
    pub fn hint_bytes(&mut self, label: Label) -> Result<&'a [u8], std::io::Error> {
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        )).map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Pattern error"))?;

        if self.narg_string.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Insufficient transcript remaining for hint",
            ));
        }

        let len = u32::from_le_bytes(self.narg_string[..4].try_into().unwrap()) as usize;
        let rest = &self.narg_string[4..];

        if rest.len() < len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Insufficient transcript remaining, got {}, need {len}", rest.len()),
            ));
        }

        let (hint, remaining) = rest.split_at(len);
        self.narg_string = remaining;

        Ok(hint)
    }

    /// Abort the verifier session without completing playback.
    ///
    /// Any remaining expected interactions are discarded.
    pub fn abort(mut self) -> Result<(), crate::pattern::PatternError> {
        self.pattern.abort()?;
        Ok(())
    }

    /// Finalize the verifier session, asserting all interactions were consumed.
    pub fn finalize(self) -> Result<(), crate::pattern::PatternError> {
        self.pattern.finalize()?;
        Ok(())
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> UnitTranscript<U> for VerifierState<'_, H, U> {
    /// Add native elements to the sponge without writing them to the NARG string.
    fn public_units(&mut self, label: Label, input: &[U]) -> Result<&mut Self, PatternError> {
        // Use proper begin_public to match the pattern
        self.pattern.begin_public::<U>(label.clone(), Length::Fixed(input.len()))?;

        // Process the atomic interaction
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            Label::custom("units"),
            Length::Fixed(input.len()),
        ))?;

        self.duplex_sponge.absorb_unchecked(input);

        // Use proper end_public to match the pattern
        self.pattern.end_public::<U>(label, Length::Fixed(input.len()))?;
        
        Ok(self)
    }

    #[inline]
    fn fill_challenge_units(&mut self, label: Label, input: &mut [U]) -> Result<&mut Self, PatternError> {
        // Use proper begin_challenge to match the pattern
        self.pattern.begin_challenge::<U>(label.clone(), Length::Fixed(input.len()))?;

        // Process the atomic interaction
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Challenge,
            Label::custom("units"),
            Length::Fixed(input.len()),
        ))?;

        self.duplex_sponge.squeeze_unchecked(input);

        // Use proper end_challenge to match the pattern
        self.pattern.end_challenge::<U>(label, Length::Fixed(input.len()))?;
        
        Ok(self)
    }
}

// In verifier.rs
impl<'a, H, C, const N: usize> VerifierState<'a, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    /// Helper to deserialize curve points and absorb their coordinates
    pub(crate) fn fill_next_curve_points<G, A>(
        &mut self, 
        label: Label, 
        output: &mut [G]
    ) -> ProofResult<&mut Self>
    where
        G: From<A>,
        A: ark_serialize::CanonicalDeserialize + ark_ec::AffineRepr<BaseField = Fp<C, N>>,
    {
        // Begin the outer group message
        self.pattern.begin_message::<G>(label.clone(), Length::Fixed(output.len()))?;
        
        // Begin the inner coordinates layer
        self.pattern.begin_message::<Fp<C, N>>(Label::custom("coordinates"), Length::Fixed(output.len() * 2))?;
        
        // Process the atomic interaction
        self.pattern.interact(Interaction::new::<Fp<C, N>>(
            Hierarchy::Atomic,
            Kind::Message,
            Label::custom("units"),
            Length::Fixed(output.len() * 2),
        ))?;

        for o in output.iter_mut() {
            let affine = A::deserialize_compressed(&mut self.narg_string)?;
            *o = G::from(affine);
            
            // Extract coordinates and absorb
            let (x, y) = affine.xy().unwrap();
            self.duplex_sponge.absorb_unchecked(&[x, y]);
        }
        
        // End the inner coordinates layer
        self.pattern.end_message::<Fp<C, N>>(Label::custom("coordinates"), Length::Fixed(output.len() * 2))?;
        
        // End the outer group message
        self.pattern.end_message::<G>(label, Length::Fixed(output.len()))?;
        
        Ok(self)
    }
}

impl<H: DuplexSpongeInterface<U>, U: Unit> core::fmt::Debug for VerifierState<'_, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifierState").field(&self.pattern).finish()
    }
}

impl<H: DuplexSpongeInterface<u8>> BytesToUnitDeserialize for VerifierState<'_, H, u8> {
    #[inline]
    fn fill_next_bytes(&mut self, label: Label, input: &mut [u8]) -> Result<&mut Self, std::io::Error> {
        self.fill_next_units(label, input)
    }
}

impl<H: DuplexSpongeInterface<u8>> CommonUnitToBytes for VerifierState<'_, H, u8> {
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError> {
        self.public_units(label, input)
    }
}

impl<H: DuplexSpongeInterface<u8>> UnitToBytes for VerifierState<'_, H, u8> {
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> Result<&mut Self, PatternError> {
        self.fill_challenge_units(label, output)
    }
}
#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    use super::*;
    use crate::{
        codecs::{bytes::Pattern as _, unit::Pattern},
        pattern::PatternState,
        ProverState,
    };

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

    #[test]
    fn test_new_verifier_state_constructs_correctly() {
        let pattern = PatternState::<u8>::new().finalize();
        let transcript = b"abc";
        let vs = VerifierState::<DummySponge>::new(Arc::new(pattern), transcript);
        assert_eq!(vs.narg_string, b"abc");
        vs.finalize();
    }

    #[test]
    fn test_fill_next_units_reads_and_absorbs() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units(Label::custom("units"), 3);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"abc");
        let mut buf = [0u8; 3];
        assert!(vs.fill_next_units(&mut buf).is_ok());
        assert_eq!(buf, *b"abc");
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), b"abc");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_fill_next_units_with_insufficient_data_errors() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units(Label::custom("units"), 4);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"xy");
        let mut buf = [0u8; 4];
        assert!(vs.fill_next_units(&mut buf).is_err());
        vs.abort().expect("Failed to abort");
    }

    #[test]
    fn test_ratcheting_success() {
        let mut pattern = PatternState::<u8>::new();
        pattern.ratchet();
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), &[]);
        vs.ratchet().expect("Failed to ratchet");
        assert!(*vs.duplex_sponge.ratcheted.borrow());
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Protocol ratchet None (), but expected Atomic Message units Fixed(1) u8"
    )]
    fn test_ratcheting_wrong_op_errors() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units(Label::custom("units"), 1);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), &[]);
        vs.ratchet().expect("Failed to ratchet");
    }

    #[test]
    fn test_unit_transcript_public_units() {
        let mut pattern = PatternState::<u8>::new();
        pattern.public_units(Label::custom("public_units"), 2);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"..");
        vs.public_units(&[1, 2]);
        assert_eq!(*vs.duplex_sponge.absorbed.borrow(), &[1, 2]);
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_unit_transcript_fill_challenge_units() {
        let mut pattern = PatternState::<u8>::new();
        pattern.challenge_units(Label::custom("fill_challenge_units"), 4);
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"abcd");
        let mut out = [0u8; 4];
        vs.fill_challenge_units(&mut out);
        assert_eq!(out, [0, 1, 2, 3]);
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_fill_next_bytes_impl() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_bytes(Label::Bytes, 3).expect("Failed to add message bytes");
        let pattern = pattern.finalize();

        let mut vs = VerifierState::<DummySponge>::new(Arc::new(pattern), b"xyz");
        let mut out = [0u8; 3];
        assert!(vs.fill_next_bytes(&mut out).is_ok());
        assert_eq!(out, *b"xyz");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_hint_bytes_verifier_valid_hint() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let hint = b"abc123";
        let mut prover: ProverState = ProverState::from(&pattern);
        prover.hint_bytes(hint).expect("Failed to add hint bytes");
        let narg = prover.finalize().expect("Failed to finalize");
        assert_eq!(hex::encode(&narg), "06000000616263313233");

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern.clone()), &narg);
        let result = vs.hint_bytes().unwrap();
        assert_eq!(result, hint);
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_hint_bytes_verifier_empty_hint() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let hint = b"";
        let mut prover: ProverState = ProverState::from(&pattern);
        prover.hint_bytes(hint).expect("Failed to add hint bytes");
        let narg = prover.finalize().expect("Failed to finalize");

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern.clone()), &narg);
        let result = vs.hint_bytes().unwrap();
        assert_eq!(result, b"");
        vs.finalize().expect("Failed to finalize");
    }

    #[test]
    #[should_panic(
        expected = "Received interaction, but no more expected interactions: Atomic Hint hint_bytes Dynamic u8"
    )]
    fn test_hint_bytes_verifier_no_hint_op() {
        let pattern = PatternState::<u8>::new().finalize();

        // Manually construct a hint buffer (length = 6, followed by bytes)
        let narg = hex::decode("06000000616263313233").unwrap();

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), &narg);
        vs.hint_bytes().unwrap();
    }

    #[test]
    fn test_hint_bytes_verifier_length_prefix_too_short() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        // Provide only 3 bytes, which is not enough for a u32 length
        let narg = &[1, 2, 3]; // less than 4 bytes

        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), narg);
        let err = vs.hint_bytes().unwrap_err();
        assert!(format!("{err}").contains("Insufficient transcript remaining for hint"));
        vs.abort().expect("Failed to abort");
    }

    #[test]
    fn test_hint_bytes_verifier_declared_hint_too_long() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let narg = [5u8, 0, 0, 0, b'a', b'b'];
        let mut vs: VerifierState = VerifierState::new(Arc::new(pattern), &narg);
        let err = vs.hint_bytes().unwrap_err();
        assert!(format!("{err}").contains("Insufficient transcript remaining"));
        vs.abort().expect("Failed to abort");
    }
}
