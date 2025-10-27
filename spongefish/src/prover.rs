use std::{marker::PhantomData, sync::Arc};

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::{duplex_sponge::DuplexSpongeInterface, keccak::Keccak, DefaultHash, DefaultRng};
use crate::{
    duplex_sponge::Unit,
    pattern::{
        Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, Pattern, PatternPlayer,
    },
    ByteTranscript, MessageWriter, UnitTranscript,
};

/// A cryptographically-secure random number generator that is bound to the protocol transcript.
///
/// For most public-coin protocols it is *vital* not to have two different verifier messages for the same prover message.
/// For this reason, we construct a Rng that will absorb whatever the verifier absorbs, and that in addition
/// it is seeded by a cryptographic random number generator (by default, [`rand::rngs::OsRng`]).
///
/// Every time a challenge is being generated, the private prover sponge is ratcheted, so that it can't be inverted and the randomness recovered.
pub struct ProverPrivateRng<R: RngCore + CryptoRng> {
    /// The duplex sponge that is used to generate the random coins.
    pub(crate) ds: Keccak,
    /// The cryptographic random number generator that seeds the sponge.
    pub(crate) csrng: R,
}

impl<R: RngCore + CryptoRng> RngCore for ProverPrivateRng<R> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(buf.as_mut());
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(buf.as_mut());
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Seed (at most) 32 bytes of randomness from the CSRNG
        let len = usize::min(dest.len(), 32);
        self.csrng.fill_bytes(&mut dest[..len]);
        self.ds.absorb_unchecked(&dest[..len]);
        // fill `dest` with the output of the sponge
        self.ds.squeeze_unchecked(dest);
        // erase the state from the sponge so that it can't be reverted
        self.ds.ratchet_unchecked();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.ds.squeeze_unchecked(dest);
        Ok(())
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverPrivateRng<R> {}

/// [`ProverState`] is the prover state of an interactive proof (IP) system.
/// It internally holds the **secret coins** of the prover for zero-knowledge, and
/// has the hash function state for the verifier state.
///
/// Unless otherwise specified,
/// [`ProverState`] is set to work over bytes with [`DefaultHash`] and
/// rely on the default random number generator [`DefaultRng`].
///
/// # Safety
///
/// The prover state is meant to be private in contexts where zero-knowledge is desired.
/// Leaking the prover state *will* leak the prover's private coins and as such it will compromise the zero-knowledge property.
/// [`ProverState`] does not implement [`Clone`] or [`Copy`] to prevent accidental leaks.
pub struct ProverState<H = DefaultHash, U = u8, R = DefaultRng>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// The interaction pattern being followed.
    pub(crate) pattern: PatternPlayer,
    /// The randomness state of the prover.
    pub(crate) rng: ProverPrivateRng<R>,
    /// The public coins for the protocol
    pub(crate) duplex_sponge: H,
    /// The encoded data.
    pub(crate) narg_string: Vec<u8>,
    /// Unit type
    pub(crate) _unit_type: PhantomData<U>,
}

impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Create a new prover state.
    pub fn new(pattern: InteractionPattern, csrng: R) -> Self {
        let pattern = Arc::new(pattern);
        let iv = pattern.domain_separator();

        let mut duplex_sponge = Keccak::default();
        duplex_sponge.absorb_unchecked(&iv);
        let rng = ProverPrivateRng {
            ds: duplex_sponge,
            csrng,
        };

        let mut state = Self {
            pattern: PatternPlayer::new(pattern.clone()),
            rng,
            duplex_sponge: H::new(iv),
            narg_string: Vec::new(),
            _unit_type: PhantomData,
        };

        // Handle the automatic protocol wrapping that PatternState::finalize() adds
        // The pattern starts with Begin Protocol, so we need to consume it
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

    /// Add units with a label to the transcript.
    ///
    /// # Panics
    ///
    /// Panics if the interaction doesn't match the expected pattern.
    pub fn add_units(&mut self, label: Label, input: &[U]) {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(input.len()),
        ));

        self.duplex_sponge.absorb_unchecked(input);
        let old_len = self.narg_string.len();
        U::write(input, &mut self.narg_string)
            .unwrap_or_else(|_| panic!("Failed to write units to narg string"));
        self.rng.ds.absorb_unchecked(&self.narg_string[old_len..]);
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

    /// Add a hint to the proof.
    ///
    /// # Panics
    ///
    /// Panics if the interaction doesn't match the expected pattern.
    pub fn hint_bytes(&mut self, label: Label, hint: &[u8]) {
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ));
        let len = u32::try_from(hint.len())
            .unwrap_or_else(|_| panic!("Hint too large: {} bytes", hint.len()));
        self.narg_string.extend_from_slice(&len.to_le_bytes());
        self.narg_string.extend_from_slice(hint);
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

        // Still absorb into the private RNG for consistency
        let mut temp_buf = Vec::new();
        U::write(input, &mut temp_buf).unwrap_or_else(|_| panic!("Failed to write public units"));
        self.rng.ds.absorb_unchecked(&temp_buf);
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

    /// Get mutable reference to the RNG.
    pub fn rng(&mut self) -> &mut (impl CryptoRng + RngCore) {
        &mut self.rng
    }

    /// Get the proof string (NARG string).
    pub fn narg_string(&self) -> &[u8] {
        self.narg_string.as_slice()
    }

    /// Finalize the prover and return the proof.
    pub fn finalize(mut self) -> Vec<u8> {
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
        self.duplex_sponge.zeroize();
        self.rng.ds.zeroize();
        self.narg_string
    }

    pub fn message_units(&mut self, label: Label, input: &[U]) -> &mut Self {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(input.len()),
        ));

        self.duplex_sponge.absorb_unchecked(input);
        let old_len = self.narg_string.len();
        U::write(input, &mut self.narg_string)
            .unwrap_or_else(|_| panic!("Failed to write units to narg string"));
        self.rng.ds.absorb_unchecked(&self.narg_string[old_len..]);
        self
    }

    pub fn message_public_units(&mut self, label: Label, input: &[U]) -> &mut Self {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(input.len()),
        ));

        self.duplex_sponge.absorb_unchecked(input);
        let mut temp_buf = Vec::new();
        U::write(input, &mut temp_buf).unwrap_or_else(|_| panic!("Failed to write public units"));
        self.rng.ds.absorb_unchecked(&temp_buf);
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
}

impl<U, H> From<InteractionPattern> for ProverState<H, U, DefaultRng>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn from(pattern: InteractionPattern) -> Self {
        ProverState::new(pattern, DefaultRng::default())
    }
}

// Trait implementations
impl<H, U, R> UnitTranscript<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn message_public_units(&mut self, label: Label, input: &[U]) -> &mut Self {
        ProverState::message_public_units(self, label, input)
    }

    fn challenge_units(&mut self, label: Label, output: &mut [U]) -> &mut Self {
        ProverState::challenge_units(self, label, output)
    }
}

impl<H, R> ByteTranscript for ProverState<H, u8, R>
where
    H: DuplexSpongeInterface<u8>,
    R: RngCore + CryptoRng,
{
    fn message_bytes_unchecked(&mut self, input: &[u8]) -> &mut Self {
        self.message_units(Label::Units, input)
    }

    fn message_public_bytes_unchecked(&mut self, input: &[u8]) -> &mut Self {
        // Only absorb into sponge, don't write to proof
        self.message_public_units(Label::Units, input)
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
impl<H, R> MessageWriter<u8> for ProverState<H, u8, R>
where
    H: DuplexSpongeInterface<u8>,
    R: RngCore + CryptoRng,
{
    fn message_units(&mut self, label: Label, input: &[u8]) -> &mut Self {
        ProverState::message_units(self, label, input)
    }
}

impl<H, U, R> core::fmt::Debug for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProverState")
            .field("pattern", &self.pattern)
            .finish()
    }
}

// Implements Pattern trait for ProverState by delegating to the internal PatternPlayer
impl<H, U, R> Pattern for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codecs::{bytes::Pattern as _, unit::Pattern as _},
        pattern::{Pattern as PatternTrait, PatternState},
    };

    #[test]
    fn test_prover_state_add_units_and_rng_differs() {
        let mut pattern = PatternState::new();
        pattern.message_bytes(Label::Bytes, 4);
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(pattern);

        pstate.message_bytes(Label::Bytes, &[1, 2, 3, 4]);

        let mut buf = [0u8; 8];
        pstate.rng().fill_bytes(&mut buf);
        assert_ne!(buf, [0; 8]);
        let _proof = pstate.finalize();
    }

    #[test]
    fn test_prover_state_public_units_does_not_affect_narg() {
        let mut pattern = PatternState::new();
        pattern.message_public_units(Label::custom("public_units"), 4);
        let pattern = pattern.finalize();
        let mut pstate: ProverState = ProverState::from(pattern);
        pstate.message_public_units(Label::custom("public_units"), &[1, 2, 3, 4]);
        assert_eq!(pstate.narg_string(), b"");
        let _proof = pstate.finalize();
    }

    #[test]
    fn test_prover_state_ratcheting_changes_rng_output() {
        let mut pattern = PatternState::new();
        pattern.ratchet();
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(pattern);
        let mut buf1 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf1);
        pstate.ratchet();
        let mut buf2 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf2);

        assert_ne!(buf1, buf2);
        let _proof = pstate.finalize();
    }

    #[test]
    fn test_add_units_appends_to_narg_string() {
        let mut pattern = PatternState::new();
        pattern.message_units(Label::Units, 3);
        let pattern = pattern.finalize();
        let mut pstate: ProverState = ProverState::from(pattern);

        let input = [42, 43, 44];

        pstate.add_units(Label::Units, &input);
        let proof = pstate.finalize();
        assert_eq!(proof, &input);
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]
    fn test_add_units_too_many_elements_should_panic() {
        let mut pattern = PatternState::new();
        pattern.message_units(Label::Units, 2);
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(pattern);
        pstate.add_units(Label::Units, &[1, 2, 3]);

        pstate.finalize();
    }

    #[test]
    fn test_ratchet_works_when_expected() {
        let mut pattern = PatternState::new();
        pattern.ratchet();
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(pattern);
        pstate.ratchet();
        let _proof = pstate.finalize();
    }

    #[test]
    #[should_panic(expected = "Unexpected interaction")]
    fn test_ratchet_fails_when_not_expected() {
        let mut pattern = PatternState::new();
        pattern.message_units(Label::Units, 4);
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(pattern);
        pstate.ratchet();
        let _proof = pstate.finalize();
    }

    #[test]
    fn test_fill_challenge_units() {
        let mut pattern = PatternState::new();
        pattern.begin_challenge::<u8>(Label::custom("fill_challenge_units"), Length::Fixed(8));
        pattern.challenge_units(Label::Units, 8);
        pattern.end_challenge::<u8>(Label::custom("fill_challenge_units"), Length::Fixed(8));
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(pattern);
        let mut out = [0u8; 8];
        pstate.challenge_bytes(Label::custom("fill_challenge_units"), &mut out);
        assert_ne!(out, [0u8; 8], "Challenge bytes should not be all zeros");
        let _proof = pstate.finalize();
    }

    #[test]
    fn test_rng_entropy_changes_with_transcript() {
        let mut pattern = PatternState::new();
        pattern.message_bytes(Label::Bytes, 3);
        let pattern = pattern.finalize();

        let mut p1: ProverState = ProverState::from(pattern.clone());
        let mut p2: ProverState = ProverState::from(pattern);

        let mut a = [0u8; 16];
        let mut b = [0u8; 16];

        p1.rng().fill_bytes(&mut a);
        p2.message_bytes(Label::Bytes, &[1, 2, 3]);
        p2.rng().fill_bytes(&mut b);

        assert_ne!(a, b);
        p1.abort();
        p2.abort();
    }

    #[test]
    fn test_add_units_multiple_accumulates() {
        let mut pattern = PatternState::new();
        pattern.message_units(Label::Units, 2);
        pattern.message_units(Label::Units, 3);
        let pattern = pattern.finalize();

        let mut p: ProverState = ProverState::from(pattern);
        p.add_units(Label::Units, &[10, 11]);
        p.add_units(Label::Units, &[20, 21, 22]);
        assert_eq!(p.finalize(), &[10, 11, 20, 21, 22]);
    }

    #[test]
    fn test_narg_string_round_trip_check() {
        let mut pattern = PatternState::new();
        pattern.message_units(Label::Units, 5);
        let pattern = pattern.finalize();

        let mut p: ProverState = ProverState::from(pattern);
        let msg = b"zkp42";
        p.add_units(Label::Units, msg);
        assert_eq!(p.finalize(), msg);
    }

    #[test]
    fn test_hint_bytes_appends_hint_length_and_data() {
        let mut pattern = PatternState::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let mut prover: ProverState = ProverState::from(pattern);
        let hint = b"abc123";
        prover.hint_bytes(Label::custom("hint_bytes"), hint);
        let expected = [6, 0, 0, 0, b'a', b'b', b'c', b'1', b'2', b'3'];
        assert_eq!(prover.finalize(), &expected);
    }

    #[test]
    fn test_hint_bytes_empty_hint_is_encoded_correctly() {
        let mut pattern = PatternState::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let mut prover: ProverState = ProverState::from(pattern);
        prover.hint_bytes(Label::custom("hint_bytes"), b"");
        assert_eq!(prover.finalize(), &[0, 0, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "No more expected interactions")]
    fn test_hint_bytes_fails_if_hint_op_missing() {
        let pattern = PatternState::new().finalize();

        let mut prover: ProverState = ProverState::from(pattern);
        prover.hint_bytes(Label::custom("hint_bytes"), b"some_hint");
        prover.finalize();
    }

    #[test]
    fn test_hint_bytes_is_deterministic() {
        let mut pattern = PatternState::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let hint = b"zkproof_hint";
        let mut prover1: ProverState = ProverState::from(pattern.clone());
        let mut prover2: ProverState = ProverState::from(pattern);

        prover1.hint_bytes(Label::custom("hint_bytes"), hint);
        prover2.hint_bytes(Label::custom("hint_bytes"), hint);

        assert_eq!(
            prover1.narg_string(),
            prover2.narg_string(),
            "Encoding should be deterministic"
        );
        let _proof1 = prover1.finalize();
        let _proof2 = prover2.finalize();
    }
}
