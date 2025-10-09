use std::{marker::PhantomData, sync::Arc};

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::{duplex_sponge::DuplexSpongeInterface, keccak::Keccak, DefaultHash, DefaultRng};
use crate::{
    duplex_sponge::Unit, 
    pattern::{Hierarchy, Interaction, InteractionPattern, Kind, Label, Length, Pattern, PatternError, PatternPlayer}, 
    BytesToUnitSerialize, CommonUnitToBytes, UnitToBytes, UnitTranscript
};

/// [`ProverState`] is the prover state of an interactive proof (IP) system.
/// It internally holds the **secret coins** of the prover for zero-knowledge, and
/// has the hash function state for the verifier state.
///
/// Unless otherwise specified,
/// [`ProverState`] is set to work over bytes with [`DefaultHash`] and
/// rely on the default random number generator [`DefaultRng`].
///
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

impl<U, H> From<&InteractionPattern> for ProverState<H, U, DefaultRng>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn from(pattern: &InteractionPattern) -> Self {
        Self::new(Arc::new(pattern.clone()), DefaultRng::default())
    }
}

impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    pub fn new(pattern: Arc<InteractionPattern>, csrng: R) -> Self {
        let iv = pattern.domain_separator();

        let mut duplex_sponge = Keccak::default();
        duplex_sponge.absorb_unchecked(&iv);
        let rng = ProverPrivateRng {
            ds: duplex_sponge,
            csrng,
        };

        Self {
            pattern: PatternPlayer::new(pattern),
            rng,
            duplex_sponge: H::new(iv),
            narg_string: Vec::new(),
            _unit_type: PhantomData,
        }
    }

    /// Add units with a label to the transcript
    pub fn add_units(&mut self, label: Label, input: &[U]) -> Result<&mut Self, PatternError> {
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Message,
            label,
            Length::Fixed(input.len()),
        ))?;

        self.duplex_sponge.absorb_unchecked(input);
        let old_len = self.narg_string.len();
        U::write(input, &mut self.narg_string)
            .map_err(|_| PatternError::AlreadyFinalized)?;
        self.rng.ds.absorb_unchecked(&self.narg_string[old_len..]);
        
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
        self.pattern.begin_protocol(label)?;
        Ok(self)
    }

    /// End a protocol
    pub fn end_protocol(&mut self, label: Label) -> Result<&mut Self, PatternError> {
        self.pattern.end_protocol(label)?;
        Ok(self)
    }

    pub fn ratchet(&mut self) -> Result<&mut Self, PatternError> {
        self.pattern.interact(Interaction::new::<()>(
            Hierarchy::Atomic,
            Kind::Protocol,
            Label::RATCHET,
            Length::None,
        ))?;
        self.duplex_sponge.ratchet_unchecked();
        Ok(self)
    }

    pub fn hint_bytes(&mut self, label: Label, hint: &[u8]) -> Result<&mut Self, PatternError> {
        self.pattern.interact(Interaction::new::<u8>(
            Hierarchy::Atomic,
            Kind::Hint,
            label,
            Length::Dynamic,
        ))?;
        let len = u32::try_from(hint.len()).map_err(|_| PatternError::AlreadyFinalized)?;
        self.narg_string.extend_from_slice(&len.to_le_bytes());
        self.narg_string.extend_from_slice(hint);
        Ok(self)
    }

    pub fn abort(mut self) -> Result<(), PatternError> {
        self.pattern.abort()?;
        self.duplex_sponge.zeroize();
        self.rng.ds.zeroize();
        self.narg_string.zeroize();
        Ok(())
    }

    pub fn finalize(mut self) -> Result<Vec<u8>, PatternError> {
        self.pattern.finalize()?;
        self.duplex_sponge.zeroize();
        self.rng.ds.zeroize();
        Ok(self.narg_string)
    }

    pub fn rng(&mut self) -> &mut (impl CryptoRng + RngCore) {
        &mut self.rng
    }

    pub fn narg_string(&self) -> &[u8] {
        self.narg_string.as_slice()
    }
}

impl<H, U, R> UnitTranscript<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn public_units(&mut self, label: Label, input: &[U]) -> Result<&mut Self, PatternError> {
        // Record single atomic interaction for public units
        self.pattern.interact(Interaction::new::<U>(
            Hierarchy::Atomic,
            Kind::Public,
            label,
            Length::Fixed(input.len()),
        ))?;

        self.duplex_sponge.absorb_unchecked(input);
        let old_len = self.narg_string.len();
        U::write(input, &mut self.narg_string)
            .map_err(|_| PatternError::AlreadyFinalized)?;
        self.rng.ds.absorb_unchecked(&self.narg_string[old_len..]);
        
        Ok(self)
    }

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

impl<R: RngCore + CryptoRng> CryptoRng for ProverPrivateRng<R> {}

impl<H, U, R> core::fmt::Debug for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.pattern.fmt(f)
    }
}

// Implements Pattern trait for ProverState by delegating to the internal PatternPlayer
impl<H, U, R> crate::pattern::Pattern for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
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

impl<H, R> BytesToUnitSerialize for ProverState<H, u8, R>
where
    H: DuplexSpongeInterface<u8>,
    R: RngCore + CryptoRng,
{
    fn add_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError> {
        self.pattern.begin_message::<u8>(label, Length::Fixed(input.len()))?;
        self.add_units(Label::UNITS, input)?;
        self.pattern.end_message::<u8>(label, Length::Fixed(input.len()))?;
        Ok(self)
    }
}

impl<H, R> CommonUnitToBytes for ProverState<H, u8, R>
where
    H: DuplexSpongeInterface<u8>,
    R: RngCore + CryptoRng,
{
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError> {
        self.public_units(label, input)
    }
}

impl<H, R> UnitToBytes for ProverState<H, u8, R>
where
    H: DuplexSpongeInterface<u8>,
    R: RngCore + CryptoRng,
{
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> Result<&mut Self, PatternError> {
        self.pattern.begin_challenge::<u8>(label, Length::Fixed(output.len()))?;
        self.fill_challenge_units(Label::UNITS, output)?;
        self.pattern.end_challenge::<u8>(label, Length::Fixed(output.len()))?;
        Ok(self)
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
        let mut pattern = PatternState::<u8>::new();
        pattern.message_bytes(Label::BYTES, 4).expect("Failed to add message bytes");
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(&pattern);

        pstate.add_bytes(Label::BYTES, &[1, 2, 3, 4]).expect("Failed to add bytes");

        let mut buf = [0u8; 8];
        pstate.rng().fill_bytes(&mut buf);
        assert_ne!(buf, [0; 8]);
        let _proof = pstate.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_prover_state_public_units_does_not_affect_narg() {
        let mut pattern = PatternState::<u8>::new();
        pattern.public_units(Label::custom("public_units"), 4);
        let pattern = pattern.finalize();
        let mut pstate: ProverState = ProverState::from(&pattern);

        pstate.public_units(Label::custom("public_units"), &[1, 2, 3, 4]);
        assert_eq!(pstate.narg_string(), b"");
        let _proof = pstate.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_prover_state_ratcheting_changes_rng_output() {
        let mut pattern = PatternState::<u8>::new();
        pattern.ratchet();
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(&pattern);
        let mut buf1 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf1);
        pstate.ratchet().expect("Failed to ratchet");
        let mut buf2 = [0u8; 4];
        pstate.rng().fill_bytes(&mut buf2);

        // TODO: This test is broken. You'd expect these to be different even without the ratchet.
        assert_ne!(buf1, buf2);
        let _proof = pstate.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_add_units_appends_to_narg_string() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units(Label::UNITS, 3);
        let pattern = pattern.finalize();
        let mut pstate: ProverState = ProverState::from(&pattern);

        let input = [42, 43, 44];

        pstate.add_units(Label::UNITS, &input).expect("Failed to add units");
        let proof = pstate.finalize().expect("Failed to finalize");
        assert_eq!(proof, &input);
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Message units Fixed(3) u8, but expected Atomic Message units Fixed(2) u8"
    )]
    fn test_add_units_too_many_elements_should_panic() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units(Label::UNITS, 2);
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(&pattern);
        pstate.add_units(Label::UNITS, &[1, 2, 3]).expect("Failed to add units");
    }

    #[test]
    fn test_ratchet_works_when_expected() {
        let mut pattern = PatternState::<u8>::new();
        pattern.ratchet();
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(&pattern);
        pstate.ratchet().expect("Failed to ratchet");
        let _proof = pstate.finalize().expect("Failed to finalize");
    }

    #[test]
    #[should_panic(
        expected = "Received interaction Atomic Protocol ratchet None (), but expected Atomic Message units Fixed(4) u8"
    )]
    fn test_ratchet_fails_when_not_expected() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units(Label::UNITS, 4);
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(&pattern);
        pstate.ratchet().expect("Failed to ratchet");
        let _proof = pstate.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_fill_challenge_units() {
        let mut pattern = PatternState::<u8>::new();
        pattern.begin_challenge::<u8>(Label::custom("fill_challenge_units"), Length::Fixed(8)).expect("Failed to begin challenge");
        let _ = pattern.challenge_units(Label::UNITS, 8);
        pattern.end_challenge::<u8>(Label::custom("fill_challenge_units"), Length::Fixed(8)).expect("Failed to end challenge");
        let pattern = pattern.finalize();

        let mut pstate: ProverState = ProverState::from(&pattern);
        let mut out = [0u8; 8];
        pstate.fill_challenge_units(Label::custom("fill_challenge_units"), &mut out).expect("Failed to fill challenge units");
        assert_eq!(out, [62, 110, 82, 217, 159, 135, 60, 9]);
        let _proof = pstate.finalize().expect("Failed to finalize");
    }

    #[test]
    fn test_rng_entropy_changes_with_transcript() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_bytes(Label::BYTES, 3).expect("Failed to add message bytes");
        let pattern = pattern.finalize();

        let mut p1: ProverState = ProverState::from(&pattern);
        let mut p2: ProverState = ProverState::from(&pattern);

        let mut a = [0u8; 16];
        let mut b = [0u8; 16];

        p1.rng().fill_bytes(&mut a);
        p2.add_bytes(Label::BYTES, &[1, 2, 3]).expect("Failed to add bytes");
        p2.rng().fill_bytes(&mut b);

        assert_ne!(a, b);
        p1.abort().expect("Failed to abort");
        p2.abort().expect("Failed to abort");
    }

    #[test]
    fn test_add_units_multiple_accumulates() {
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.message_units(Label::UNITS, 2);
        let _ = pattern.message_units(Label::UNITS, 3);
        let pattern = pattern.finalize();

        let mut p: ProverState = ProverState::from(&pattern);
        p.add_units(Label::UNITS, &[10, 11]).expect("Failed to add units");
        p.add_units(Label::UNITS, &[20, 21, 22]).expect("Failed to add units");
        assert_eq!(p.finalize().expect("Failed to finalize"), &[10, 11, 20, 21, 22]);
    }

    #[test]
    fn test_narg_string_round_trip_check() {
        let mut pattern = PatternState::<u8>::new();
        pattern.message_units(Label::UNITS, 5);
        let pattern = pattern.finalize();

        let mut p: ProverState = ProverState::from(&pattern);
        let msg = b"zkp42";
        p.add_units(Label::UNITS, msg).expect("Failed to add units");
        assert_eq!(p.finalize().expect("Failed to finalize"), msg);
    }

    #[test]
    fn test_hint_bytes_appends_hint_length_and_data() {
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let mut prover: ProverState = ProverState::from(&pattern);
        let hint = b"abc123";
        prover.hint_bytes(Label::custom("hint_bytes"), hint).expect("Failed to add hint bytes");
        let expected = [6, 0, 0, 0, b'a', b'b', b'c', b'1', b'2', b'3'];
        assert_eq!(prover.finalize().expect("Failed to finalize"), &expected);
    }

    #[test]
    fn test_hint_bytes_empty_hint_is_encoded_correctly() {
        let mut pattern = PatternState::<u8>::new();
        let _ = pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let mut prover: ProverState = ProverState::from(&pattern);
        let _ = prover.hint_bytes(Label::custom("hint_bytes"), b"");
        assert_eq!(prover.finalize().expect("Failed to finalize"), &[0, 0, 0, 0]);
    }

    #[test]
    #[should_panic(
        expected = "Received interaction, but no more expected interactions: Atomic Hint hint_bytes Dynamic u8"
    )]
    fn test_hint_bytes_fails_if_hint_op_missing() {
        let pattern = PatternState::<u8>::new().finalize();

        let mut prover: ProverState = ProverState::from(&pattern);
        // indicate a hint without a matching hint_bytes interaction
        let _ = prover
            .hint_bytes(Label::custom("hint_bytes"), b"some_hint")
            .expect("Should have failed due to missing hint interaction");
    }
    
    #[test]
    fn test_hint_bytes_is_deterministic() {
        let mut pattern = PatternState::<u8>::new();
        pattern.hint_bytes_dynamic(Label::custom("hint_bytes"));
        let pattern = pattern.finalize();

        let hint = b"zkproof_hint";
        let mut prover1: ProverState = ProverState::from(&pattern);
        let mut prover2: ProverState = ProverState::from(&pattern);

        prover1.hint_bytes(Label::custom("hint_bytes"), hint).expect("Failed to add hint bytes");
        prover2.hint_bytes(Label::custom("hint_bytes"), hint).expect("Failed to add hint bytes");

        assert_eq!(
            prover1.narg_string(),
            prover2.narg_string(),
            "Encoding should be deterministic"
        );
        let _proof1 = prover1.finalize().expect("Failed to finalize");
        let _proof2 = prover2.finalize().expect("Failed to finalize");
    }
}