use crate::{
    pattern::{Label, Length, Pattern},
    Unit,
};

/// Core transcript operations for generic units.
///
/// Provides operations that both prover and verifier need:
/// - Absorbing public parameters
/// - Generating challenges
pub trait UnitTranscript<U: Unit> {
    /// Absorb public units into transcript (not in proof).
    fn message_public_units(&mut self, label: impl AsRef<str>, input: &[U]) -> &mut Self;

    /// Generate challenge units from transcript.
    fn challenge_units(&mut self, label: impl AsRef<str>, output: &mut [U]) -> &mut Self;
}

/// Transcript operations for bytes (when U = u8).
///
/// Provides both low-level and high-level APIs for byte operations.
/// Most users should use the high-level methods.
pub trait ByteTranscript: Pattern {
    // ========================================================================
    // REQUIRED: Low-level operations (implementors provide these)
    // ========================================================================

    /// Add bytes to transcript without pattern management.
    ///
    /// **⚠️ Low-level API**: Does not call `begin_message`/`end_message`.
    fn message_bytes_unchecked(&mut self, input: &[u8]) -> &mut Self;

    /// Generate challenge bytes without pattern management.
    ///
    /// **⚠️ Low-level API**: Does not call `begin_challenge`/`end_challenge`.
    fn challenge_bytes_unchecked(&mut self, output: &mut [u8]) -> &mut Self;

    // ========================================================================
    // PROVIDED: High-level operations (automatic pattern management)
    // ========================================================================

    /// Add bytes to transcript with automatic pattern management.
    fn message_bytes(&mut self, label: impl AsRef<str>, input: &[u8]) -> &mut Self {
        self.begin_message::<u8>(&label, Length::Fixed(input.len()));
        self.message_bytes_unchecked(input);
        self.end_message::<u8>(label, Length::Fixed(input.len()));
        self
    }

    /// Generate challenge bytes with automatic pattern management.
    fn challenge_bytes(&mut self, label: impl AsRef<str>, output: &mut [u8]) -> &mut Self {
        self.begin_challenge::<u8>(&label, Length::Fixed(output.len()));
        self.challenge_bytes_unchecked(output);
        self.end_challenge::<u8>(label, Length::Fixed(output.len()));
        self
    }

    /// Absorb public bytes with automatic pattern management.
    fn message_public_bytes_unchecked(&mut self, input: &[u8]) -> &mut Self;

    fn message_public_bytes(&mut self, label: impl AsRef<str>, input: &[u8]) -> &mut Self {
        self.begin_public::<u8>(&label, Length::Fixed(input.len()));
        self.message_public_bytes_unchecked(input); // ✅ Use the public-specific method
        self.end_public::<u8>(label, Length::Fixed(input.len()));
        self
    }

    /// Convenience method for fixed-size challenges.
    ///
    /// # Example
    /// ```ignore
    /// let challenge: [u8; 32] = prover.challenge_bytes_array(Label::new("chal"));
    /// ```
    fn challenge_bytes_array<const N: usize>(&mut self, label: impl AsRef<str>) -> [u8; N] {
        let mut output = [0u8; N];
        self.challenge_bytes(label, &mut output);
        output
    }
}

/// Verifier-specific byte operations.
pub trait VerifierByteTranscript: ByteTranscript {
    /// Read bytes from proof without pattern management.
    ///
    /// **⚠️ Low-level API**: Does not call `begin_message`/`end_message`.
    fn read_message_bytes_unchecked(&mut self, output: &mut [u8]) -> &mut Self;

    /// Read bytes from proof with automatic pattern management.
    fn read_message_bytes(&mut self, label: impl AsRef<str>, output: &mut [u8]) -> &mut Self {
        self.begin_message::<u8>(&label, Length::Fixed(output.len()));
        self.read_message_bytes_unchecked(output);
        self.end_message::<u8>(label, Length::Fixed(output.len()));
        self
    }
}

/// Writing messages to transcript.
pub trait MessageWriter<U: Unit> {
    fn message_units(&mut self, label: impl AsRef<str>, input: &[U]) -> &mut Self;
}

/// Reading messages from proof.
pub trait MessageReader<U: Unit> {
    fn read_message_units(&mut self, label: impl AsRef<str>, output: &mut [U]) -> &mut Self;
}
