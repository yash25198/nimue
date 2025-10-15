use crate::{
    pattern::{Label, PatternError},
    Unit,
};

/// Absorbing and squeezing native elements from the sponge.
pub trait UnitTranscript<U: Unit> {
    fn public_units(&mut self, label: Label, input: &[U]) -> &mut Self;
    fn fill_challenge_units(&mut self, label: Label, output: &mut [U]) -> &mut Self;
}

/// Absorbing bytes from the sponge, without reading or writing them into the protocol transcript.
pub trait CommonUnitToBytes {
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> &mut Self;
}

/// Squeezing bytes from the sponge.
pub trait UnitToBytes {
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> &mut Self;

    fn challenge_bytes<const N: usize>(&mut self, label: Label) -> [u8; N] {
        let mut output = [0u8; N];
        self.fill_challenge_bytes(label, &mut output);
        output
    }
}

/// A trait for absorbing and squeezing bytes from a sponge.
pub trait ByteTranscript: CommonUnitToBytes + UnitToBytes {}

pub trait BytesToUnitDeserialize {
    fn fill_next_bytes(
        &mut self,
        label: Label,
        input: &mut [u8],
    ) -> &mut Self;

    fn next_bytes<const N: usize>(&mut self, label: Label) -> [u8; N] {
        let mut input = [0u8; N];
        self.fill_next_bytes(label, &mut input);
        input
    }
}

pub trait BytesToUnitSerialize {
    fn add_bytes(&mut self, label: Label, input: &[u8]) -> &mut Self;
    fn message_bytes(&mut self, label: Label, input: &[u8]) -> &mut Self;
}

/// Methods for adding bytes to the [`DomainSeparator`](crate::DomainSeparator), properly counting group elements.
pub trait ByteDomainSeparator {
    #[must_use]
    fn add_bytes(self, count: usize, label: &str) -> Self;
    #[must_use]
    fn hint(self, label: &str) -> Self;
    #[must_use]
    fn challenge_bytes(self, count: usize, label: &str) -> Self;
}
