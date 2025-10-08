use crate::{pattern::{Kind, Label, PatternError}, Unit};

/// Absorbing and squeezing native elements from the sponge.
pub trait UnitTranscript<U: Unit> {
    fn public_units(&mut self, label: Label, input: &[U]) -> Result<&mut Self, PatternError>;
    fn fill_challenge_units(&mut self, label: Label, output: &mut [U]) -> Result<&mut Self, PatternError>;
}

/// Absorbing bytes from the sponge, without reading or writing them into the protocol transcript.
pub trait CommonUnitToBytes {
    fn public_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError>;
}

/// Squeezing bytes from the sponge.
pub trait UnitToBytes {
    fn fill_challenge_bytes(&mut self, label: Label, output: &mut [u8]) -> Result<&mut Self, PatternError>;

    fn challenge_bytes<const N: usize>(&mut self, label: Label) -> Result<[u8; N], PatternError> {
        let mut output = [0u8; N];
        self.fill_challenge_bytes(label, &mut output)?;
        Ok(output)
    }
}

/// A trait for absorbing and squeezing bytes from a sponge.
pub trait ByteTranscript: CommonUnitToBytes + UnitToBytes {}

pub trait BytesToUnitDeserialize {
    fn fill_next_bytes(&mut self, label: Label, input: &mut [u8]) -> Result<&mut Self, std::io::Error>;

    fn next_bytes<const N: usize>(&mut self, label: Label) -> Result<[u8; N], std::io::Error> {
        let mut input = [0u8; N];
        self.fill_next_bytes(label, &mut input)?;
        Ok(input)
    }
}

pub trait BytesToUnitSerialize {
    fn add_bytes(&mut self, label: Label, input: &[u8]) -> Result<&mut Self, PatternError>;
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
