use crate::{
    codecs::{bytes, bytes_modp, bytes_uniform_modp},
    pattern::{self, Label, Length},
};

/// Generic helper for implementing field patterns
pub fn field_pattern_message<P, F>(
    pattern: &mut P,
    label: Label,
    count: usize,
    modulus_bits: u32,
    extension_degree: usize,
) where
    P: pattern::Pattern + bytes::Pattern,
{
    pattern.begin_message::<F>(label, Length::Fixed(count)).expect("Failed to begin message");
    pattern.message_bytes("bytes", count * extension_degree * bytes_modp(modulus_bits)).expect("Failed to add message bytes");
    pattern.end_message::<F>(label, Length::Fixed(count)).expect("Failed to end message");
}

/// Generic helper for implementing field patterns for challenges
pub fn field_pattern_challenge<P, F>(
    pattern: &mut P,
    label: Label,
    count: usize,
    modulus_bits: u32,
    extension_degree: usize,
) where
    P: pattern::Pattern + bytes::Pattern,
{
    pattern.begin_challenge::<F>(label, Length::Fixed(count)).expect("Failed to begin challenge");
    pattern.challenge_bytes(
        "bytes",
        count * extension_degree * bytes_uniform_modp(modulus_bits),
    ).expect("Failed to add challenge bytes");
    pattern.end_challenge::<F>(label, Length::Fixed(count)).expect("Failed to end challenge");
}

/// Generic helper for implementing group patterns
pub fn group_pattern_message<P, G>(pattern: &mut P, label: Label, count: usize, element_size: usize)
where
    P: pattern::Pattern + bytes::Pattern,
{
    pattern.begin_message::<G>(label, Length::Fixed(count)).expect("Failed to begin message");
    pattern.message_bytes("bytes", count * element_size).expect("Failed to add message bytes");
    pattern.end_message::<G>(label, Length::Fixed(count)).expect("Failed to end message");
}
