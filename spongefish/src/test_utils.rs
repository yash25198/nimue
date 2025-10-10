//! Test utilities for Spongefish tests.
//!
//! This module provides helper functions and utilities to make tests more
//! readable, reduce boilerplate, and improve error handling in tests.

use crate::{
    pattern::{PatternState, PatternError, Label},
    ProverState, VerifierState,
    duplex_sponge::DuplexSpongeInterface,
};
use std::sync::Arc;

/// Result type for test operations that can fail with PatternError
pub type TestResult<T = ()> = Result<T, PatternError>;

/// Helper to create a basic pattern with a single message
pub fn pattern_with_message_bytes(label: &'static str, size: usize) -> TestResult<Arc<crate::pattern::InteractionPattern>> {
    use crate::codecs::bytes::Pattern;
    
    let mut pattern = PatternState::<u8>::new();
    pattern.message_bytes(Label::custom(label), size)?;
    Ok(Arc::new(pattern.finalize()?))
}

/// Helper to create a basic pattern with public units
pub fn pattern_with_public_units(label: &'static str, size: usize) -> TestResult<Arc<crate::pattern::InteractionPattern>> {
    use crate::codecs::unit::Pattern;
    
    let mut pattern = PatternState::<u8>::new();
    pattern.public_units(Label::custom(label), size)?;
    Ok(Arc::new(pattern.finalize()?))
}

/// Helper to create a basic pattern with a challenge
pub fn pattern_with_challenge(label: &'static str, size: usize) -> TestResult<Arc<crate::pattern::InteractionPattern>> {
    use crate::codecs::unit::Pattern;
    
    let mut pattern = PatternState::<u8>::new();
    pattern.challenge_units(Label::custom(label), size)?;
    Ok(Arc::new(pattern.finalize()?))
}

/// Helper to create a basic pattern with a ratchet
pub fn pattern_with_ratchet() -> TestResult<Arc<crate::pattern::InteractionPattern>> {
    use crate::codecs::unit::Pattern;
    
    let mut pattern = PatternState::<u8>::new();
    pattern.ratchet()?;
    Ok(Arc::new(pattern.finalize()?))
}

/// Helper to create a pattern with dynamic hint
pub fn pattern_with_dynamic_hint(label: &'static str) -> TestResult<Arc<crate::pattern::InteractionPattern>> {
    use crate::codecs::unit::Pattern;
    
    let mut pattern = PatternState::<u8>::new();
    pattern.hint_bytes_dynamic(Label::custom(label))?;
    Ok(Arc::new(pattern.finalize()?))
}

/// Helper to create an empty pattern
pub fn empty_pattern() -> TestResult<Arc<crate::pattern::InteractionPattern>> {
    let pattern = PatternState::<u8>::new();
    Ok(Arc::new(pattern.finalize()?))
}

/// Assert that a pattern error matches the expected variant
#[macro_export]
macro_rules! assert_pattern_error {
    ($result:expr, $pattern:pat $(if $guard:expr)?) => {
        match $result {
            Err($pattern) $(if $guard)? => {},
            other => panic!("Expected pattern error, got: {:?}", other),
        }
    };
}

/// Create a prover with default RNG from a pattern
pub fn prover_from_pattern<H: DuplexSpongeInterface<u8>>(
    pattern: Arc<crate::pattern::InteractionPattern>
) -> ProverState<H, u8, rand::rngs::OsRng> {
    ProverState::from(pattern.as_ref())
}

/// Create a verifier from pattern and proof data
pub fn verifier_from_pattern<H: DuplexSpongeInterface<u8>>(
    pattern: Arc<crate::pattern::InteractionPattern>,
    proof: &[u8]
) -> VerifierState<'_, H, u8> {
    VerifierState::new(pattern, proof)
}

/// Run a prover-verifier test with automatic finalization
pub fn run_prover_verifier_test<H, F>(
    pattern_builder: impl FnOnce(&mut PatternState::<u8>) -> TestResult<()>,
    prover_fn: F,
) -> TestResult<()>
where
    H: DuplexSpongeInterface<u8>,
    F: FnOnce(&mut ProverState<H, u8, rand::rngs::OsRng>) -> TestResult<Vec<u8>>,
{
    // Build pattern
    let mut pattern_state = PatternState::<u8>::new();
    pattern_builder(&mut pattern_state)?;
    let pattern = Arc::new(pattern_state.finalize()?);
    
    // Run prover
    let mut prover = prover_from_pattern::<H>(Arc::clone(&pattern));
    let proof = prover_fn(&mut prover)?;
    
    // Verify proof can be created
    let mut verifier = verifier_from_pattern::<H>(pattern, &proof);
    verifier.finalize()?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultHash;
    
    #[test]
    fn test_pattern_helpers() -> TestResult {
        // Test various pattern helpers
        let _p1 = pattern_with_message_bytes("test", 10)?;
        let _p2 = pattern_with_public_units("public", 5)?;
        let _p3 = pattern_with_challenge("challenge", 3)?;
        let _p4 = pattern_with_ratchet()?;
        let _p5 = pattern_with_dynamic_hint("hint")?;
        let _p6 = empty_pattern()?;
        
        Ok(())
    }
    
    #[test]
    fn test_prover_verifier_helpers() -> TestResult {
        use crate::traits::BytesToUnitSerialize;
        
        let pattern = pattern_with_message_bytes("msg", 4)?;
        
        // Create prover and add data
        let mut prover = prover_from_pattern::<DefaultHash>(Arc::clone(&pattern));
        prover.add_bytes(Label::custom("msg"), b"test")?;
        let proof = prover.finalize()?;
        
        // Verify
        let mut verifier = verifier_from_pattern::<DefaultHash>(pattern, &proof);
        let mut out = [0u8; 4];
        verifier.fill_next_bytes(Label::custom("msg"), &mut out)?;
        verifier.finalize()?;
        
        assert_eq!(&out, b"test");
        Ok(())
    }
}


