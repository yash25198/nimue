use spongefish::{
    pattern::{Label, PatternState},
    codecs::bytes::Pattern,
    ProverState,
    VerifierState,
};

fn main() {
    // Test the new API
    println!("Testing new API...");
    
    // 1. Create a pattern using PatternState
    let mut pattern_state = PatternState::new();
    pattern_state.message_bytes(Label::custom("message"), 4);
    pattern_state.challenge_bytes(Label::custom("challenge"), 4);
    
    // 2. Finalize the pattern to get InteractionPattern
    let pattern = pattern_state.finalize().expect("Failed to finalize pattern");
    
    // 6. Test Debug implementation first (before moving pattern)
    println!("Pattern debug output:");
    println!("{:?}", pattern);
    
    // 3. Test the new finalize() method that returns Arc<Self>
    let pattern_arc = pattern.finalize();
    
    // 4. Test the new constructors that accept InteractionPattern directly
    let _prover: ProverState<spongefish::keccak::Keccak, u8, spongefish::DefaultRng> = 
        ProverState::new(pattern_arc.as_ref().clone(), spongefish::DefaultRng::default());
    let _verifier: VerifierState<spongefish::keccak::Keccak, u8> = 
        VerifierState::new(pattern_arc.as_ref().clone(), &[]);
    
    // 5. Test the to_prover_state method
    let pattern2 = {
        let mut pattern_state2 = PatternState::new();
        pattern_state2.message_bytes(Label::custom("test"), 2);
        pattern_state2.finalize().expect("Failed to finalize")
    };
    
    let _prover2 = pattern2.to_prover_state::<spongefish::keccak::Keccak, u8, spongefish::DefaultRng>(spongefish::DefaultRng::default());
    
    println!("All tests passed! ✅");
}
