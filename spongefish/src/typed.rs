use core::marker::PhantomData;
use std::sync::Arc;

use rand::{CryptoRng, RngCore};

use crate::{
    duplex_sponge::{DuplexSpongeInterface, Unit},
    pattern::InteractionPattern,
    DefaultHash, DefaultRng, ProverState, VerifierState,
};

/// Zero-sized marker binding both sides to the same protocol IV at the type level.
/// We encode the 256-bit IV as two `u128` const generics to stay within stable Rust limits.
pub struct Protocol<const IV0: u128, const IV1: u128>;

/// Initial state marker for typestated transcripts.
pub struct S0;

/// A typestated prover wrapper enforcing compile-time sequencing.
pub struct Prover<P, S, H = DefaultHash, U = u8, R = DefaultRng>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    inner: ProverState<H, U, R>,
    _p: PhantomData<P>,
    _s: PhantomData<S>,
}

impl<const IV0: u128, const IV1: u128, S, H, U, R> Prover<Protocol<IV0, IV1>, S, H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Access the underlying prover state immutably.
    pub fn inner(&self) -> &ProverState<H, U, R> {
        &self.inner
    }

    /// Access the underlying prover state mutably.
    pub fn inner_mut(&mut self) -> &mut ProverState<H, U, R> {
        &mut self.inner
    }
}

impl<const IV0: u128, const IV1: u128, H, U, R> Prover<Protocol<IV0, IV1>, S0, H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Create a new typestated prover bound to the compile-time protocol IV.
    pub fn new(pattern: InteractionPattern, csrng: R) -> Self {
        let iv = pattern.domain_separator();
        let iv0 = u128::from_le_bytes(iv[0..16].try_into().unwrap());
        let iv1 = u128::from_le_bytes(iv[16..32].try_into().unwrap());
        debug_assert!(iv0 == IV0 && iv1 == IV1, "Pattern IV mismatch ");
        Self {
            inner: ProverState::new(pattern, csrng),
            _p: PhantomData,
            _s: PhantomData,
        }
    }
}

impl<P, S, H, U, R> From<ProverState<H, U, R>> for Prover<P, S, H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn from(inner: ProverState<H, U, R>) -> Self {
        Self {
            inner,
            _p: PhantomData,
            _s: PhantomData,
        }
    }
}

// Add this method to the Prover impl block (around line 85)
impl<P, S, H, U, R> Prover<P, S, H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Convenience to expose the current NARG string bytes produced by the prover so far.
    pub fn narg_bytes(&self) -> &[u8] {
        self.inner.narg_string()
    }

    /// Transition to a new typestate without changing runtime state.
    pub fn transition<SN>(self) -> Prover<P, SN, H, U, R> {
        Prover {
            inner: self.inner,
            _p: PhantomData,
            _s: PhantomData,
        }
    }

    /// Consume the prover and finalize, returning the proof bytes
    pub fn finalize(self) -> Vec<u8> {
        self.inner.finalize()
    }

    /// Access the underlying RNG for generating randomness
    pub fn rng(&mut self) -> &mut (impl rand::CryptoRng + rand::RngCore) {
        self.inner.rng()
    }
}

/// A typestated verifier wrapper enforcing compile-time sequencing.
pub struct Verifier<'a, P, S, H = DefaultHash, U = u8>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    inner: VerifierState<'a, H, U>,
    _p: PhantomData<P>,
    _s: PhantomData<S>,
}

impl<'a, const IV0: u128, const IV1: u128, S, H, U> Verifier<'a, Protocol<IV0, IV1>, S, H, U>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    /// Access the underlying verifier state immutably.
    pub fn inner(&self) -> &VerifierState<'a, H, U> {
        &self.inner
    }

    /// Access the underlying verifier state mutably.
    pub fn inner_mut(&mut self) -> &mut VerifierState<'a, H, U> {
        &mut self.inner
    }
}

impl<'a, const IV0: u128, const IV1: u128, H, U> Verifier<'a, Protocol<IV0, IV1>, S0, H, U>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    /// Create a new typestated verifier bound to the compile-time protocol IV.
    pub fn new(pattern: Arc<InteractionPattern>, narg_string: &'a [u8]) -> Self {
        let iv = pattern.domain_separator();
        let iv0 = u128::from_le_bytes(iv[0..16].try_into().unwrap());
        let iv1 = u128::from_le_bytes(iv[16..32].try_into().unwrap());
        debug_assert!(iv0 == IV0 && iv1 == IV1, "Pattern IV mismatch");
        Self {
            inner: VerifierState::new(pattern, narg_string),
            _p: PhantomData,
            _s: PhantomData,
        }
    }
}

impl<'a, P, S, H, U> From<VerifierState<'a, H, U>> for Verifier<'a, P, S, H, U>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    fn from(inner: VerifierState<'a, H, U>) -> Self {
        Self {
            inner,
            _p: PhantomData,
            _s: PhantomData,
        }
    }
}

impl<'a, P, S, H, U> Verifier<'a, P, S, H, U>
where
    H: DuplexSpongeInterface<U>,
    U: Unit,
{
    /// Transition to a new typestate without changing runtime state.
    pub fn transition<SN>(self) -> Verifier<'a, P, SN, H, U> {
        Verifier {
            inner: self.inner,
            _p: PhantomData,
            _s: PhantomData,
        }
    }

    /// Finalize the verifier
    pub fn finalize(self) -> crate::ProofResult<()> {
        self.inner
            .finalize()
            .map_err(|e| crate::ProofError::PatternError(e.to_string()))
    }
}

/// Macro to generate a simple linear protocol with typestated steps.
#[macro_export]
macro_rules! define_protocol {
    (
        $(#[$meta:meta])* $vis:vis protocol $Name:ident IV0 = $iv0:expr; IV1 = $iv1:expr;
        steps { $( $step_kind:ident $method:ident $label:literal ; )* }
    ) => {
        $(#[$meta])* $vis type $Name = $crate::typed::Protocol<{ $iv0 }, { $iv1 }>;

        // Generate per-protocol state markers S1..Sn
        $(
            #[allow(non_camel_case_types)]
            pub struct $method;
        )*

        // Starting state alias for readability in user code
        pub type Start = $crate::typed::S0;

        // Generate namespaced free functions per step for Prover/Verifier to avoid value name collisions
        pub mod prover_steps {
            use super::*;
            $crate::define_protocol!(@impl_steps_prover_fns [$Name] [$crate::typed::S0] [] $( ($step_kind $method $label) )*);
        }
        pub mod verifier_steps {
            use super::*;
            $crate::define_protocol!(@impl_steps_verifier_fns [$Name] [$crate::typed::S0] [] $( ($step_kind $method $label) )*);
        }
    };

    // Recursive: generate free functions for Prover
    (@impl_steps_prover_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*]) => { $($acc)* };

    (@impl_steps_prover_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (message_units $method:ident $label:literal) $($tail:tt)*) => {
        pub fn $method<H, U, R>(mut state: $crate::typed::Prover<$Name, $PrevState, H, U, R>, input: &[U]) -> $crate::typed::Prover<$Name, $method, H, U, R>
        where
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            R: rand::RngCore + rand::CryptoRng,
        {
            use $crate::pattern::Label;
            state.inner_mut().add_units(Label::Units, input);
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_prover_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_prover_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (challenge_units $method:ident $label:literal) $($tail:tt)*) => {
        pub fn $method<H, U, R>(mut state: $crate::typed::Prover<$Name, $PrevState, H, U, R>, output: &mut [U]) -> $crate::typed::Prover<$Name, $method, H, U, R>
        where
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            R: rand::RngCore + rand::CryptoRng,
        {
            use $crate::{pattern::Label, UnitTranscript};
            state.inner_mut().fill_challenge_units(Label::Units, output).expect("Failed to fill challenge units");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_prover_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_prover_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (ratchet $method:ident $label:literal) $($tail:tt)*) => {
        pub fn $method<H, U, R>(mut state: $crate::typed::Prover<$Name, $PrevState, H, U, R>) -> $crate::typed::Prover<$Name, $method, H, U, R>
        where
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            R: rand::RngCore + rand::CryptoRng,
        {
            state.inner_mut().ratchet().expect("Failed to ratchet");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_prover_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_prover_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (message_points $method:ident $label:literal) $($tail:tt)*) => {
        #[cfg(feature = "arkworks-algebra")]
        pub fn $method<G, H, U, R>(mut state: $crate::typed::Prover<$Name, $PrevState, H, U, R>, input: &[G]) -> $crate::typed::Prover<$Name, $method, H, U, R>
        where
            G: ark_ec::CurveGroup,
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            R: rand::RngCore + rand::CryptoRng,
            $crate::ProverState<H, U, R>: $crate::codecs::arkworks_algebra::ProverGroupMessageExt<G>,
        {
            use $crate::codecs::arkworks_algebra::ProverGroupMessageExt;
            use $crate::pattern::Label;
            state.inner_mut().message_points(Label::custom($label), input).expect("Failed to add points");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_prover_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_prover_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (challenge_scalars $method:ident $label:literal) $($tail:tt)*) => {
        #[cfg(feature = "arkworks-algebra")]
        pub fn $method<F, H, U, R>(mut state: $crate::typed::Prover<$Name, $PrevState, H, U, R>, output: &mut [F]) -> $crate::typed::Prover<$Name, $method, H, U, R>
        where
            F: ark_ff::Field,
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            R: rand::RngCore + rand::CryptoRng,
            $crate::ProverState<H, U, R>: $crate::UnitTranscript<U> + $crate::codecs::arkworks_algebra::UnitToField<F>,
        {
            use $crate::{pattern::Label, codecs::arkworks_algebra::UnitToField};
            state.inner_mut().fill_challenge_scalars(Label::custom($label), output).expect("Failed to fill challenge scalars");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_prover_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_prover_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (message_scalars $method:ident $label:literal) $($tail:tt)*) => {
        #[cfg(feature = "arkworks-algebra")]
        pub fn $method<F, H, U, R>(mut state: $crate::typed::Prover<$Name, $PrevState, H, U, R>, input: &[F]) -> $crate::typed::Prover<$Name, $method, H, U, R>
        where
            F: ark_ff::Field,
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            R: rand::RngCore + rand::CryptoRng,
            $crate::ProverState<H, U, R>: $crate::codecs::arkworks_algebra::ProverFieldMessageExt<F>,
        {
            use $crate::codecs::arkworks_algebra::ProverFieldMessageExt;
            use $crate::pattern::Label;
            state.inner_mut().message_scalars(Label::custom($label), input).expect("Failed to add scalars");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_prover_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    // Recursive: generate free functions for Verifier
    (@impl_steps_verifier_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*]) => { $($acc)* };

    (@impl_steps_verifier_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (message_units $method:ident $label:literal) $($tail:tt)*) => {
        pub fn $method<'a, H, U>(mut state: $crate::typed::Verifier<'a, $Name, $PrevState, H, U>, output: &mut [U]) -> $crate::typed::Verifier<'a, $Name, $method, H, U>
        where
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
        {
            use $crate::pattern::Label;
            let _ = state.inner_mut().fill_next_units(Label::Units, output);
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_verifier_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_verifier_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (challenge_units $method:ident $label:literal) $($tail:tt)*) => {
        pub fn $method<'a, H, U>(mut state: $crate::typed::Verifier<'a, $Name, $PrevState, H, U>, output: &mut [U]) -> $crate::typed::Verifier<'a, $Name, $method, H, U>
        where
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
        {
            use $crate::{pattern::Label, UnitTranscript};
            state.inner_mut().fill_challenge_units(Label::Units, output).expect("Failed to fill challenge units");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_verifier_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_verifier_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (ratchet $method:ident $label:literal) $($tail:tt)*) => {
        pub fn $method<'a, H, U>(mut state: $crate::typed::Verifier<'a, $Name, $PrevState, H, U>) -> $crate::typed::Verifier<'a, $Name, $method, H, U>
        where
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
        {
            state.inner_mut().ratchet().expect("Failed to ratchet");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_verifier_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_verifier_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (message_points $method:ident $label:literal) $($tail:tt)*) => {
        #[cfg(feature = "arkworks-algebra")]
        pub fn $method<'a, G, H, U>(mut state: $crate::typed::Verifier<'a, $Name, $PrevState, H, U>, output: &mut [G]) -> $crate::typed::Verifier<'a, $Name, $method, H, U>
        where
            G: ark_ec::CurveGroup,
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            $crate::VerifierState<'a, H, U>: $crate::codecs::arkworks_algebra::VerifierGroupMessageExt<G>,
        {
            use $crate::codecs::arkworks_algebra::VerifierGroupMessageExt;
            use $crate::pattern::Label;
            let _ = state.inner_mut().fill_message_points(Label::custom($label), output);
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_verifier_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_verifier_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (challenge_scalars $method:ident $label:literal) $($tail:tt)*) => {
        #[cfg(feature = "arkworks-algebra")]
        pub fn $method<'a, F, H, U>(mut state: $crate::typed::Verifier<'a, $Name, $PrevState, H, U>, output: &mut [F]) -> $crate::typed::Verifier<'a, $Name, $method, H, U>
        where
            F: ark_ff::Field,
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            $crate::VerifierState<'a, H, U>: $crate::UnitTranscript<U> + $crate::codecs::arkworks_algebra::UnitToField<F>,
        {
            use $crate::{pattern::Label, codecs::arkworks_algebra::UnitToField};
            state.inner_mut().fill_challenge_scalars(Label::custom($label), output).expect("Failed to fill challenge scalars");
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_verifier_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };

    (@impl_steps_verifier_fns [$Name:ident] [$PrevState:ty] [$($acc:tt)*] (message_scalars $method:ident $label:literal) $($tail:tt)*) => {
        #[cfg(feature = "arkworks-algebra")]
        pub fn $method<'a, F, H, U>(mut state: $crate::typed::Verifier<'a, $Name, $PrevState, H, U>, output: &mut [F]) -> $crate::typed::Verifier<'a, $Name, $method, H, U>
        where
            F: ark_ff::Field,
            U: $crate::duplex_sponge::Unit,
            H: $crate::duplex_sponge::DuplexSpongeInterface<U>,
            $crate::VerifierState<'a, H, U>: $crate::codecs::arkworks_algebra::VerifierFieldMessageExt<F>,
        {
            use $crate::codecs::arkworks_algebra::VerifierFieldMessageExt;
            use $crate::pattern::Label;
            let _ = state.inner_mut().fill_message_scalars(Label::custom($label), output);
            state.transition::<$method>()
        }
        $crate::define_protocol!(@impl_steps_verifier_fns [$Name] [$method] [$($acc)*] $($tail)*);
    };
}
