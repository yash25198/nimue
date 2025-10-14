macro_rules! field_traits {
    ($Field:path) => {
        /// Absorb and squeeze field elements to the domain separator.
        pub trait FieldPattern {
            fn message_scalars<F: $Field>(
                &mut self,
                label: $crate::pattern::Label,
                count: usize,
            ) -> Result<&mut Self, $crate::pattern::PatternError>;
            fn challenge_scalars<F: $Field>(
                &mut self,
                label: $crate::pattern::Label,
                count: usize,
            ) -> Result<&mut Self, $crate::pattern::PatternError>;
        }

        /// Interpret verifier messages as uniformly distributed field elements.
        ///
        /// The implementation of this trait **MUST** ensure that the field elements
        /// are uniformly distributed and valid.
        pub trait UnitToField<F: $Field> {
            fn fill_challenge_scalars(
                &mut self,
                label: $crate::pattern::Label,
                output: &mut [F],
            ) -> Result<&mut Self, $crate::pattern::PatternError>;

            fn challenge_scalars<const N: usize>(
                &mut self,
                label: $crate::pattern::Label,
            ) -> Result<[F; N], $crate::pattern::PatternError> {
                let mut output = [F::default(); N];
                self.fill_challenge_scalars(label, &mut output)?;
                Ok(output)
            }
        }

        /// Add field elements as shared public information.
        pub trait CommonFieldToUnit<F: $Field> {
            type Repr;
            fn public_scalars(
                &mut self,
                input: &[F],
            ) -> Result<Self::Repr, $crate::pattern::PatternError>;
        }

        /// Add field elements to the protocol transcript.
        pub trait FieldToUnitSerialize<F: $Field>: CommonFieldToUnit<F> {
            fn add_scalars(
                &mut self,
                input: &[F],
            ) -> Result<&mut Self, $crate::pattern::PatternError>;
        }

        /// Deserialize field elements from the protocol transcript.
        ///
        /// The implementation of this trait **MUST** ensure that the field elements
        /// are correct encodings.
        pub trait FieldToUnitDeserialize<F: $Field>: CommonFieldToUnit<F> {
            fn fill_next_scalars(&mut self, output: &mut [F]) -> $crate::ProofResult<&mut Self>;

            fn next_scalars<const N: usize>(&mut self) -> $crate::ProofResult<[F; N]> {
                let mut output = [F::default(); N];
                self.fill_next_scalars(&mut output)?;
                Ok(output)
            }
        }
    };
}

macro_rules! group_traits {
    ($Group:path, Scalar: $Field:path) => {
        /// Send group elements in the domain separator.
        pub trait GroupPattern {
            fn message_points<G: $Group>(
                &mut self,
                label: $crate::pattern::Label,
                count: usize,
            ) -> Result<&mut Self, $crate::pattern::PatternError>;
        }

        /// Adds a new prover message consisting of an EC element.
        pub trait GroupToUnitSerialize<G: $Group>: CommonGroupToUnit<G> {
            fn add_points(
                &mut self,
                input: &[G],
            ) -> Result<&mut Self, $crate::pattern::PatternError>;
        }

        /// Receive (and deserialize) group elements from the domain separator.
        ///
        /// The implementation of this trait **MUST** ensure that the points decoded are
        /// valid group elements.
        pub trait GroupToUnitDeserialize<G: $Group + Default> {
            /// Deserialize group elements from the protocol transcript into `output`.
            fn fill_next_points(&mut self, output: &mut [G]) -> $crate::ProofResult<&mut Self>;

            fn next_points<const N: usize>(&mut self) -> $crate::ProofResult<[G; N]> {
                let mut output = [G::default(); N];
                self.fill_next_points(&mut output)?;
                Ok(output)
            }
        }

        /// Add group elements to the protocol transcript.
        pub trait CommonGroupToUnit<G: $Group> {
            /// In order to be added to the sponge, elements may be serialize into another format.
            /// This associated type represents the format used, so that other implementation can potentially
            /// re-use the serialized element.
            type Repr;
            fn public_points(
                &mut self,
                label: $crate::pattern::Label,
                input: &[G],
            ) -> Result<Self::Repr, $crate::pattern::PatternError>;
        }
    };
}

#[cfg(any(feature = "zkcrypto-group", feature = "arkworks-algebra"))]
pub(super) use {field_traits, group_traits};
