use super::PatternError;

/// Generic result wrapper for stateful pattern operations.
///
/// This type enables ergonomic method chaining while accumulating errors.
/// It holds either:
/// - `Some(T)` and no error: operations continue normally
/// - `Some(T)` with an error: subsequent operations are skipped
/// - `None` with an error: finalized or aborted state
///
/// # Design
///
/// The wrapper pattern separates concerns:
/// - **Inner types** (`*Inner`) contain the actual logic and return `Result<(), PatternError>`
/// - **Wrapper types** (`PatternResult<*Inner>`) provide a builder interface that chains operations
/// - **`finalize()`** unwraps and checks for accumulated errors
///
/// This follows idiomatic Rust patterns similar to `std::io::BufWriter` and other builder types.
///
/// # Example
///
/// ```ignore
/// let pattern = PatternState::new()
///     .message_bytes(Label::from("msg"), 32)
///     .challenge_bytes(Label::from("chal"), 32)
///     .finalize()?; // Check for errors here
/// ```
#[derive(Debug)]
pub struct PatternResult<T> {
    inner: Option<T>,
    error: Option<PatternError>,
}

impl<T> PatternResult<T> {
    /// Create a new `PatternResult` with a successful value.
    ///
    /// This is internal-only. Public API should use type-specific constructors.
    #[must_use]
    pub(crate) const fn from_value(inner: T) -> Self {
        Self {
            inner: Some(inner),
            error: None,
        }
    }

    /// Create a `PatternResult` with an error.
    ///
    /// This is internal-only.
    #[must_use]
    pub(crate) const fn from_error(error: PatternError) -> Self {
        Self {
            inner: None,
            error: Some(error),
        }
    }

    /// Get a mutable reference to the inner value, if no error has occurred.
    ///
    /// Returns `None` if an error has been set or the value has been consumed.
    pub fn inner_mut(&mut self) -> Option<&mut T> {
        if self.error.is_some() {
            None
        } else {
            self.inner.as_mut()
        }
    }

    /// Get a reference to the inner value, if no error has occurred.
    ///
    /// Returns `None` if an error has been set or the value has been consumed.
    pub fn inner(&self) -> Option<&T> {
        if self.error.is_some() {
            None
        } else {
            self.inner.as_ref()
        }
    }

    /// Check if an error has occurred.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn get_error(&self) -> Option<&PatternError> {
        self.error.as_ref()
    }

    /// Finalize and return the inner value or the accumulated error.
    ///
    /// Consumes the `PatternResult` and either:
    /// - Returns `Ok(T)` if no error occurred
    /// - Returns `Err(PatternError)` if an error was accumulated
    /// - Returns `Err(AlreadyFinalized)` if the inner value was already consumed
    ///
    /// This is internal-only. Public API should use type-specific `finalize()` methods.
    pub(crate) fn into_result(self) -> Result<T, PatternError> {
        match (self.inner, self.error) {
            (_, Some(error)) => Err(error),
            (Some(inner), None) => Ok(inner),
            (None, None) => Err(PatternError::AlreadyFinalized),
        }
    }

    /// Set an error on this result.
    ///
    /// The inner value is kept to avoid triggering drop logic that might panic.
    /// It will be properly dropped when `into_result()` is called or when the
    /// PatternResult itself is dropped.
    pub fn set_error(&mut self, error: PatternError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

impl<T: Clone> Clone for PatternResult<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            error: self.error.clone(),
        }
    }
}

impl<T: PartialEq> PartialEq for PatternResult<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.error == other.error
    }
}

impl<T: Eq> Eq for PatternResult<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_result_new() {
        let result = PatternResult::from_value(42);
        assert_eq!(result.inner(), Some(&42));
        assert!(!result.has_error());
        assert_eq!(result.into_result(), Ok(42));
    }

    #[test]
    fn test_pattern_result_with_error() {
        let result: PatternResult<i32> = PatternResult::from_error(PatternError::AlreadyFinalized);
        assert_eq!(result.inner(), None);
        assert!(result.has_error());
        assert!(result.into_result().is_err());
    }

    #[test]
    fn test_pattern_result_set_error() {
        let mut result = PatternResult::from_value(42);
        result.set_error(PatternError::AlreadyFinalized);
        assert_eq!(result.inner(), None);
        assert!(result.has_error());
        assert!(result.into_result().is_err());
    }
}
