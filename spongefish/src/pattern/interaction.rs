use core::{any::type_name, fmt::Display};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

// ============================================================================
// String Interning for Constant-Time Label Comparison
// ============================================================================

lazy_static::lazy_static! {
    /// Global string interner for constant-time label comparison.
    ///
    /// All label strings are stored here to ensure:
    /// - Identical strings share the same Arc pointer
    /// - Label equality is constant-time (pointer comparison)
    /// - Memory efficiency through deduplication
    static ref LABEL_INTERNER: Mutex<HashSet<Arc<str>>> = Mutex::new(HashSet::new());
}

/// Intern a string in the global cache.
///
/// Returns an `Arc<str>` that is guaranteed to be pointer-equal to any other
/// interned string with the same content.
///
/// # Thread Safety
///
/// This function acquires a `MutexGuard` on the global interner. The guard is
/// automatically released when the function returns.
fn intern_string(s: &str) -> Arc<str> {
    // Acquire MutexGuard - blocks if another thread holds the lock
    let mut interner = LABEL_INTERNER
        .lock()
        .expect("Label interner mutex poisoned");

    // Check if string is already interned
    if let Some(existing) = interner.get(s) {
        // Return existing Arc - ensures pointer equality
        return Arc::clone(existing);
    }

    // String not found - create new Arc and insert into cache
    let arc: Arc<str> = Arc::from(s);
    interner.insert(Arc::clone(&arc));

    // MutexGuard automatically dropped here, releasing the lock
    arc
}

// ============================================================================
// Label
// ============================================================================

/// Label for protocol interactions.
///
/// All labels are interned to ensure:
/// - **Constant-time equality**: All comparisons use pointer equality
/// - **Memory efficiency**: Identical strings share the same allocation
/// - **Side-channel resistance**: No variable-time string comparisons
///
/// # Security
///
/// Label equality is implemented as pure pointer comparison (`Arc::ptr_eq`),
/// making it resistant to timing side-channels. Every comparison executes
/// the exact same instructions regardless of label content. This is critical
/// for cryptographic protocols where timing differences could leak sensitive
/// information.
///
/// # Examples
///
/// ```
/// use spongefish::pattern::{Label, labels};
///
/// // Create labels from strings
/// let commitment = ;
/// let evaluation = ;
///
/// // Use predefined label constants for consistency
/// let bytes_label = ;
/// let protocol_label = ;
///
/// // Same strings are automatically interned (pointer equality)
/// let label1 = ;
/// let label2 = ;
/// assert_eq!(label1, label2); // Constant-time pointer comparison!
///
/// // Dynamic labels in loops
/// for i in 0..10 {
///     let label = );
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Label(Arc<str>);

impl Label {
    /// Create a label from any string-like type.
    ///
    /// The string is automatically interned, ensuring pointer equality
    /// for identical strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use spongefish::pattern::{Label, labels};
    ///
    /// // From string literal
    /// let label1 = Label::new("commitment");
    ///
    /// // From predefined constant
    /// let label2 = Label::new(labels::BYTES);
    ///
    /// // From dynamic string
    /// let label3 = Label::new(format!("round_{}", 5));
    ///
    /// // All labels with same string share the same Arc pointer
    /// let test1 = Label::new("test");
    /// let test2 = Label::new("test");
    /// // test1 and test2 share the same underlying Arc
    /// ```
    #[inline]
    pub fn new(s: impl AsRef<str>) -> Self {
        Self(intern_string(s.as_ref()))
    }

    /// Get the string representation of this label.
    ///
    /// # Examples
    ///
    /// ```
    /// let label = Label::new("commitment");
    /// assert_eq!(label.as_str(), "commitment");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// CRITICAL: Constant-time equality via pointer comparison ONLY
impl PartialEq for Label {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // ALWAYS the same operation - no branches based on content
        // This is the key property for side-channel resistance
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl PartialEq<&str> for Label {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<Label> for &str {
    fn eq(&self, other: &Label) -> bool {
        *self == other.as_str()
    }
}

impl Eq for Label {}

// Hash the pointer for consistency with PartialEq
impl std::hash::Hash for Label {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

// Ordering based on pointer for consistency
impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Label {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0))
    }
}

// Convenient conversions
impl From<&str> for Label {
    #[inline]
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for Label {
    #[inline]
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&String> for Label {
    #[inline]
    fn from(s: &String) -> Self {
        Self::new(s)
    }
}

impl AsRef<str> for Label {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Common Label Constants
// ============================================================================

/// Common label strings used throughout cryptographic protocols.
///
/// These constants provide a standard vocabulary for protocol interactions.
/// Use them with [`Label::new()`] to create labels:
///
/// # Examples
///
/// ```
/// use spongefish::pattern::{Label, labels};
///
/// // Use predefined constants for consistency
/// let bytes_label = ;
/// let protocol_label = ;
///
/// // Or use directly with APIs that accept `impl AsRef<str>`
/// pattern.message_bytes(labels::BYTES, 32);
/// pattern.begin_protocol(labels::PROTOCOL);
/// ```
pub mod labels {
    /// Label for byte sequences: `"bytes"`
    pub const BYTES: &str = "bytes";

    /// Label for unit/opaque data: `"units"`
    pub const UNITS: &str = "units";

    /// Label for base field coefficients: `"base-field-coefficients"`
    pub const BASE_FIELD_COEFFICIENTS: &str = "base-field-coefficients";

    /// Label for base field coefficients in little-endian: `"base-field-coefficients-little-endian"`
    pub const BASE_FIELD_COEFFICIENTS_LITTLE_ENDIAN: &str =
        "base-field-coefficients-little-endian";

    /// Label for serialized group elements: `"serialized-group"`
    pub const SERIALIZED_GROUP: &str = "serialized-group";

    /// Label for public inputs/outputs: `"public"`
    pub const PUBLIC: &str = "public";

    /// Label for state ratcheting operations: `"ratchet"`
    pub const RATCHET: &str = "ratchet";

    /// Label for protocol boundaries: `"protocol"`
    pub const PROTOCOL: &str = "protocol";

    /// Label for hint data: `"hint"`
    pub const HINT: &str = "hint";
}

// ============================================================================
// Interaction
// ============================================================================

/// A single abstract prover-verifier interaction.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Interaction {
    /// Hierarchical nesting of the interactions.
    hierarchy: Hierarchy,
    /// The kind of interaction.
    kind: Kind,
    /// A label identifying the purpose of the value.
    label: Label,
    /// The Rust name of the type of the value.
    ///
    /// We use [`core::any::type_name`] to verify value types instead of [`core::any::TypeID`] since
    /// the latter only supports types with a `'static` lifetime. The downside of `type_name` is
    /// that it is slightly less precise in that it can create more type collisions. But this is
    /// acceptable here as it only serves as an additional check and as debug information.
    type_name: &'static str,
    /// Length of the value.
    length: Length,
}

// ============================================================================
// Supporting Enums
// ============================================================================

/// Kinds of prover-verifier interactions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Kind {
    /// A protocol containing mixed interactions.
    Protocol,
    /// A public message prover and verifier agree on.
    Public,
    /// A message sent in-band from prover to verifier.
    Message,
    /// A hint sent out-of-band from prover to verifier.
    Hint,
    /// A challenge issued by the verifier.
    Challenge,
}

/// Kinds of prover-verifier interactions
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Hierarchy {
    /// A single interaction.
    Atomic,
    /// Start of a sub-protocol.
    Begin,
    /// End of a sub-protocol.
    End,
}

/// Length of values involved in interactions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Length {
    /// No length information.
    None,
    /// A single value.
    Scalar,
    /// A fixed number of values.
    Fixed(usize),
    /// A dynamic number of values.
    Dynamic,
}

impl Interaction {
    #[must_use]
    pub fn new<T: ?Sized>(hierarchy: Hierarchy, kind: Kind, label: impl AsRef<str>, length: Length) -> Self {
        let type_name = type_name::<T>();
        Self {
            hierarchy,
            kind,
            label: Label::new(label),
            type_name,
            length,
        }
    }

    #[must_use]
    pub const fn hierarchy(&self) -> Hierarchy {
        self.hierarchy
    }

    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Returns the label of this interaction.
    #[must_use]
    pub const fn label(&self) -> &Label {
        &self.label
    }

    /// Get the length information of this interaction.
    #[must_use]
    pub const fn length(&self) -> Length {
        self.length
    }

    /// Get the type name of this interaction.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// Returns `true` if this is a `Hierarchy::End` that closes the provided
    /// `Hierarchy::Begin`.
    #[must_use]
    pub(super) fn closes(&self, other: &Self) -> bool {
        self.hierarchy == Hierarchy::End
            && other.hierarchy == Hierarchy::Begin
            && self.kind == other.kind
            && self.label == other.label
            && self.type_name == other.type_name
            && self.length == other.length
    }
}

impl Display for Interaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            // Domain separator mode: stable unambiguous format.
            write!(f, "{} {}", self.hierarchy, self.kind)?;
            // Length prefixed strings for labels to disambiguate
            let label_str = self.label.as_str();
            write!(f, " {} {}", label_str.len(), label_str)?;
            write!(f, " {}", self.length)
            // Leave out type names for domain separators.
        } else {
            write!(
                f,
                "{} {} {} {} {}",
                self.hierarchy,
                self.kind,
                self.label.as_str(),
                self.length,
                self.type_name,
            )
        }
    }
}


impl Display for Hierarchy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Atomic => write!(f, "Atomic"),
            Self::Begin => write!(f, "Begin"),
            Self::End => write!(f, "End"),
        }
    }
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol => write!(f, "Protocol"),
            Self::Public => write!(f, "Public"),
            Self::Message => write!(f, "Message"),
            Self::Hint => write!(f, "Hint"),
            Self::Challenge => write!(f, "Challenge"),
        }
    }
}

impl Display for Length {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Scalar => write!(f, "Scalar"),
            Self::Fixed(size) => write!(f, "Fixed({size})"),
            Self::Dynamic => write!(f, "Dynamic"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sizes() {
        // Label should be size of Arc (16 bytes on 64-bit)
        assert_eq!(std::mem::size_of::<Label>(), std::mem::size_of::<Arc<str>>());
        assert!(std::mem::size_of::<Label>() <= 16);

        // Interaction should remain compact
        assert!(std::mem::size_of::<Interaction>() < 80);
    }

    #[test]
    fn test_domain_separator() {
        let interaction = Interaction::new::<Vec<f64>>(
            Hierarchy::Atomic,
            Kind::Message,
            Label::new("test-message"),
            Length::Scalar,
        );
        let result = format!("{interaction:#}");
        let expected = "Atomic Message 12 test-message Scalar";
        assert_eq!(result, expected);
    }
}
