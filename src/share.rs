use core::fmt;

use classified::{ClassifiedBuffer, ClassifiedExposure, Expose};
use honest_shamir::ShamirError;

use crate::Error;

/// One share, in a container.
///
/// The index is public (it is the x coordinate, and holders need to know
/// which share they hold); the bytes live in a [`ClassifiedBuffer`] bounded
/// to their own length. Like every wrapped container it has no `Clone` and
/// no `Deref`: the bytes are reached through [`expose`](Self::expose), and
/// [`reconstruct`](crate::reconstruct) takes shares by reference.
pub struct ClassifiedShare {
    index: u8,
    bytes: ClassifiedBuffer,
}

impl ClassifiedShare {
    /// Wrap bytes already in a container. The index must be non-zero.
    pub fn new(index: u8, bytes: ClassifiedBuffer) -> Result<Self, Error> {
        if index == 0 {
            return Err(ShamirError::ZeroIndex.into());
        }
        Ok(Self { index, bytes })
    }

    /// Copy a share received from elsewhere into a container of its own length.
    pub fn from_slice(index: u8, bytes: &[u8]) -> Result<Self, Error> {
        if index == 0 {
            return Err(ShamirError::ZeroIndex.into());
        }
        Ok(Self { index, bytes: ClassifiedBuffer::try_from_slice(bytes, bytes.len())? })
    }

    /// The x coordinate, `1..=255`.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// How many bytes the share holds, which is the length of the secret.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false: a share is never built empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Lend the bytes to `op` for the duration of the call.
    pub fn expose<R>(&self, op: impl for<'a> FnOnce(ClassifiedExposure<'a>) -> R) -> R {
        self.bytes.expose(op)
    }

    /// Constant-time equality of index and bytes.
    pub fn ct_eq(&self, other: &Self) -> bool {
        // the index is public, so comparing it first leaks nothing
        self.index == other.index && self.bytes.ct_eq(&other.bytes)
    }

    /// Take the container back out.
    pub fn into_buffer(self) -> ClassifiedBuffer {
        self.bytes
    }
}

impl Expose for ClassifiedShare {
    type View<'a> = ClassifiedExposure<'a>;

    fn expose<'s, R>(&'s self, op: impl FnOnce(Self::View<'s>) -> R) -> R {
        Expose::expose(&self.bytes, op)
    }
}

impl fmt::Debug for ClassifiedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClassifiedShare")
            .field("index", &self.index)
            .field("len", &self.bytes.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for ClassifiedShare {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for ClassifiedShare {}
