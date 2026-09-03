use core::fmt;

use classified::ClassifiedError;
use honest_shamir::ShamirError;

/// Why a split, reconstruction or refresh was refused: either the scheme
/// refused the policy or the share set, or a container refused the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The arithmetic layer refused: threshold, share count, indexes, lengths, randomness.
    Shamir(ShamirError),
    /// A container refused: an index of zero for a share, or a rebuilt
    /// secret that does not fit the fixed-size type asked for.
    Classified(ClassifiedError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shamir(e) => e.fmt(f),
            Self::Classified(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Shamir(e) => Some(e),
            Self::Classified(e) => Some(e),
        }
    }
}

impl From<ShamirError> for Error {
    fn from(e: ShamirError) -> Self {
        Self::Shamir(e)
    }
}

impl From<ClassifiedError> for Error {
    fn from(e: ClassifiedError) -> Self {
        Self::Classified(e)
    }
}
