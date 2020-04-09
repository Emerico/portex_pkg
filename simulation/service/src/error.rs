//! code borrowed from https://docs.rs/crate/threshold_crypto/0.3.2/source/src/error.rs

use failure::Fail;

/// A crypto error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    /// Not enough signature shares.
    #[fail(display = "Not enough signature shares")]
    NotEnoughShares,
    /// Signature shares contain a duplicated index.
    #[fail(display = "Signature shares contain a duplicated index")]
    DuplicateEntry,
    /// The degree is too high for the coefficients to be indexed by `usize`.
    #[fail(display = "The degree is too high for the coefficients to be indexed by usize.")]
    DegreeTooHigh,
}

/// A crypto result.
pub type Result<T> = ::std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    /// No-op function that compiles only if its argument is `Send + Sync`.
    fn is_send_and_sync<T: Send + Sync>(_: T) {}

    #[test]
    fn errors_are_send_and_sync() {
        is_send_and_sync(Error::NotEnoughShares);
    }
}

/// An error reading a structure from an array of bytes.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum FromBytesError {
    /// Invalid representation
    #[fail(display = "Invalid representation.")]
    Invalid,
}

/// The result of attempting to read a structure from an array of bytes.
pub type FromBytesResult<T> = ::std::result::Result<T, FromBytesError>;