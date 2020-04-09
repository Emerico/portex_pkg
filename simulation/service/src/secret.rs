//! Utilities for working with secret values. This module includes functionality for overwriting
//! memory with zeros.
// Code borrowed from https://docs.rs/crate/threshold_crypto/0.3.2/source/src/secret.rs


use zeroize::Zeroize;

use crate::{Fr, FrRepr};

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr: &mut Fr) {
    let fr_repr = unsafe { &mut *(fr as *mut Fr as *mut FrRepr) };
    fr_repr.0.zeroize();
}