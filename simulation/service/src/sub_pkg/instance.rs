//#![allow(clippy::derive_hash_xor_eq)]
#![warn(missing_docs)]

//#![deny(missing_docs)]
// When using the mocktography, the resulting field elements become wrapped `u32`s, suddenly
// triggering pass-by-reference warnings. They are conditionally disabled for this reason:
#![cfg_attr(
    feature = "use-insecure-test-only-mock-crypto",
    allow(clippy::trivially_copy_pass_by_ref)
)]

use portex_pkg::PkgPublicKeySet;
use portex_pkg::SecretKeySet;
use portex_pkg::Ciphertext;
//use portex_pkg::hash_g1;
pub use pairing;

//#[cfg(feature = "codec-support")]
//#[macro_use]
//mod codec_impl;
//use pairing::{CurveAffine, CurveProjective};

#[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
pub use pairing::bls12_381::{Bls12 as PEngine, Fr, FrRepr, G1Affine, G2Affine, G1, G2};

// A SubPKG of IBE.
use portex_pkg::SecretKeyShare;
use portex_pkg::PkgPublicKeyShare;
//use portex_pkg::PkgPublicKey;
//use serde::{Deserialize, Serialize};

/// SubPKG
#[derive(Clone, Debug)]
pub struct SubPKG {
    pub id: usize,
    pub pkg_sk_share: SecretKeyShare,
    pub pkg_pk_share: PkgPublicKeyShare,
    pub msg_inbox: Option<Ciphertext>,
}

/// SubPKG impl
impl SubPKG {
	/// new 
    pub fn new(id: usize, secret_key_set :SecretKeySet, public_key_set:PkgPublicKeySet) -> Self {
	    //let id: usize = 1;
        let pkg_sk_share = secret_key_set.secret_key_share(id);
	    let pkg_pk_share = public_key_set.public_key_share(id);

        SubPKG {
            id,
            pkg_sk_share,
            pkg_pk_share,
            msg_inbox: None,
        }
    }
    /// get_pkg_pk_share
    pub fn get_pkg_pk_share(&self) -> PkgPublicKeyShare {
	    self.pkg_pk_share
    }
}
