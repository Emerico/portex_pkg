//#![warn(missing_docs)]
// A SubPKG of IBE.
use portex_pkg::PkgPublicKey;
use portex_pkg::PkgPublicKeySet;
use portex_pkg::SecretKeySet;

use std::collections::BTreeMap;

use crate::sub_pkg::instance::SubPKG;
pub use crate::end_user::receiver::Receiver;

/// SubPKGManager
pub struct SubPKGManager {
    sub_pkg: Vec<SubPKG>,
    pkg_pk_set: PkgPublicKeySet,
}


/// SubPKGManager impl
impl SubPKGManager {
	
	/// new
	pub fn new(sub_pkg: Vec<SubPKG>,pkg_pk_set:PkgPublicKeySet) -> Self {
		SubPKGManager {sub_pkg, pkg_pk_set}
	}
	
	/// setup
	pub fn setup(&self) -> SecretKeySet {
        let mut rng = rand::thread_rng();
		let pkg_sk_set = SecretKeySet::random(1, &mut rng);
		pkg_sk_set
    }
	
	/// publish_public_key
	pub fn publish_public_key(&self) -> PkgPublicKey {
        self.pkg_pk_set.public_key()
    }

    /// get_sub_pkg
    pub fn get_sub_pkg(&mut self, id: usize) -> &mut SubPKG {
        self.sub_pkg
            .get_mut(id)
            .expect("No `SubPKG` exists with that ID")
    }

    // Starts a new meeting of the secret society. Each time the set of actors receive an encrypted
    // message, at least 2 of them (i.e. 1 more than the threshold) must work together to decrypt
    // the ciphertext.

    /// start_decryption_meeting
    pub fn start_decryption_meeting(&self) -> Receiver {
        Receiver {
             pk_set: self.pkg_pk_set.clone(),
             ciphertext: None,
             partial_private_key: BTreeMap::new(),
        }
    }
}
