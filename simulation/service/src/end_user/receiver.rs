
use crate::sub_pkg::instance::SubPKG;
use portex_pkg::DecryptionShare;
use portex_pkg::Ciphertext;
use std::collections::BTreeMap;
use portex_pkg::PkgPublicKeySet;
use portex_pkg::GParameter;

#[derive(Clone,Debug)]
pub struct Receiver {
    pub pk_set: PkgPublicKeySet,
    pub ciphertext: Option<Ciphertext>,
    pub partial_private_key: BTreeMap<usize, DecryptionShare>,
}

impl Receiver {
	
	pub fn new(pk_set: PkgPublicKeySet) -> Self {
        Receiver {
             pk_set,
             ciphertext: None,
             partial_private_key: BTreeMap::new(),
        }
    }

   pub fn obtain_user_partial_private_key(&mut self, sub_pkg: &SubPKG, id: String) -> DecryptionShare {
        sub_pkg.pkg_sk_share.obtain_partial_private_key(id).unwrap()
   }

   pub fn decrypt_ciphertext(&self, pk_set: PkgPublicKeySet, partial_private_key_map: &BTreeMap<usize, DecryptionShare>, ciphertext: &Ciphertext) -> Result<Vec<u8>, ()> {
         pk_set
        .decrypt(partial_private_key_map, ciphertext)
        .map_err(|_| ())
   }
	
    // An actor contributes their decryption share to the decryption process.
    pub fn obtain_partial_private_key_with_verification(&mut self, sub_pkg: &mut SubPKG, _g_parameter: &GParameter, id: String) {
        let ciphertext = sub_pkg.msg_inbox.take().unwrap();
        // Check that the actor's ciphertext is the same ciphertext decrypted at the meeting.
        // The first actor to arrive at the decryption meeting sets the meeting's ciphertext.
        if let Some(ref meeting_ciphertext) = self.ciphertext {
            if ciphertext != *meeting_ciphertext {
                return;
            }
        } else {
            self.ciphertext = Some(ciphertext.clone());
        }

        //println!("ciphertext ######################eee {:?}", ciphertext);
        let partial_private_key = sub_pkg.pkg_sk_share.obtain_partial_private_key(id).unwrap();
        
        //let partial_private_key_is_valid = sub_pkg
        //    .pkg_pk_share
        //    .verify_ciphertext(&partial_private_key, &ciphertext, g_parameter);
        //assert!(partial_private_key_is_valid);

        self.partial_private_key.insert(sub_pkg.id, partial_private_key);
    }
    // Tries to decrypt the shared ciphertext using the decryption shares.
    pub fn decrypt_message(&self) -> Result<Vec<u8>, ()> {
        let ciphertext = self.ciphertext.clone().unwrap();
        self.pk_set
            .decrypt(&self.partial_private_key, &ciphertext)
            .map_err(|_| ())
    }
}