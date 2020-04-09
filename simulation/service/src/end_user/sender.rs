
//use crate::sub_pkg::instance::SubPKG;
//use portex_pkg::DecryptionShare;
use portex_pkg::Ciphertext;
//use std::collections::BTreeMap;
use portex_pkg:: PkgPublicKey;

#[derive(Clone,Debug)]
pub struct Sender {
    pub ppk: PkgPublicKey,
}

impl Sender {
	
	pub fn new(ppk: PkgPublicKey) -> Self {
        Sender {
             ppk
        }
    }
 
   pub fn encrypt_new<M: AsRef<[u8]>>(&self, msg: M, id: String) -> Ciphertext {
	   self.ppk.encrypt_new(msg, id)
   }
}