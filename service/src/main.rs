use oasis_std::{Address, Context};
use std::collections::BTreeMap;
use std::str;

use portex_pkg::GParameter;
use portex_pkg::SecretKeySet;
use portex_pkg::PkgPublicKeySet;
use portex_pkg::PkgPublicKey;
use portex_pkg::DecryptionShare;
use portex_pkg::Ciphertext;

//use serde_json::Result;

extern crate time;
use time::PreciseTime;

#[macro_use]
extern crate lazy_static;

//use map_vec::{map::Entry, Map};

mod sub_pkg;
pub use crate::sub_pkg::instance::SubPKG;
pub use crate::sub_pkg::manager::SubPKGManager;

mod parameter;
pub use crate::parameter::setting::SystemSetting;


mod end_user;
pub use crate::end_user::receiver::Receiver;
pub use crate::end_user::sender::Sender;

lazy_static! {
	
	static ref G_PARAMETER: GParameter = {
	   GParameter::new()
    };

    static ref SECRET_KEY_SET: SecretKeySet = {
	   SystemSetting::new(*G_PARAMETER).setup_secret_key_set()
    };

    static ref PUBLIC_KEY_SET: PkgPublicKeySet = {
	   SystemSetting::new(*G_PARAMETER).setup_public_key_set((*SECRET_KEY_SET).clone())
    };

    static ref SUB_PKG1: SubPKG = {
       SubPKG::new(1,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone())
    };
    
    static ref SUB_PKG2: SubPKG = {
       SubPKG::new(2,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone())
    };
   
    static ref SUB_PKG3: SubPKG = {
       SubPKG::new(3,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone())
    };
}

#[derive(oasis_std::Service)]
struct PortexPkg{
	//admin: Address,
	pkg_mpk: PkgPublicKey,
}

impl PortexPkg {
	
    pub fn new(_ctx: &Context) -> Self {
	
        let mut sub_pkg_vec = Vec::new();
        sub_pkg_vec.push((*SUB_PKG1).clone());
        sub_pkg_vec.push((*SUB_PKG2).clone());
        sub_pkg_vec.push((*SUB_PKG3).clone());
        
        //let g_parameter: GParameter = GParameter::new();
        SubPKG::new(1,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone());
    
        let sub_pkg_manager = SubPKGManager::new(sub_pkg_vec, (*PUBLIC_KEY_SET).clone());
        // Obtain master public_key of all the sub PKGs
		let pkg_mpk = sub_pkg_manager.publish_public_key(); 
		
        Self{
	        //admin: ctx.sender(),
			pkg_mpk,
		}
    }
    
    
    /// Obtain master public_key of all the sub PKGs
    fn get_pkg_mpk(&self) -> PkgPublicKey {
        self.pkg_mpk
    }

    // Key  Extraction [OnLine] ***************** [start] *****************************
    fn get_user_partial_private_key_from_sub_pkg1(&self, mut receiver: Receiver, id: String) ->  DecryptionShare {
       receiver.obtain_user_partial_private_key(&SUB_PKG1, id)
    }
    
    fn get_user_partial_private_key_from_sub_pkg2(&self, mut receiver: Receiver, id: String) ->   DecryptionShare {
       receiver.obtain_user_partial_private_key(&SUB_PKG2, id)
    }

    fn get_user_partial_private_key_from_sub_pkg3(&self, mut receiver: Receiver, id: String) ->  DecryptionShare {
       receiver.obtain_user_partial_private_key(&SUB_PKG3, id)
    }

    // Check ***************** [start] *****************************	 
    fn verify_ciphertext(&self, ciphertext: &Ciphertext) ->  bool {
       SUB_PKG1
           .pkg_pk_share
           .verify_ciphertext(&ciphertext, &G_PARAMETER)
    }

    fn check_partial_private_key_from_sub_pkg1(&self, id: String, partial_private_key: &DecryptionShare) ->  bool {
       SUB_PKG1
           .pkg_pk_share
           .verify_partial_private_key(id,partial_private_key, &G_PARAMETER)
    }

    fn check_partial_private_key_from_sub_pkg2(&self, id: String, partial_private_key: &DecryptionShare) ->  bool {
       SUB_PKG2
           .pkg_pk_share
           .verify_partial_private_key(id,partial_private_key, &G_PARAMETER)
    }

    fn check_partial_private_key_from_sub_pkg3(&self, id: String, partial_private_key: &DecryptionShare) ->  bool {
       SUB_PKG3
           .pkg_pk_share
           .verify_partial_private_key(id,partial_private_key, &G_PARAMETER)
    }
}

fn main() {
    oasis_std::service!(PortexPkg);
}

//#[cfg_attr(feature = "wasm-bindgen", wasm_bindgen_test)]
#[cfg(test)]
mod tests {
    extern crate oasis_test;

    use super::*;
    //use oasis_std::{Address, Context};

    /// Creates a new account and a `Context` with the new account as the sender.
    fn create_account_ctx() -> (Address, Context) {
        let addr = oasis_test::create_account(0 /* initial balance */);
        let ctx = Context::default().with_sender(addr).with_gas(100_000);
        (addr, ctx)
    }

    #[test]
    fn test() {
	    let (_admin, admin_ctx) = create_account_ctx();
        
        
        // PKG Setup ***************** [start] *****************************
        // Prepare the group parameters	
		let start_0 = PreciseTime::now();
		let portex_pkg = PortexPkg::new(&admin_ctx);
        let pkg_mpk = portex_pkg.get_pkg_mpk();
		let end_0 = PreciseTime::now();
		println!("{} seconds for preparing the group parameters", start_0.to(end_0));
        //println!("pkg_mpk {:?}", pkg_mpk);

        // Key  Extraction [OnLine] ***************** [start] *****************************
		let start_1 = PreciseTime::now();
        let id = "bob".to_string(); 
        let receiver =  Receiver::new((*PUBLIC_KEY_SET).clone());
        let partial_private_key_1 = portex_pkg.get_user_partial_private_key_from_sub_pkg1(receiver.clone(),id.clone());
        let partial_private_key_2 = portex_pkg.get_user_partial_private_key_from_sub_pkg2(receiver.clone(),id.clone());
        let partial_private_key_3 = portex_pkg.get_user_partial_private_key_from_sub_pkg3(receiver.clone(),id.clone());
		
	    let end_1 = PreciseTime::now();
		println!("{} seconds for key extraction", start_1.to(end_1));
		
        //println!("partial_private_key_1 {:?}", partial_private_key_1);
    
        // Encryption [OffLine] ***************** [start] *****************************	
        let start_2 = PreciseTime::now();		
	    let msg = b"this is a test";
        let sender =  Sender::new(pkg_mpk);
        let ciphertext = sender.encrypt_new(msg,id.clone());
		
		let end_2 = PreciseTime::now();
		println!("{} seconds for encryption", start_2.to(end_2));
		
	    //let ciphertext = pkg_mpk.encrypt_new(msg,id.clone());

        // Check ***************** [start] *****************************	 
	    // check the ciphertext
		let start_3 = PreciseTime::now();
		
	    let check_res_0 =  portex_pkg.verify_ciphertext(&ciphertext);
	    assert!(check_res_0);

        let mut partial_private_key_map = BTreeMap::new();

	    let check_res_1 = portex_pkg.check_partial_private_key_from_sub_pkg1(id.clone(), &partial_private_key_1);
	    assert!(check_res_1);
        partial_private_key_map.insert(1, partial_private_key_1.clone());
	
	    let check_res_2 = portex_pkg.check_partial_private_key_from_sub_pkg2(id.clone(), &partial_private_key_2);
	    assert!(check_res_2);
        partial_private_key_map.insert(2, partial_private_key_2.clone());

        let check_res_3 = portex_pkg.check_partial_private_key_from_sub_pkg3(id.clone(), &partial_private_key_3);
	    assert!(check_res_3);
        partial_private_key_map.insert(3, partial_private_key_3.clone());
		
		let end_3 = PreciseTime::now();
		println!("{} seconds for checking the ciphertext", start_3.to(end_3));

        // Decryption ***************** [start] *****************************	 
		
		let start_4 = PreciseTime::now();
		
		let res = receiver.decrypt_ciphertext((*PUBLIC_KEY_SET).clone(), &partial_private_key_map, &ciphertext).unwrap();
		let decryption_message = str::from_utf8(&res).unwrap();
		println!("decryption_message {:?}", decryption_message);
		
		let end_4 = PreciseTime::now();
		println!("{} seconds for decryption", start_4.to(end_4));

        //println!("{}", portex_pkg.say_hello(&admin_ctx));
        
    }
}