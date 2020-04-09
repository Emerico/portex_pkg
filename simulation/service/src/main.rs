use oasis_std::{Address, Context};
//use std::collections::BTreeMap;
//use std::str;

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
}

type Result<T> = std::result::Result<T, String>; 

impl PortexPkg {
	
    pub fn new(ctx: &Context) -> Self {
        Self{
	        //admin: ctx.sender(),
		}
    }
    
    // Obtain master public_key
    fn simpk16(&self) -> PkgPublicKey {
	    let mut x = 0;
        let mut sub_pkg_vec = Vec::new();
		loop {
		    sub_pkg_vec.push(SubPKG::new(x,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone()));
			x = x + 1;
			if x == 16 { break; }
		}
        let sub_pkg_manager = SubPKGManager::new(sub_pkg_vec, (*PUBLIC_KEY_SET).clone());
	    sub_pkg_manager.publish_public_key()	
    }
	
	// Obtain master public_key
    fn simpk32(&self) -> PkgPublicKey {
	    let mut x = 0;
        let mut sub_pkg_vec = Vec::new();
		loop {
		    sub_pkg_vec.push(SubPKG::new(x,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone()));
			x = x + 1;
			if x == 32 { break; }
		}
        let sub_pkg_manager = SubPKGManager::new(sub_pkg_vec, (*PUBLIC_KEY_SET).clone());
	    sub_pkg_manager.publish_public_key()	
    }
	
	// Obtain master public_key
    fn simpk64(&self) -> PkgPublicKey {
	    let mut x = 0;
        let mut sub_pkg_vec = Vec::new();
		loop {
		    sub_pkg_vec.push(SubPKG::new(x,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone()));
			x = x + 1;
			if x == 64 { break; }
		}
        let sub_pkg_manager = SubPKGManager::new(sub_pkg_vec, (*PUBLIC_KEY_SET).clone());
	    sub_pkg_manager.publish_public_key()	
    }
	
	// Obtain master public_key
    fn simpk128(&self) -> PkgPublicKey {
	    let mut x = 0;
        let mut sub_pkg_vec = Vec::new();
		loop {
		    sub_pkg_vec.push(SubPKG::new(x,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone()));
			x = x + 1;
			if x == 128 { break; }
		}
        let sub_pkg_manager = SubPKGManager::new(sub_pkg_vec, (*PUBLIC_KEY_SET).clone());
	    sub_pkg_manager.publish_public_key()	
    }
	
	// Obtain master public_key
    fn simpk256(&self) -> PkgPublicKey {
	    let mut x = 0;
        let mut sub_pkg_vec = Vec::new();
		loop {
		    sub_pkg_vec.push(SubPKG::new(x,(*SECRET_KEY_SET).clone(), (*PUBLIC_KEY_SET).clone()));
			x = x + 1;
			if x == 256 { break; }
		}
        let sub_pkg_manager = SubPKGManager::new(sub_pkg_vec, (*PUBLIC_KEY_SET).clone());
	    sub_pkg_manager.publish_public_key()	
    }

    // Key  Extraction
    pub fn simuk(&self,_ctx: &Context, id: String) ->  Result<()> {
	   //let mut receiver =  Receiver::new((PkgPublicKeySet).clone());
	   let mut receiver =  Receiver::new((*PUBLIC_KEY_SET).clone());
	   let key = receiver.obtain_user_partial_private_key(&SUB_PKG1, id);
	   Ok(())
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
		let portex_pkg = PortexPkg::new(&admin_ctx);
		
		let start_0 = PreciseTime::now();
		portex_pkg.simpk16();
		let end_0 = PreciseTime::now();
		println!("{} seconds for simulating 16 PKGs", start_0.to(end_0));
		
		let start_1 = PreciseTime::now();
		portex_pkg.simpk32();
		let end_1 = PreciseTime::now();
		println!("{} seconds for simulating 32 PKGs", start_1.to(end_1));
		
		let start_2 = PreciseTime::now();
		portex_pkg.simpk64();
		let end_2 = PreciseTime::now();
		println!("{} seconds for simulating 64 PKGs", start_2.to(end_2));
		
		let start_3 = PreciseTime::now();
		portex_pkg.simpk128();
		let end_3 = PreciseTime::now();
		println!("{} seconds for simulating 128 PKGs", start_3.to(end_3));
		
		let start_4 = PreciseTime::now();
		portex_pkg.simpk256();
		let end_4 = PreciseTime::now();
		println!("{} seconds for simulating 256 PKGs", start_4.to(end_4));
		
		//let start_5 = PreciseTime::now();
		//portex_pkg.simuk('test');
		//let end_5 = PreciseTime::now();
		//println!("{} seconds for simulating obtain the user key", start_5.to(end_5));
    }
}