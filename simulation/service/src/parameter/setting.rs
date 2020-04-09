use portex_pkg::SecretKeySet;
use portex_pkg::PkgPublicKeySet;
use portex_pkg::GParameter;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SystemSetting {
	g_parameter: GParameter,
}

impl SystemSetting {
	
	pub fn new(g_parameter: GParameter) -> Self {
		SystemSetting {g_parameter}
	}
	
	pub fn get_g_parameter(&self) -> GParameter {
		self.g_parameter
	}
	
	pub fn setup_secret_key_set(&self) -> SecretKeySet {
        let mut rng = rand::thread_rng();
        //let address = SecretKeySet::random(1, &mut rng);
        //let serialized = serde_json::to_string(&address).unwrap();
       // let serialized = 
 //"{\"poly\":{\"coeff\":[[13684573813709835702,1772061032320941925,17139540486939305054,4797739647464446729],[1862498692327455198,1001392833144568233,2557868070081348817,7444051843144898802]]}}"
  //.to_string();
        //let deserialized: SecretKeySet = serde_json::from_str(&serialized).unwrap();
        //println!("deserialized = {:?}", deserialized);
        //deserialized
		SecretKeySet::random(1, &mut rng)
    }

    pub fn setup_public_key_set(&self, secret_key_set: SecretKeySet) -> PkgPublicKeySet {
        secret_key_set.public_keys()
    }

}
