//! A pairing-based threshold cryptosystem for collaborative decryption and signatures.

// Clippy warns that it's dangerous to derive `PartialEq` and explicitly implement `Hash`, but the
// `pairing::bls12_381` types don't implement `Hash`, so we can't derive it.
//#![allow(clippy::derive_hash_xor_eq)]
#![deny(missing_docs)]
// When using the mocktography, the resulting field elements become wrapped `u32`s, suddenly
// triggering pass-by-reference warnings. They are conditionally disabled for this reason:
#![cfg_attr(
    feature = "use-insecure-test-only-mock-crypto",
    allow(clippy::trivially_copy_pass_by_ref)
)]
#![warn(missing_docs)]

pub use pairing;
mod into_fr;
mod secret;
pub mod error;
pub mod serde_impl;

//#[cfg(feature = "codec-support")]
//#[macro_use]
//mod codec_impl;

//mod libs;
//pub use crate::libs::poly;
//pub use crate::libs::poly::{Commitment, Poly};

pub mod poly;

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ptr::copy_nonoverlapping;

use hex_fmt::HexFmt;
use pairing::{CurveAffine, CurveProjective, EncodedPoint, Engine, Field};
use rand::distributions::{Distribution, Standard};
use rand::{rngs::OsRng, Rng, SeedableRng};
use rand::{thread_rng};

mod rand_wrapper;
pub use crate::rand_wrapper::rand04_compat::RngExt;
pub use crate::rand_wrapper::rand04_compat::rand04;
pub use crate::poly::{Commitment, Poly};

//use core::marker::PhantomData;

use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use tiny_keccak::sha3_256;
use zeroize::Zeroize;

//use crate::cmp_pairing::cmp_projective;
use crate::error::{Error, FromBytesError, FromBytesResult, Result};
//use crate::poly::{Commitment, Poly};
use crate::secret::clear_fr;

//pub use crate::libs::into_fr::IntoFr;
pub use crate::into_fr::IntoFr;

#[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
pub use pairing::bls12_381::{Bls12 as PEngine, Fr, FrRepr, G1Affine, G2Affine, G1, G2};

/// The size of a key's representation in bytes.
#[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
pub const PK_SIZE: usize = 48;

const ERR_OS_RNG: &str = "could not initialize the OS random number generator";

/// A public key [start].
#[derive(Deserialize, Serialize, Copy, Clone, PartialEq, Eq)]
pub struct PkgPublicKey(#[serde(with = "serde_impl::projective")] G2);

impl Hash for PkgPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl fmt::Debug for PkgPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        write!(f, "PkgPublicKey({:0.10})", HexFmt(uncomp))
    }
}

impl PartialOrd for PkgPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for PkgPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_projective(&self.0, &other.0)
    }
}

impl PkgPublicKey {
	
	// ***********************************************
	/// Encrypts the message.
	pub fn encrypt_new<M: AsRef<[u8]>>(&self, msg: M, id: String) -> Ciphertext {
        //let mut rng: OsRng = OsRng::new().expect(ERR_OS_RNG);
        let mut rng = rand::thread_rng();
        let r: Fr = rng.gen04();
        //let r: Fr = Fr::one();

        let u = G2::one().into_affine().mul(r);
        let v: Vec<u8> = {
            let qid = hash_g1("bob".to_string()).into_affine().mul(r);
            let gid = PEngine::pairing(qid,self.0);
            let hash1 =  hash_g1(gid.to_string());
            xor_with_hash_new(hash1.to_string(), msg.as_ref())
        };
        let w = hash_g1_m(u, &v).into_affine().mul(r);
        Ciphertext(u, v, w)
    }

    /// Returns the key with the given representation, if valid.
    pub fn from_bytes<B: Borrow<[u8; PK_SIZE]>>(bytes: B) -> FromBytesResult<Self> {
        let mut compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
        compressed.as_mut().copy_from_slice(bytes.borrow());
        let opt_affine = compressed.into_affine().ok();
        let projective = opt_affine.ok_or(FromBytesError::Invalid)?.into_projective();
        Ok(PkgPublicKey(projective))
    }

    /// Returns a byte string representation of the public key.
    pub fn to_bytes(&self) -> [u8; PK_SIZE] {
        let mut bytes = [0u8; PK_SIZE];
        bytes.copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        bytes
    }
}

/// **************************************** A public key [end] ********************************

/// **************************************** A public key share [start] ********************************

/// A public key share.
#[cfg_attr(feature = "codec-support", derive(codec::Encode, codec::Decode))]
#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct PkgPublicKeyShare(PkgPublicKey);

impl fmt::Debug for PkgPublicKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = (self.0).0.into_affine().into_uncompressed();
        write!(f, "PkgPublicKeyShare({:0.10})", HexFmt(uncomp))
    }
}

impl PkgPublicKeyShare {

    /// Returns `true` if the decryption share matches the ciphertext.
    pub fn verify_ciphertext(&self,ct: &Ciphertext, g_parameter: &GParameter) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *ct;
        let hash = hash_g1_m(*u, v);
        PEngine::pairing(*w, g_parameter.g_2())  == PEngine::pairing(hash,*u)
    }

    pub fn verify_partial_private_key(&self,id: String,
     partial_private_key: &DecryptionShare, g_parameter: &GParameter) -> bool {
        let hash = hash_g1(id);
        PEngine::pairing(partial_private_key.0, g_parameter.g_2())  == PEngine::pairing(hash,(self.0).0)
    }

    /// Returns the key share with the given representation, if valid.
    pub fn from_bytes<B: Borrow<[u8; PK_SIZE]>>(bytes: B) -> FromBytesResult<Self> {
        Ok(PkgPublicKeyShare(PkgPublicKey::from_bytes(bytes)?))
    }

    /// Returns a byte string representation of the public key share.
    pub fn to_bytes(&self) -> [u8; PK_SIZE] {
        self.0.to_bytes()
    }
}

/// **************************************** A public key share [end] ********************************


/// A secret key; wraps a single prime field element. The field element is
/// heap allocated to avoid any stack copying that result when passing
/// `SecretKey`s between stack frames.
///
/// # Serde integration
/// `SecretKey` implements `Deserialize` but not `Serialize` to avoid accidental
/// serialization in insecure contexts. To enable both use the `::serde_impl::SerdeSecret`
/// wrapper which implements both `Deserialize` and `Serialize`.
#[derive(PartialEq, Eq)]
pub struct SecretKey(Box<Fr>);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        clear_fr(&mut *self.0)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Creates a `SecretKey` containing the zero prime field element.
impl Default for SecretKey {
    fn default() -> Self {
        let mut fr = Fr::zero();
        SecretKey::from_mut(&mut fr)
    }
}

impl Distribution<SecretKey> for Standard {
    /// Creates a new random instance of `SecretKey`. If you do not need to specify your own RNG,
    /// you should use the [`SecretKey::random()`](struct.SecretKey.html#method.random) constructor,
    /// which uses [`rand::thread_rng()`](https://docs.rs/rand/0.6.1/rand/fn.thread_rng.html)
    /// internally as its RNG.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        //SecretKey(Box::new(rng.gen04()))
       let r: Fr = Fr::one();
       SecretKey(Box::new(r))
    }
}

/// Creates a new `SecretKey` by cloning another `SecretKey`'s prime field element.
impl Clone for SecretKey {
    fn clone(&self) -> Self {
        let mut fr = *self.0;
        SecretKey::from_mut(&mut fr)
    }
}

/// A debug statement where the secret prime field element is redacted.
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey").field(&DebugDots).finish()
    }
}

impl SecretKey {
    /// Creates a new `SecretKey` from a mutable reference to a field element. This constructor
    /// takes a reference to avoid any unnecessary stack copying/moving of secrets (i.e. the field
    /// element). The field element is copied bytewise onto the heap, the resulting `Box` is
    /// stored in the returned `SecretKey`.
    ///
    /// *WARNING* this constructor will overwrite the referenced `Fr` element with zeros after it
    /// has been copied onto the heap.
    /// [ds]
    pub fn from_mut(fr: &mut Fr) -> Self {
        let fr_ptr = fr as *mut Fr;
        let mut boxed_fr = Box::new(Fr::zero());
        unsafe {
            copy_nonoverlapping(fr_ptr, &mut *boxed_fr as *mut Fr, 1);
        }
        clear_fr(fr);
        SecretKey(boxed_fr)
    }

    /// Creates a new random instance of `SecretKey`. If you want to use/define your own random
    /// number generator, you should use the constructor:
    /// [`SecretKey::sample()`](struct.SecretKey.html#impl-Distribution<SecretKey>). If you do not
    /// need to specify your own RNG, you should use the
    /// [`SecretKey::random()`](struct.SecretKey.html#method.random) constructor, which uses
    /// [`rand::thread_rng()`](https://docs.rs/rand/0.6.1/rand/fn.thread_rng.html) internally as its
    /// RNG.
    pub fn random() -> Self {
        rand::random()
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PkgPublicKey {
        //PublicKey(G1Affine::one().mul(*self.0))
       //PublicKey(hash_g1("bob".to_string()).into_affine().mul(*self.0))
       PkgPublicKey(G2Affine::one().mul(*self.0))
    }

    /// Returns the decrypted text, or `None`, if the ciphertext isn't valid.
    pub fn decrypt(&self, ct: &Ciphertext) -> Option<Vec<u8>> {
        if !ct.verify() {
            return None;
        }
        let Ciphertext(ref u, ref v, _) = *ct;
        let g = u.into_affine().mul(*self.0);
        Some(xor_with_hash_h2(g, v))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        let uncomp = self.public_key().0.into_affine().into_uncompressed();
        format!("SecretKey({:0.10})", HexFmt(uncomp))
    }
}

/// A secret key share.
///
/// # Serde integration
/// `SecretKeyShare` implements `Deserialize` but not `Serialize` to avoid accidental
/// serialization in insecure contexts. To enable both use the `::serde_impl::SerdeSecret`
/// wrapper which implements both `Deserialize` and `Serialize`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretKeyShare(SecretKey);

impl fmt::Debug for SecretKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKeyShare").field(&DebugDots).finish()
    }
}

impl SecretKeyShare {
    /// Creates a new `SecretKeyShare` from a mutable reference to a field element. This
    /// constructor takes a reference to avoid any unnecessary stack copying/moving of secrets
    /// field elements. The field element will be copied bytewise onto the heap, the resulting
    /// `Box` is stored in the `SecretKey` which is then wrapped in a `SecretKeyShare`.
    ///
    /// *WARNING* this constructor will overwrite the pointed to `Fr` element with zeros once it
    /// has been copied into a new `SecretKeyShare`.
    
    
    pub fn from_mut(fr: &mut Fr) -> Self {
        SecretKeyShare(SecretKey::from_mut(fr))
    }

    /// Returns the matching public key share.
    pub fn public_key_share(&self) -> PkgPublicKeyShare {
        PkgPublicKeyShare(self.0.public_key())
    }

    /// Returns a decryption share.
    pub fn obtain_partial_private_key(&self, id: String) -> Option<DecryptionShare> {
        Some(self.decrypt_share_no_verify_new(id))
    }
    
    /// Returns a decryption share, without validating the ciphertext.
    pub fn decrypt_share_no_verify_new(&self, id: String) -> DecryptionShare {
	    DecryptionShare(hash_g1(id).into_affine().mul(*(self.0).0))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        let uncomp = self.0.public_key().0.into_affine().into_uncompressed();
        format!("SecretKeyShare({:0.10})", HexFmt(uncomp))
    }
}

///[ds] An encrypted message.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(
    #[serde(with = "serde_impl::projective")] 
    G2,
    Vec<u8>,
    #[serde(with = "serde_impl::projective")]
    G1,
);

// [ds] 
impl Hash for Ciphertext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Ciphertext(ref u, ref v, ref w) = *self;
        u.into_affine().into_compressed().as_ref().hash(state);
        v.hash(state);
        w.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl PartialOrd for Ciphertext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for Ciphertext {
    fn cmp(&self, other: &Self) -> Ordering {
        let Ciphertext(ref u0, ref v0, ref w0) = self;
        let Ciphertext(ref u1, ref v1, ref w1) = other;
        cmp_projective(u0, u1)
            .then(v0.cmp(v1))
            .then(cmp_projective(w0, w1))
    }
}

impl Ciphertext {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        //let Ciphertext(ref u, ref v, ref w) = *self;
        //let hash = hash_g1_g2(*u, v);
        true
        //PEngine::pairing(G1Affine::one(), *w) == PEngine::pairing(*u, hash)
    }
}

/// A decryption share. A threshold of decryption shares can be used to decrypt a message.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DecryptionShare(#[serde(with = "serde_impl::projective")] G1);

impl Distribution<DecryptionShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> DecryptionShare {
       let r: G1 = G1::one(); 
       //DecryptionShare(rng.gen04())
       DecryptionShare(r)
    }
}

impl Hash for DecryptionShare {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl fmt::Debug for DecryptionShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DecryptionShare").field(&DebugDots).finish()
    }
}

/// A public key and an associated set of public key shares.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct PkgPublicKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    commit: Commitment,
}

impl Hash for PkgPublicKeySet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.commit.hash(state);
    }
}

impl From<Commitment> for PkgPublicKeySet {
    fn from(commit: Commitment) -> PkgPublicKeySet {
        PkgPublicKeySet { commit }
    }
}

impl PkgPublicKeySet {
    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.commit.degree()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PkgPublicKey {
        PkgPublicKey(self.commit.coeff[0])
    }

    /// Returns the `i`-th public key share.
    pub fn public_key_share<T: IntoFr>(&self, i: T) -> PkgPublicKeyShare {
        let value = self.commit.evaluate(into_fr_plus_1(i));
        //println!("value {:?}", value);
        PkgPublicKeyShare(PkgPublicKey(value))
    }

    /// Combines the shares to decrypt the ciphertext.
    pub fn decrypt<'a, T, I>(&self, shares: I, ct: &Ciphertext) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = (T, &'a DecryptionShare)>,
        T: IntoFr,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        //println!("samples {:?}", shares);
        let sid = interpolate(self.commit.degree(), samples)?;
        let gid = PEngine::pairing(sid,ct.0);
        let hash1 =  hash_g1(gid.to_string());

        let c = xor_with_hash_new(hash1.to_string(), &ct.1);
        //println!("mmm ###################### {:?}", c);
        //Ok(c)
        //Ok(xor_with_hash_new(hash1.to_string(), msg.as_ref())
        xor_with_hash(sid, &ct.1);
        Ok(c)
    }
    /*
     pub fn decrypt1<'a, T, I,S>(&self, shares: I) -> Result<S>
     where
        S: CurveProjective<Scalar = Fr>,
        I: IntoIterator<Item = (T, &'a DecryptionShare)>,
        T: IntoFr,
     {
		let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
		//let sid = interpolate(self.commit.degree(), samples)?;
		interpolate(self.commit.degree(), samples)
     }
    */
}

/// A secret key and an associated set of secret key shares.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    poly: Poly,
}

impl From<Poly> for SecretKeySet {
    fn from(poly: Poly) -> SecretKeySet {
        SecretKeySet { poly }
    }
}

impl SecretKeySet {
    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::try_random()` in every
    /// way except that this constructor panics if the other returns an error.
    ///
    /// # Panic
    ///
    /// Panics if the `threshold` is too large for the coefficients to fit into a `Vec`.
    /// [ds] 
    pub fn random<R: Rng>(threshold: usize, rng: &mut R) -> Self {
        SecretKeySet::try_random(threshold, rng)
            .unwrap_or_else(|e| panic!("Failed to create random `SecretKeySet`: {}", e))
    }

    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::random()` in every
    /// way except that this constructor returns an `Err` where the `random` would panic.
    pub fn try_random<R: Rng>(threshold: usize, rng: &mut R) -> Result<Self> {
        Poly::try_random(threshold, rng).map(SecretKeySet::from)
    }

    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.poly.degree()
    }

    /// [ds] Returns the `i`-th secret key share.
    pub fn secret_key_share<T: IntoFr>(&self, i: T) -> SecretKeyShare {
        let mut fr = self.poly.evaluate(into_fr_plus_1(i));
        SecretKeyShare::from_mut(&mut fr)
    }

   pub fn user_secret_key_share<T: IntoFr>(&self, i: T) -> SecretKeyShare {
        let mut fr = self.poly.evaluate(into_fr_plus_1(i));
        SecretKeyShare::from_mut(&mut fr)
    }

    /// Returns the corresponding public key set. That information can be shared publicly.
    pub fn public_keys(&self) -> PkgPublicKeySet {
        PkgPublicKeySet {
            commit: self.poly.commitment(),
        }
    }

    /// Returns the secret master key.
    //#[cfg(test)]
    pub fn secret_key(&self) -> SecretKey {
        let mut fr = self.poly.evaluate(0);
        SecretKey::from_mut(&mut fr)
    }
}

/// Returns a hash of the given message in `G2`.
pub fn hash_g2<M: AsRef<[u8]>>(msg: M) -> G2 {
    let digest = sha3_256(msg.as_ref());
    //ChaChaRng::from_seed(digest).gen04()
    //let mut ra = ChaChaRng::new_unseeded();
    //ra.gen04()
    ChaChaRng::from_seed(digest).gen04()
    //G2::one()
}

/// Returns a hash of the given message in `G2`.
pub fn hash_g1<M: AsRef<[u8]>>(msg: M) -> G1 {
    let digest = sha3_256(msg.as_ref());
    //SeedableRng::from_seed(digest).gen04()
    ChaChaRng::from_seed(digest).gen04()
}

/// Returns a hash of the given message in `G2`.
pub fn hash_fr<M: AsRef<[u8]>>(msg: M) -> Fr {
    let digest = sha3_256(msg.as_ref());
    //SeedableRng::from_seed(digest).gen04()
    ChaChaRng::from_seed(digest).gen04()
    //Fr::one()
}

/// Returns a hash of the group element and message, in the second group.
pub fn hash_g1_g2<M: AsRef<[u8]>>(g1: G1, msg: M) -> G2 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        sha3_256(msg.as_ref()).to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g1.into_affine().into_compressed().as_ref());
    hash_g2(&msg)
}

/// Returns a hash of the group element and message, in the second group.
pub fn hash_g1_m<M: AsRef<[u8]>>(g2: G2, msg: M) -> G1 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        sha3_256(msg.as_ref()).to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g2.into_affine().into_compressed().as_ref());
    hash_g1(&msg)
}

/// Returns a hash of the group element and message, in the second group.
pub fn hash_g1_g2_new<M: AsRef<[u8]>>(g2: G2, msg: M) -> G2 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        sha3_256(msg.as_ref()).to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g2.into_affine().into_compressed().as_ref());
    hash_g2(&msg)
}

/// Returns the bitwise xor of `bytes` with a sequence of pseudorandom bytes determined by `g1`.
fn xor_with_hash(g1: G1, bytes: &[u8]) -> Vec<u8> {
    let digest = sha3_256(g1.into_affine().into_compressed().as_ref());
    let mut rng = ChaChaRng::from_seed(digest);
    //let mut rng = rand::thread_rng();
    //let mut rng = getrandom(digest);
    
    //let mut rng = thread_rng();
    let xor = |(a, b): (u8, &u8)| a ^ b;
    rng.sample_iter(&Standard).zip(bytes).map(xor).collect()
}

fn xor_with_hash_h2(g2: G2, bytes: &[u8]) -> Vec<u8> {
    let digest = sha3_256(g2.into_affine().into_compressed().as_ref());
    let mut rng = ChaChaRng::from_seed(digest);
    //let mut rng = thread_rng();
    let xor = |(a, b): (u8, &u8)| a ^ b;
    rng.sample_iter(&Standard).zip(bytes).map(xor).collect()
}

fn xor_with_hash_new(str: String, bytes: &[u8]) -> Vec<u8> {
    let digest = sha3_256(str.as_ref());
    let mut rng = ChaChaRng::from_seed(digest);
    //let mut rng = thread_rng();
    let xor = |(a, b): (u8, &u8)| a ^ b;
    rng.sample_iter(&Standard).zip(bytes).map(xor).collect()
}

use std::borrow::Borrow;

/// Given a list of `t + 1` samples `(i - 1, f(i) * g)` for a polynomial `f` of degree `t`, and a
/// group generator `g`, returns `f(0) * g`.
pub fn interpolate<C, B, T, I>(t: usize, items: I) -> Result<C>
where
    C: CurveProjective<Scalar = Fr>,
    I: IntoIterator<Item = (T, B)>,
    T: IntoFr,
    B: Borrow<C>,
{
    let samples: Vec<_> = items
        .into_iter()
        .take(t + 1)
        .map(|(i, sample)| (into_fr_plus_1(i), sample))
        .collect();
    if samples.len() <= t {
        return Err(Error::NotEnoughShares);
    }

    if t == 0 {
        return Ok(*samples[0].1.borrow());
    }

    // Compute the products `x_prod[i]` of all but the `i`-th entry.
    let mut x_prod: Vec<C::Scalar> = Vec::with_capacity(t);
    let mut tmp = C::Scalar::one();
    x_prod.push(tmp);
    for (x, _) in samples.iter().take(t) {
        tmp.mul_assign(x);
        x_prod.push(tmp);
    }
    tmp = C::Scalar::one();
    for (i, (x, _)) in samples[1..].iter().enumerate().rev() {
        tmp.mul_assign(x);
        x_prod[i].mul_assign(&tmp);
    }

    let mut result = C::zero();
    for (mut l0, (x, sample)) in x_prod.into_iter().zip(&samples) {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut denom = C::Scalar::one();
        for (x0, _) in samples.iter().filter(|(x0, _)| x0 != x) {
            let mut diff = *x0;
            diff.sub_assign(x);
            denom.mul_assign(&diff);
        }
        l0.mul_assign(&denom.inverse().ok_or(Error::DuplicateEntry)?);
        result.add_assign(&sample.borrow().into_affine().mul(l0));
    }
    Ok(result)
}

fn into_fr_plus_1<I: IntoFr>(x: I) -> Fr {
    let mut result = Fr::one();
    //let g1:G1 = hash_g1("bob".to_string());
    //println!("into_fr_plus_1 *********************** {:?}", g1);
    result.add_assign(&x.into_fr());
    result
}

/// Type that implements `Debug` printing three dots. This can be used to hide the contents of a
/// field in a `Debug` implementation.
struct DebugDots;

impl fmt::Debug for DebugDots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "...")
    }
}

/// A public key [start].
#[derive(Deserialize, Serialize, Copy, Clone, PartialEq, Eq)]
pub struct GParameter(
	 #[serde(with = "serde_impl::projective")] G1, 
	 #[serde(with = "serde_impl::projective")] G2,);

impl Hash for GParameter {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl fmt::Debug for GParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        write!(f, "GParameter({:0.10})", HexFmt(uncomp))
    }
}

/// Returns a new GParameter
impl GParameter {
	
	/// Constructs a new `GParameter`.
	///
	/// # Examples
	///
	/// ```
	/// use portex_pkg::GParameter;
	///
	/// let test = GParameter::new();
	/// ```
	pub fn new() -> GParameter {
		let g1:G1 = G1::one();
	    //let serialized = serde_json::to_string(&g1).unwrap();
        //println!("g1 = {:?}", serialized);

        GParameter(G1::one(),G2::one())
    }

    pub fn g_1(&self) -> G1 {
        G1::one()
    }
 
    pub fn g_2(&self) -> G2 {
        G2::one()
    }
}

/// Compares two curve elements and returns their `Ordering`.
pub fn cmp_projective<G: CurveProjective>(x: &G, y: &G) -> Ordering {
    let xc = x.into_affine().into_compressed();
    let yc = y.into_affine().into_compressed();
    xc.as_ref().cmp(yc.as_ref())
}


/*
#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use rand::{self, distributions::Standard, random, Rng};
    use rand04_compat::rand04::random as random04;

    #[test]
    fn test_interpolate() {
        let mut rng = rand::thread_rng();
        for deg in 0..5 {
            println!("deg = {}", deg);
            let comm = Poly::random(deg, &mut rng).commitment();
            let mut values = Vec::new();
            let mut x = 0;
            for _ in 0..=deg {
                x += rng.gen_range(1, 5);
                values.push((x - 1, comm.evaluate(x)));
            }
            let actual = interpolate(deg, values).expect("wrong number of values");
            assert_eq!(comm.evaluate(0), actual);
        }
    }
   
    #[test]
    fn test_simple_sig() {
        let sk0 = SecretKey::random();
        let sk1 = SecretKey::random();
        let pk0 = sk0.public_key();
        let msg0 = b"Real news";
        let msg1 = b"Fake news";
        assert!(pk0.verify(&sk0.sign(msg0), msg0));
        assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
        assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
    }

    #[test]
    fn test_threshold_sig() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let pk_master = pk_set.public_key();

        // Make sure the keys are different, and the first coefficient is the main key.
        assert_ne!(pk_master, pk_set.public_key_share(0).0);
        assert_ne!(pk_master, pk_set.public_key_share(1).0);
        assert_ne!(pk_master, pk_set.public_key_share(2).0);

        // Make sure we don't hand out the main secret key to anyone.
        let sk_master = sk_set.secret_key();
        let sk_share_0 = sk_set.secret_key_share(0).0;
        let sk_share_1 = sk_set.secret_key_share(1).0;
        let sk_share_2 = sk_set.secret_key_share(2).0;
        assert_ne!(sk_master, sk_share_0);
        assert_ne!(sk_master, sk_share_1);
        assert_ne!(sk_master, sk_share_2);

        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        let sigs: BTreeMap<_, _> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            assert!(pk_set.public_key_share(*i).verify(sig, msg));
        }

        // Combined, they produce a signature matching the main public key.
        let sig = pk_set.combine_signatures(&sigs).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig, msg));

        // A different set of signatories produces the same signature.
        let sigs2: BTreeMap<_, _> = [42, 43, 44, 45]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();
        let sig2 = pk_set.combine_signatures(&sigs2).expect("signatures match");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_simple_enc() {
        let sk_bob: SecretKey = random();
        let sk_eve: SecretKey = random();
        let pk_bob = sk_bob.public_key();
        let msg = b"Muffins in the canteen today! Don't tell Eve!";
        let ciphertext = pk_bob.encrypt(&msg[..]);
        assert!(ciphertext.verify());

        // Bob can decrypt the message.
        let decrypted = sk_bob.decrypt(&ciphertext).expect("invalid ciphertext");
        assert_eq!(msg[..], decrypted[..]);

        // Eve can't.
        let decrypted_eve = sk_eve.decrypt(&ciphertext).expect("invalid ciphertext");
        assert_ne!(msg[..], decrypted_eve[..]);

        // Eve tries to trick Bob into decrypting `msg` xor `v`, but it doesn't validate.
        let Ciphertext(u, v, w) = ciphertext;
        let fake_ciphertext = Ciphertext(u, vec![0; v.len()], w);
        assert!(!fake_ciphertext.verify());
        assert_eq!(None, sk_bob.decrypt(&fake_ciphertext));
    }

    #[test]
    fn test_random_extreme_thresholds() {
        let mut rng = rand::thread_rng();
        let sks = SecretKeySet::random(0, &mut rng);
        assert_eq!(0, sks.threshold());
        assert!(SecretKeySet::try_random(usize::max_value(), &mut rng).is_err());
    }

    #[test]
    fn test_threshold_enc() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = b"Totally real news";
        let ciphertext = pk_set.public_key().encrypt(&msg[..]);

        // The threshold is 3, so 4 signature shares will suffice to decrypt.
        let shares: BTreeMap<_, _> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let dec_share = sk_set
                    .secret_key_share(i)
                    .decrypt_share(&ciphertext)
                    .expect("ciphertext is invalid");
                (i, dec_share)
            })
            .collect();

        // Each of the shares is valid matching its public key share.
        for (i, share) in &shares {
            pk_set
                .public_key_share(*i)
                .verify_decryption_share(share, &ciphertext);
        }

        // Combined, they can decrypt the message.
        let decrypted = pk_set
            .decrypt(&shares, &ciphertext)
            .expect("decryption shares match");
        assert_eq!(msg[..], decrypted[..]);
    }

    /// Some basic sanity checks for the `hash_g2` function.
    #[test]
    fn test_hash_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = rng.sample_iter(&Standard).take(1000).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();

        assert_eq!(hash_g2(&msg), hash_g2(&msg));
        assert_ne!(hash_g2(&msg), hash_g2(&msg_end0));
        assert_ne!(hash_g2(&msg_end0), hash_g2(&msg_end1));
    }

    /// Some basic sanity checks for the `hash_g1_g2` function.
    #[test]
    fn test_hash_g1_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = rng.sample_iter(&Standard).take(1000).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();
        let g0 = random04();
        let g1 = random04();

        assert_eq!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg_end0));
        assert_ne!(hash_g1_g2(g0, &msg_end0), hash_g1_g2(g0, &msg_end1));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g1, &msg));
    }

    /// Some basic sanity checks for the `hash_bytes` function.
    #[test]
    fn test_xor_with_hash() {
        let g0 = random04();
        let g1 = random04();
        let xwh = xor_with_hash;
        assert_eq!(xwh(g0, &[0; 5]), xwh(g0, &[0; 5]));
        assert_ne!(xwh(g0, &[0; 5]), xwh(g1, &[0; 5]));
        assert_eq!(5, xwh(g0, &[0; 5]).len());
        assert_eq!(6, xwh(g0, &[0; 6]).len());
        assert_eq!(20, xwh(g0, &[0; 20]).len());
    }

    #[test]
    fn test_from_to_bytes() {
        let sk: SecretKey = random();
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let pk2 = PublicKey::from_bytes(pk.to_bytes()).expect("invalid pk representation");
        assert_eq!(pk, pk2);
        let sig2 = Signature::from_bytes(sig.to_bytes()).expect("invalid sig representation");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_serde() {
        let sk = SecretKey::random();
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let ser_pk = bincode::serialize(&pk).expect("serialize public key");
        let deser_pk = bincode::deserialize(&ser_pk).expect("deserialize public key");
        assert_eq!(ser_pk.len(), PK_SIZE);
        assert_eq!(pk, deser_pk);
        let ser_sig = bincode::serialize(&sig).expect("serialize signature");
        let deser_sig = bincode::deserialize(&ser_sig).expect("deserialize signature");
        assert_eq!(ser_sig.len(), SIG_SIZE);
        assert_eq!(sig, deser_sig);
    }

    #[cfg(feature = "codec-support")]
    #[test]
    fn test_codec() {
        use codec::{Decode, Encode};
        use rand::distributions::{Distribution, Standard};
        use rand::thread_rng;

        macro_rules! assert_codec {
            ($obj:expr, $type:ty) => {
                let encoded: Vec<u8> = $obj.encode();
                let decoded: $type = <$type>::decode(&mut &encoded[..]).unwrap();
                assert_eq!(decoded, $obj.clone());
            };
        }

        let sk = SecretKey::random();
        let pk = sk.public_key();
        assert_codec!(pk, PublicKey);

        let pk_share = PublicKeyShare(pk);
        assert_codec!(pk_share, PublicKeyShare);

        let sig = sk.sign(b"this is a test");
        assert_codec!(sig, Signature);

        let sig_share = SignatureShare(sig);
        assert_codec!(sig_share, SignatureShare);

        let cipher_text = pk.encrypt(b"cipher text");
        assert_codec!(cipher_text, Ciphertext);

        let dec_share: DecryptionShare = Standard.sample(&mut thread_rng());
        assert_codec!(dec_share, DecryptionShare);

        let sk_set = SecretKeySet::random(3, &mut thread_rng());
        let pk_set = sk_set.public_keys();
        assert_codec!(pk_set, PublicKeySet);
    }

    #[test]
    fn test_size() {
        assert_eq!(<G1Affine as CurveAffine>::Compressed::size(), PK_SIZE);
        assert_eq!(<G2Affine as CurveAffine>::Compressed::size(), SIG_SIZE);
    }

    #[test]
    fn test_zeroize() {
        let zero_sk = SecretKey::from_mut(&mut Fr::zero());

        let mut sk = SecretKey::random();
        assert_ne!(zero_sk, sk);

        sk.zeroize();
        assert_eq!(zero_sk, sk);
    }
}
*/
