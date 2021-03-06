use ring::error::Unspecified;
use ring::{aead, agreement, pbkdf2, rand, signature};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{Error, Result};

/// A staticaly generated pair of (ED25519) keys.
///
/// Each peer, belonging to the VPN, has to generate a pair of keys
/// and share it with the server securely (in advance).
///
/// To generate a private key, `genkey.sh` script can be used:
/// $ ./genkey.sh > privkey.der
///
/// To derive a public key from a private key, `pubkey.sh` script can be used:
/// $ ./pubkey.sh < privkey.der > pubkey.der
#[derive(Debug)]
pub struct StaticKeyPair {
    key_pair: signature::Ed25519KeyPair,
}

impl StaticKeyPair {
    /// Opens the given file and reads a private key from it.
    /// The content must be in PKCS#8 v1 (or v2) format.
    /// To generate a private key, `genkey.sh` can be used.
    /// $ ./genkey.sh > privkey.der
    pub fn from_pkcs8<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let keyfile = std::fs::read(path)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&keyfile)
            .map_err(|_| Error::InvalidPrivateKeyFormat)?;
        Ok(Self { key_pair })
    }

    /// Returns a public key of the pair.
    pub fn public_key(&self) -> Vec<u8> {
        use signature::KeyPair;
        self.key_pair.public_key().as_ref().to_vec()
    }

    /// Signs a given data.
    pub fn sign<T: Serialize>(&self, val: &T) -> Signed<T> {
        let data = bincode::serialize(val).expect("serialize");
        let signature = self.key_pair.sign(&data).as_ref().to_vec();
        Signed {
            data,
            signature,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// A bytes with signature generated by `StaticKeyPair::sign`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Signed<T> {
    data: Vec<u8>,
    signature: Vec<u8>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Signed<T> {
    /// Verifies its content with the given public key.
    /// Returns Ok(()) if it was signed by the private one corresponding to the given key.
    pub fn verify(&self, pubkey: &[u8]) -> Result<()> {
        let pubkey = signature::UnparsedPublicKey::new(&signature::ED25519, pubkey);
        pubkey
            .verify(&self.data, &self.signature)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl<T: DeserializeOwned> Signed<T> {
    /// Verifies and deserialize its content.
    pub fn open(self, pubkey: &[u8]) -> Result<T> {
        self.verify(pubkey)?;
        let val: T = bincode::deserialize(&self.data).map_err(|_| Error::BrokenMessage)?;
        Ok(val)
    }
}

/// A private part of a session seed.
/// It is used to establish a session key between 2 peers.
#[derive(Debug)]
pub struct PrivSeed {
    privkey1: agreement::EphemeralPrivateKey,
    privkey2: agreement::EphemeralPrivateKey,
}

/// A public part of a session seed.
/// It is used to establish a session key between 2 peers.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PubSeed {
    pubkey1: Vec<u8>,
    pubkey2: Vec<u8>,
}

/// Generates a pair of session seeds.
pub fn generate_seed_pair() -> (PrivSeed, PubSeed) {
    let rng = rand::SystemRandom::new();

    let generate_key = agreement::EphemeralPrivateKey::generate;
    let privkey1 = generate_key(&agreement::ECDH_P384, &rng).expect("random source unavailable");
    let privkey2 = generate_key(&agreement::ECDH_P384, &rng).expect("random source unavailable");

    let pubkey1 = privkey1.compute_public_key().unwrap();
    let pubkey2 = privkey2.compute_public_key().unwrap();

    let privseed = PrivSeed { privkey1, privkey2 };
    let pubseed = PubSeed {
        pubkey1: pubkey1.as_ref().to_vec(),
        pubkey2: pubkey2.as_ref().to_vec(),
    };

    (privseed, pubseed)
}

/// A nonce generator implements `ring::aead::NonceSequence`.
pub struct NonceSeq {
    id: u8,
    next: u128,
}
impl NonceSeq {
    fn new(id: u8) -> Self {
        Self { id, next: 0 }
    }
}
impl aead::NonceSequence for NonceSeq {
    fn advance(&mut self) -> std::result::Result<aead::Nonce, Unspecified> {
        let value = self.next;
        if value >= 0x0000_0100_0000_0000_0000_0000_0000 {
            Err(Unspecified)
        } else {
            self.next += 1;
            let mut value_bytes = value.to_le_bytes();
            debug_assert!(value_bytes[11] == 0);
            value_bytes[11] = self.id;
            Ok(aead::Nonce::try_assume_unique_for_key(&value_bytes[..12]).expect("nonce length"))
        }
    }
}

/// A session key used for communication between a peer and the server.
pub struct SessionKey {
    opening: aead::LessSafeKey,
    sealing: aead::LessSafeKey,
    nonce_seq: NonceSeq,
}

impl SessionKey {
    fn derive(
        privkey: agreement::EphemeralPrivateKey,
        pubkey: agreement::UnparsedPublicKey<Vec<u8>>,
    ) -> aead::UnboundKey {
        agreement::agree_ephemeral(privkey, &pubkey, (), |material| {
            let algo = &aead::CHACHA20_POLY1305;
            let mut key_bytes = vec![0; algo.key_len()];
            let pbkdf2 = pbkdf2::PBKDF2_HMAC_SHA256;
            let iter = std::num::NonZeroU32::new(100000).unwrap();
            pbkdf2::derive(pbkdf2, iter, &[], material, &mut key_bytes);
            let key = aead::UnboundKey::new(algo, &key_bytes).map_err(|_| ())?;
            Ok(key)
        })
        .expect("agreement")
    }

    /// Derives a session key for clients.
    pub fn client_derive(privseed: PrivSeed, pubseed: PubSeed) -> Self {
        let privkey = privseed.privkey1;
        let pubkey = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, pubseed.pubkey1);
        let ubkey = Self::derive(privkey, pubkey);
        let sealing_key = aead::LessSafeKey::new(ubkey);

        let privkey = privseed.privkey2;
        let pubkey = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, pubseed.pubkey2);
        let ubkey = Self::derive(privkey, pubkey);
        let opening_key = aead::LessSafeKey::new(ubkey);

        Self {
            opening: opening_key,
            sealing: sealing_key,
            nonce_seq: NonceSeq::new(1),
        }
    }

    /// Derives a session key for the server.
    pub fn server_derive(privseed: PrivSeed, pubseed: PubSeed) -> Self {
        let privkey = privseed.privkey1;
        let pubkey = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, pubseed.pubkey1);
        let ubkey = Self::derive(privkey, pubkey);
        let opening_key = aead::LessSafeKey::new(ubkey);

        let privkey = privseed.privkey2;
        let pubkey = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, pubseed.pubkey2);
        let ubkey = Self::derive(privkey, pubkey);
        let sealing_key = aead::LessSafeKey::new(ubkey);

        Self {
            opening: opening_key,
            sealing: sealing_key,
            nonce_seq: NonceSeq::new(2),
        }
    }

    /// Encrypts any data.
    pub fn seal<A: AsRef<[u8]>, T: Serialize>(&mut self, aad: A, data: T) -> Result<Vec<u8>> {
        use aead::NonceSequence;
        let nonce = self.nonce_seq.advance().expect("nonce wear out");
        let nonce_bytes: [u8; 12] = *nonce.as_ref();

        let aad = aead::Aad::from([aad.as_ref(), &nonce_bytes].concat());

        let mut bytes = bincode::serialize(&data).expect("serialize");

        self.sealing
            .seal_in_place_append_tag(nonce, aad, &mut bytes)
            .expect("seal");

        // append the nonce at the end of the ciphertext
        bytes.extend_from_slice(&nonce_bytes);
        Ok(bytes)
    }

    /// Decrypts a ciphertext.
    pub fn unseal<A: AsRef<[u8]>, T: DeserializeOwned>(
        &self,
        aad: A,
        ciphertext: &mut [u8],
    ) -> Result<T> {
        let (ciphertext, nonce_bytes) = ciphertext.split_at_mut(ciphertext.len() - aead::NONCE_LEN);

        let nonce_bytes: [u8; aead::NONCE_LEN] = nonce_bytes[..].try_into().expect("nonce len");
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let aad = aead::Aad::from([aad.as_ref(), &nonce_bytes].concat());

        let plaintext = self
            .opening
            .open_in_place(nonce, aad, ciphertext)
            .map_err(|_| Error::BrokenMessage)?;

        bincode::deserialize(plaintext).map_err(|_| Error::BrokenMessage)
    }
}
