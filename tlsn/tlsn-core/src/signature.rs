//! Signature Mod

use mina_hasher::{Hashable, ROInput};
use mina_signer::{BaseField, PubKey, ScalarField, Signer, NetworkId, Schnorr};
use o1_utils::FieldHelpers;
use p256::{
    ecdsa::{signature::Verifier, VerifyingKey},
    elliptic_curve::generic_array::GenericArray,
};

use serde::{
    de::{self, Visitor},
    Deserializer,
};
use serde::{Deserialize, Serialize};

use bitcoin;
use bitcoin::base58;
use serde::de::Error;
use std::fmt;

use crate::SessionHeader;
use mpz_core::serialize::CanonicalSerialize;

/// A Notary public key.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NotaryPublicKey {
    /// A Mina-compatible public key.
    MinaSchnorr(PubKey),
    /// A NIST P-256 public key.
    P256(p256::PublicKey),
}

impl From<PubKey> for NotaryPublicKey {
    fn from(key: PubKey) -> Self {
        Self::MinaSchnorr(key)
    }
}

impl From<p256::PublicKey> for NotaryPublicKey {
    fn from(key: p256::PublicKey) -> Self {
        Self::P256(key)
    }
}

/// An error occurred while verifying a signature.
#[derive(Debug, thiserror::Error)]
#[error("signature verification failed: {0}")]
pub struct SignatureVerifyError(String);

/// A Notary signature.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TLSNSignature {
    /// A Mina-Schnorr signature.
    MinaSchnorr(mina_signer::Signature),
    /// A secp256r1 signature.
    P256(p256::ecdsa::Signature),
}

impl From<mina_signer::Signature> for TLSNSignature {
    fn from(sig: mina_signer::Signature) -> Self {
        Self::MinaSchnorr(sig)
    }
}

impl From<p256::ecdsa::Signature> for TLSNSignature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        Self::P256(sig)
    }
}

/// Data Struct
#[derive(Debug, Clone)]
pub struct Data(pub &'static [u8]);
// #[derive(Debug, Clone)]
// pub struct Data(pub Vec<u8>);

impl Hashable for SessionHeader {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        let roi = ROInput::new()
            .append_bytes(&self.encoder_seed)
            .append_bytes(&self.merkle_root.0)
            .append_u64(self.sent_len as u64)
            .append_u64(self.recv_len as u64)
            .append_bytes(&self.handshake_summary.to_bytes());

        roi
        
    }

    fn domain_string(_: Self::D) -> Option<String> {
        None
    }

}


impl Data {
    /// to_array method
    pub fn to_array(&self) -> &[u8] {
        &self.0
    }

    /// Converts the data to a Base58-encoded string.
    pub fn to_base58(&self) -> String {
        base58::encode(&self.0)
    }

    /// from method
    pub fn from(data: &[u8]) -> Self {
        let data_static: &'static [u8] = Box::leak(data.to_vec().into_boxed_slice());
        Self(data_static)
    }
}

impl From<Vec<u8>> for Data {
    fn from(data: Vec<u8>) -> Self {
        let data_static: &'static [u8] = Box::leak(data.into_boxed_slice());
        Self(data_static)
    }
}

impl Hashable for Data {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        ROInput::new().append_bytes(&self.0)
        // let roi = ROInput::new();

        // roi
    }

    fn domain_string(_: Self::D) -> Option<String> {
        None
    }
}

impl TLSNSignature {
    /// Returns the bytes of this signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::MinaSchnorr(sig) => {
                let mut bytes = Vec::with_capacity(BaseField::size_in_bytes() * 2);

                let rx_bytes = sig.rx.to_bytes();
                let s_bytes = sig.s.to_bytes();

                bytes.extend_from_slice(&rx_bytes);
                bytes.extend_from_slice(&s_bytes);
                bytes
            }
            Self::P256(sig) => sig.to_vec(),
        }
    }

    /// Verifies the signature.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to verify.
    /// * `notary_public_key` - The public key of the notary.
    pub fn verify(
        &self,
        msg: &SessionHeader,
        notary_public_key: impl Into<NotaryPublicKey>,
    ) -> Result<(), SignatureVerifyError> {
        println!("msg: {:?}", msg);
        // println!("msg.to_array: {:?}", msg.to_array());
        // println!("msg.to_base58: {:?}", msg.to_base58());
        match (self, notary_public_key.into()) {
            (Self::MinaSchnorr(sig), NotaryPublicKey::MinaSchnorr(key)) => {

                let mut ctx = mina_signer::create_legacy::<SessionHeader>(NetworkId::TESTNET);

                if ctx.verify(&sig, &key, msg) {
                    Ok(())
                } else {
                    Err(SignatureVerifyError(
                        "Signature verification failed".to_string(),
                    ))
                }
            }
            (Self::P256(sig), NotaryPublicKey::P256(key)) => VerifyingKey::from(key)
                .verify(msg.to_bytes(), sig)
                .map_err(|e| SignatureVerifyError(e.to_string())),
            (Self::MinaSchnorr(_), NotaryPublicKey::P256(_)) => Err(SignatureVerifyError(
                "Invalid public key type for Mina-Schnorr signature".to_string(),
            )),
            (Self::P256(_), NotaryPublicKey::MinaSchnorr(_)) => Err(SignatureVerifyError(
                "Invalid public key type for P-256 signature".to_string(),
            )),
        }
    }
}

impl serde::Serialize for TLSNSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();

        let versioned_data = [vec![154], vec![1], bytes.to_vec()].concat();
        let b58_str = bitcoin::base58::encode_check(&versioned_data);

        serializer.serialize_str(&b58_str)
    }
}

impl<'de> serde::Deserialize<'de> for TLSNSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TLSNSignatureVisitor;

        impl<'de> Visitor<'de> for TLSNSignatureVisitor {
            type Value = TLSNSignature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string encoded in Base58")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let data = bitcoin::base58::decode_check(v).map_err(E::custom)?;

                // Validate version byte
                if data[0] != 154 {
                    return Err(E::custom("Invalid version byte"));
                }

                let bytes = &data[2..];

                // The rest of the deserialization logic remains the same
                let (rx_bytes, s_bytes) = bytes.split_at(32);

                if let Ok(rx) = BaseField::from_bytes(rx_bytes) {
                    if let Ok(s) = ScalarField::from_bytes(s_bytes) {
                        println!(
                            "rx: {:?}, s: {:?}",
                            rx.to_biguint(),
                            s.to_biguint()
                        );
                        let sig = mina_signer::Signature { rx, s };
                        return Ok(TLSNSignature::MinaSchnorr(sig));
                    }
                }

                let sig = p256::ecdsa::Signature::from_bytes(GenericArray::from_slice(bytes))
                    .map_err(|e| E::custom(format!("Invalid P256 signature: {}", e)))?;
                Ok(TLSNSignature::P256(sig))
            }
        }

        deserializer.deserialize_str(TLSNSignatureVisitor)
    }
}
