//! Signature Mod

use mina_hasher::{Hashable, ROInput};
use mina_signer::{BaseField, NetworkId, PubKey, ScalarField, Signer};
use o1_utils::FieldHelpers;
use p256::{
    ecdsa::{signature::Verifier, VerifyingKey},
    elliptic_curve::generic_array::GenericArray,
};

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use bitcoin;
use serde::de::Error;
use std::{fmt, fmt::Formatter};

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

/// Wrapper around the mina_signer::Signature type to allow for custom serialization.
#[derive(Debug, Clone)]
pub struct MinaSchnorrSignature(pub mina_signer::Signature);

impl Serialize for MinaSchnorrSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(BaseField::size_in_bytes() * 2);

        let rx_bytes = self.0.rx.to_bytes();
        let s_bytes = self.0.s.to_bytes();

        bytes.extend_from_slice(&rx_bytes);
        bytes.extend_from_slice(&s_bytes);

        let versioned_data = [vec![154], vec![1], bytes.to_vec()].concat();
        let b58_str = bitcoin::base58::encode_check(&versioned_data);

        serializer.serialize_str(&b58_str)
    }
}

impl<'de> serde::Deserialize<'de> for MinaSchnorrSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MinaSchnorrSignatureVisitor;

        impl<'de> Visitor<'de> for MinaSchnorrSignatureVisitor {
            type Value = MinaSchnorrSignature;

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

                let (rx_bytes, s_bytes) = bytes.split_at(32);

                if let Ok(rx) = BaseField::from_bytes(rx_bytes) {
                    if let Ok(s) = ScalarField::from_bytes(s_bytes) {
                        println!("rx: {:?}, s: {:?}", rx.to_biguint(), s.to_biguint());
                        let sig = mina_signer::Signature { rx, s };
                        return Ok(MinaSchnorrSignature(sig));
                    } else {
                        return Err(E::custom("Invalid MinaSchnorr signature s bytes"));
                    }
                } else {
                    return Err(E::custom("Invalid MinaSchnorr signature rx bytes"));
                }
            }
        }

        deserializer.deserialize_str(MinaSchnorrSignatureVisitor)
    }
}

/// A Notary signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TLSNSignature {
    /// A Mina-Schnorr signature.
    MinaSchnorr(MinaSchnorrSignature),
    /// A secp256r1 signature.
    P256(p256::ecdsa::Signature),
}

impl From<mina_signer::Signature> for TLSNSignature {
    fn from(sig: mina_signer::Signature) -> Self {
        Self::MinaSchnorr(MinaSchnorrSignature(sig))
    }
}

impl From<p256::ecdsa::Signature> for TLSNSignature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        Self::P256(sig)
    }
}

/// Data Struct
#[derive(Clone)]
pub enum Data {
    /// Mina data
    Mina(Vec<BaseField>),
    /// P256 data
    P256(Vec<u8>),
}

impl Data {
    /// Returns a reference to the byte array if the data is of the P256 variant.
    pub fn to_array(&self) -> &[u8] {
        match self {
            Data::P256(data) => data,
            Data::Mina(_) => panic!("to_array is not applicable for Mina variant"),
        }
    }

    /// Returns the data as a byte array.
    pub fn from(data: &[u8]) -> Self {
        let mina_data: Vec<BaseField> = data.iter().map(|&byte| BaseField::from(byte)).collect();

        Data::Mina(mina_data)
    }
}

impl Hashable for Data {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        match self {
            Data::Mina(fields) => {
                let mut ro_input = ROInput::new();

                for field in fields {
                    ro_input = ro_input.append_field(*field);
                }

                ro_input
            }
            Data::P256(_) => panic!("to_roinput is not applicable for P256 variant"),
        }
    }

    fn domain_string(network_id: NetworkId) -> Option<String> {
        match network_id {
            NetworkId::MAINNET => "MinaSignatureMainnet".to_string().into(),
            NetworkId::TESTNET => "CodaSignature".to_string().into(),
        }
    }
}

impl TLSNSignature {
    /// Returns the bytes of this signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::MinaSchnorr(MinaSchnorrSignature(sig)) => {
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
        msg: &Data,
        notary_public_key: impl Into<NotaryPublicKey>,
    ) -> Result<(), SignatureVerifyError> {
        match (self, notary_public_key.into()) {
            (Self::MinaSchnorr(MinaSchnorrSignature(sig)), NotaryPublicKey::MinaSchnorr(key)) => {
                let mut ctx = mina_signer::create_kimchi(NetworkId::TESTNET);
                if ctx.verify(&sig, &key, msg) {
                    Ok(())
                } else {
                    Err(SignatureVerifyError(
                        "Signature verification failed".to_string(),
                    ))
                }
            }
            (Self::P256(sig), NotaryPublicKey::P256(key)) => VerifyingKey::from(key)
                .verify(msg.to_array(), sig)
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
