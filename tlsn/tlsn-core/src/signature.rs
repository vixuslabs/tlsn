//! Signature Mod

use mina_hasher::{Hashable, ROInput};
use mina_signer::{
    keypair::Keypair, NetworkId, SecKey, Signature as MinaSignature, Signer as MinaSigner,
};
use mina_signer::{BaseField, PubKey, ScalarField};
use o1_utils::FieldHelpers;
use p256::{
    ecdsa::{signature::Verifier, VerifyingKey},
    elliptic_curve::generic_array::GenericArray,
    pkcs8::DecodePrivateKey,
};
use serde::{
    de::{self, Visitor},
    Deserializer,
};
use serde::{Deserialize, Serialize};

use bitcoin;
use serde::de::Error;
use std::fmt;

use signature::Signer;

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
#[derive(Clone, Debug)]
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
            Data::Mina(data) => {

                panic!("to_array is not applicable for Mina variant")
            },
        }
    }

    /// Converts a byte array to a Mina data variant.
    pub fn to_base_field(data: &[u8]) -> Self {
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
        msg: &Data,
        notary_public_key: impl Into<NotaryPublicKey>,
    ) -> Result<(), SignatureVerifyError> {
        match (self, notary_public_key.into()) {
            (Self::MinaSchnorr(sig), NotaryPublicKey::MinaSchnorr(key)) => {

                println!("MinaSchnorr - msg: {:?}", msg);

                let mut ctx = mina_signer::create_kimchi(NetworkId::TESTNET);
                if ctx.verify(&sig, &key, msg) {
                    Ok(())
                } else {
                    Err(SignatureVerifyError(
                        "Signature verification failed".to_string(),
                    ))
                }
            }
            (Self::P256(sig), NotaryPublicKey::P256(key)) => {
                println!(" P256 - msg: {:?}", msg);

                VerifyingKey::from(key)
                .verify(msg.to_array(), sig)
                .map_err(|e| SignatureVerifyError(e.to_string()))
            },
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
                        println!("rx: {:?}, s: {:?}", rx.to_biguint(), s.to_biguint());
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

/// Signing key type names.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TLSNSigningKeyTypeNames {
    /// Mina Schnorr key.
    MinaSchnorr,
    /// P256 key.
    P256,
}

/// A Signing Key which can be either a Mina Schnorr key or a P256 key.
#[derive(Clone, Debug)]
pub enum TLSNSigningKey {
    /// A Mina Schnorr signing key.
    MinaSchnorr(SecKey),
    /// A P256 signing key.
    P256(p256::ecdsa::SigningKey),
}

impl From<mina_signer::seckey::SecKey> for TLSNSigningKey {
    fn from(key: SecKey) -> Self {
        Self::MinaSchnorr(key)
    }
}

impl From<p256::ecdsa::SigningKey> for TLSNSigningKey {
    fn from(key: p256::ecdsa::SigningKey) -> Self {
        Self::P256(key)
    }
}

impl TLSNSigningKey {
    /// Reads a randomly generated Mina Schnorr key.
    pub fn read_default_schnorr_pem_file() -> Self {
        Self::MinaSchnorr(SecKey::from_bytes(&[0u8; 32]).unwrap())
    }

    /// Reads a Mina Schnorr key from a PEM file.
    pub fn read_schnorr_pem_file(path: &str) -> Result<Self, ()> {
        Ok(Self::MinaSchnorr(
            SecKey::from_base58("EKFSmntAEAPm5CnYMsVpfSEuyNfbXfxy2vHW8HPxGyPPgm5xyRtN").unwrap(),
        ))
    }

    /// Reads a P256 key from a PEM file.
    pub fn read_p256_pem_file(path: &str) -> Result<Self, eyre::Error> {
        let signing_key = p256::ecdsa::SigningKey::read_pkcs8_pem_file(path)
            .map_err(|err| eyre::eyre!("Failed to parse P256 PEM file: {}", err))?;

        Ok(Self::P256(signing_key))

        // let signing_key_str = std::fs::read_to_string(DEFAULT_PEM_PATH)
        // .map_err(|_| ())?;

        // Ok(Self::P256(p256::ecdsa::SigningKey::read_pkcs8_pem_file(signing_key_str).unwrap()))

        // Ok(Self::P256(p256::ecdsa::SigningKey::read_pkcs8_pem_file(path).unwrap()))
    }

    /// Returns a TLSNSigningKey from a byte array.
    pub fn from_bytes(bytes: &[u8], to: TLSNSigningKeyTypeNames) -> Result<Self, ()> {
        let key = p256::ecdsa::SigningKey::from_bytes(bytes.into()).unwrap();

        Ok(Self::P256(key))
    }
}

/// Sign the provided message bytestring using `Self` (e.g. a cryptographic key
/// or connection to an HSM), returning a digital signature.
impl Signer<TLSNSignature> for TLSNSigningKey {
    fn sign(&self, msg: &[u8]) -> TLSNSignature {
        self.try_sign(msg).expect("signature operation failed")
    }

    fn try_sign(&self, msg: &[u8]) -> Result<TLSNSignature, signature::Error> {
        match self {
            TLSNSigningKey::MinaSchnorr(sk) => {
                let mut ctx = mina_signer::create_kimchi::<Data>(NetworkId::TESTNET);
                let key_pair =
                    Keypair::from_secret_key(sk.clone()).map_err(|_| signature::Error::new())?;
                let sig = ctx.sign(&key_pair, &Data::to_base_field(msg));
                Ok(TLSNSignature::MinaSchnorr(sig))
            }
            TLSNSigningKey::P256(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(TLSNSignature::P256(sig))
            }
        }
    }
}
