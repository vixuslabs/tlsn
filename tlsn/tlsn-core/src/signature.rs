//! Signature Mod

use mina_hasher::{DomainParameter, Hashable, ROInput};
use mina_signer::{
    BaseField, Keypair, NetworkId, PubKey, ScalarField, Signer, SecKey
};
use o1_utils::FieldHelpers;
use p256::{ecdsa::{signature::Verifier, VerifyingKey}, elliptic_curve::generic_array::GenericArray};
use serde::{Deserialize, Serialize};

/// A Notary public key.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NotaryPublicKey {
    /// A Mina-compatible public key.
    MinaSchnorr(PubKey),
    /// A NIST P-256 public key.
    P256(p256::PublicKey),
}

impl NotaryPublicKey {
    /// Returns the bytes of this public key.
    pub fn from_public_key_pem() -> Self {
        const PUB_KEY: &str = "B62qowWuY2PsBZsm64j4Uu2AB3y4L6BbHSvtJcSLcsVRXdiuycbi8Ws";
        let t = PubKey::from_address(PUB_KEY).unwrap();
        Self::MinaSchnorr(t)
    }
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
#[derive(Clone)]
pub struct Data(pub Vec<u8>);

impl Data {
    /// to_array method
    pub fn to_array(&self) -> &[u8] {
        &self.0
    }

    /// from method
    pub fn from(data: &[u8]) -> Self {
        Self(data.to_vec())
    }
}

impl Hashable for Data {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        ROInput::new().append_bytes(&self.0)
    }

    fn domain_string(_: Self::D) -> Option<String> {
        None
    }
}

impl TLSNSignature {
    /// Returns the bytes of this signature.
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        match self {
            Self::MinaSchnorr(sig) => (sig.rx.to_bytes(), sig.s.to_bytes()),
            // Probably wrong
            Self::P256(sig) => {
                let bytes = sig.to_bytes();

                // let bytes = Vec::deserialize(deserializer)?;
                let mid = bytes.len() / 2;
                let bytes1 = bytes[..mid].to_vec();
                let bytes2 = bytes[mid..].to_vec();


                (bytes1, bytes2)
            }
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
                let mut ctx = mina_signer::create_legacy(());

                let is_valid = ctx.verify(&sig, &key, msg);
                if is_valid {
                    Ok(())
                } else {
                    Err(SignatureVerifyError(
                        "Signature verification failed".to_string(),
                    ))
                }
            },
            (Self::P256(sig), NotaryPublicKey::P256(key)) => VerifyingKey::from(key)
                .verify(msg.to_array(), sig)
                .map_err(|e| SignatureVerifyError(e.to_string())),
            (Self::MinaSchnorr(_), NotaryPublicKey::P256(_)) => Err(SignatureVerifyError(
                "3: Invalid public key type for Mina-Schnorr signature".to_string(),
            )),
            (Self::P256(sig), NotaryPublicKey::MinaSchnorr(key)) => {
                


                // let mut ctx = mina_signer::create_legacy(());

                // let is_valid = ctx.verify(&sig, &key, msg);
                // if is_valid {
                //     Ok(())
                // } else {
                //     Err(SignatureVerifyError(
                //         "Signature verification failed".to_string(),
                //     ))
                // }

                println!("self: {:?}", self);

                Err(SignatureVerifyError(
                    "4: Invalid public key type for P-256 signature".to_string(),
                ))
            },
        }
    }
}

impl serde::Serialize for TLSNSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (bytes1, bytes2) = self.to_bytes();
        let mut bytes = bytes1;
        bytes.extend(bytes2);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> serde::Deserialize<'de> for TLSNSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = Vec::<u8>::deserialize(deserializer)?;

        // Try to deserialize as MinaSchnorr signature
        if bytes.len() == 64 {
            let rx_bytes = &bytes[..32];
            let s_bytes = &bytes[32..];

            let rx = BaseField::from_bytes(rx_bytes)
                .map_err(|e| Error::custom(format!("Invalid rx: {}", e)))?;
            let s = ScalarField::from_bytes(s_bytes)
                .map_err(|e| Error::custom(format!("Invalid s: {}", e)))?;

            let sig = mina_signer::Signature { rx, s };
            return Ok(TLSNSignature::MinaSchnorr(sig));
        }

        // Try to deserialize as P256 signature
        let sig = p256::ecdsa::Signature::from_bytes(GenericArray::from_slice(&bytes))
            .map_err(|e| Error::custom(format!("Invalid P256 signature: {}", e)))?;
        Ok(TLSNSignature::P256(sig))
    }
}