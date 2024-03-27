//! Signature Mod

use mina_hasher::{DomainParameter, Hashable, ROInput};
use mina_signer::{
    BaseField, Keypair, NetworkId, PubKey, ScalarField, Signature as MinaSignature, Signer, SecKey
};
use o1_utils::FieldHelpers;
use serde::{Deserialize, Serialize};

// use p256::ecdsa::{signature::Verifier, VerifyingKey};

/// A Notary public key.

#[derive(Debug, Clone)]
#[non_exhaustive]

pub enum NotaryPublicKey {
    /// A Mina-compatible public key.
    PK(PubKey),
}

impl NotaryPublicKey {
    /// Returns the bytes of this public key.
    pub fn from_public_key_pem() -> Self {
        const PUB_KEY: &str = "B62qowWuY2PsBZsm64j4Uu2AB3y4L6BbHSvtJcSLcsVRXdiuycbi8Ws";
        let t = PubKey::from_address(PUB_KEY).unwrap();
        Self::PK(t)
    }
}

impl From<PubKey> for NotaryPublicKey {
    fn from(key: PubKey) -> Self {
        Self::PK(key)
    }

    // fn from_public_key_pem() -> Self {
    //     // let (label, doc) = Document::from_pem(s)?;
    //     // SubjectPublicKeyInfoRef::validate_pem_label(label)?;
    //     // Self::from_public_key_der(doc.as_bytes())

    //     const PUB_KEY: &str = "B62qowWuY2PsBZsm64j4Uu2AB3y4L6BbHSvtJcSLcsVRXdiuycbi8Ws";

    //     let t = PubKey::from_address(PUB_KEY).unwrap();

    //     PK(t)
    // }
}

/// An error occurred while verifying a signature.
#[derive(Debug, thiserror::Error)]
#[error("signature verification failed: {0}")]
pub struct SignatureVerifyError(String);

/// A Notary signature.
#[derive(Debug, Clone)]
#[non_exhaustive]
/// Signature Enum
pub enum Signature {
    /// A Mina-style signature.
    Mina(MinaSignature),
}

impl From<MinaSignature> for Signature {
    fn from(sig: MinaSignature) -> Self {
        Self::Mina(sig)
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

    // /// sign method
    // pub fn sign(&self, keypair: &Keypair) -> Signature {
    //     let mut ctx = mina_signer::create_legacy(());
    //     let sig = ctx.sign(keypair.secret_key(), self);
    //     Signature::Mina(sig)
    // }
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

impl Signature {
    /// Returns the bytes of this signature.
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        match self {
            Self::Mina(sig) => (sig.rx.to_bytes(), sig.s.to_bytes()),
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
        let mut ctx = mina_signer::create_legacy(());
        match (self, notary_public_key.into()) {
            (Self::Mina(sig), NotaryPublicKey::PK(key)) => {
                let is_valid = ctx.verify(&sig, &key, msg);
                if is_valid {
                    Ok(())
                } else {
                    Err(SignatureVerifyError(
                        "Signature verification failed".to_string(),
                    ))
                }
            }
        }
    }
}

impl serde::Serialize for Signature {
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

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::deserialize(deserializer)?;
        let mid = bytes.len() / 2;
        let bytes1 = bytes[..mid].to_vec();
        let bytes2 = bytes[mid..].to_vec();
        Ok(Signature::from(MinaSignature::new(
            BaseField::from_bytes(&bytes1).unwrap(),
            ScalarField::from_bytes(&bytes2).unwrap(),
        )))
    }
}
