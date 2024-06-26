use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tlsn_core::signature::TLSNSigningKey;
use tokio::sync::Mutex;

pub use crate::{
    config::NotarizationProperties, domain::auth::AuthorizationWhitelistRecord, NotaryServerError,
    NotarySigningKeyProperties,
};

/// Response object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
    /// Unique session id that is generated by notary and shared to prover
    pub session_id: String,
}

/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
    pub client_type: ClientType,
    /// Maximum transcript size in bytes
    pub max_transcript_size: Option<usize>,
}

/// Request query of the /notarize API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequestQuery {
    /// Session id that is returned from /session API
    pub session_id: String,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    /// Client that has access to the transport layer
    Tcp,
    /// Client that cannot directly access transport layer, e.g. browser extension
    Websocket,
}

/// Session configuration data to be stored in temporary storage
#[derive(Clone, Debug)]
pub struct SessionData {
    pub max_transcript_size: Option<usize>,
    pub created_at: DateTime<Utc>,
}

/// Global data that needs to be shared with the axum handlers
#[derive(Clone, Debug)]
pub struct NotaryGlobals {
    pub notary_signing_key: TLSNSigningKey,
    pub notarization_config: NotarizationProperties,
    /// A temporary storage to store configuration data, mainly used for WebSocket client
    pub store: Arc<Mutex<HashMap<String, SessionData>>>,
    /// Whitelist of API keys for authorization purpose
    pub authorization_whitelist: Option<Arc<HashMap<String, AuthorizationWhitelistRecord>>>,
}

impl NotaryGlobals {
    pub async fn new_mina(
        config: &NotarySigningKeyProperties,
        notarization_config: NotarizationProperties,
        authorization_whitelist: Option<Arc<HashMap<String, AuthorizationWhitelistRecord>>>,
    ) -> Result<Self, NotaryServerError> {
        let notary_signing_key =
            match TLSNSigningKey::read_schnorr_pem_file(&config.private_key_pem_path) {
                Ok(key) => key,
                Err(_err) => {
                    return Err(NotaryServerError::Connection(
                        "Failed to read Mina Schnorr private key".to_string(),
                    ))
                }
            };
        Ok(Self {
            notary_signing_key,
            notarization_config,
            store: Default::default(),
            authorization_whitelist,
        })
    }

    pub async fn new_p256(
        config: &NotarySigningKeyProperties,
        notarization_config: NotarizationProperties,
        authorization_whitelist: Option<Arc<HashMap<String, AuthorizationWhitelistRecord>>>,
    ) -> Result<Self, NotaryServerError> {
        let notary_signing_key =
            match TLSNSigningKey::read_p256_pem_file(&config.private_key_pem_path) {
                Ok(key) => key,
                Err(_err) => {
                    return Err(NotaryServerError::Connection(
                        "Failed to read P256 private key".to_string(),
                    ))
                }
            };
        Ok(Self {
            notary_signing_key,
            notarization_config,
            store: Default::default(),
            authorization_whitelist,
        })
    }
}

// impl NotaryGlobals {
//     pub fn new(
//         signing_key_type: SigningKeyType,
//         notarization_config: NotarizationProperties,
//         authorization_whitelist: Option<Arc<HashMap<String, AuthorizationWhitelistRecord>>>,
//     ) -> Self {
//         // let notary_signing_key = match signing_key_type {
//         //     SigningKeyType::MinaSchnorr(key) => SigningKeyType::MinaSchnorr(key),
//         //     SigningKeyType::P256(key) => SigningKeyType::P256(key),
//         // };
//        let notary_globals = match signing_key_type {
//             SigningKeyType::MinaSchnorr(key) => {

//                 NotaryGlobals {
//                     notary_signing_key: SigningKeyType::MinaSchnorr(key),
//                     notarization_config,
//                     store: Default::default(),
//                     authorization_whitelist,
//                 }

//             },
//             SigningKeyType::P256(key) => {

//                 NotaryGlobals {
//                     notary_signing_key: SigningKeyType::P256(key),
//                     notarization_config,
//                     store: Default::default(),
//                     authorization_whitelist,
//                 }
//             },
//         };

//         notary_globals

//         // Self {
//         //     notary_signing_key,
//         //     notarization_config,
//         //     store: Default::default(),
//         //     authorization_whitelist,
//         // }
//     }
// }
