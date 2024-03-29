use std::{str, sync::Arc};

use elliptic_curve::pkcs8::DecodePrivateKey;
use futures::{AsyncRead, AsyncWrite};
use http_body_util::{BodyExt as _, Either, Empty, Full};
use hyper::{client::conn::http1::Parts, Request, StatusCode};
use hyper_util::rt::TokioIo;
use mina_signer::SecKey;
use notary_server::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse, TLSNSigningKeyTypeNames};
use rustls::{Certificate, ClientConfig, RootCertStore};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::bytes::Bytes;
use tracing::debug;

use tlsn_core::{signature::TLSNSignature, NotaryPublicKey};

use elliptic_curve::pkcs8::DecodePublicKey;
use mina_signer::PubKey;


use notary_server::TLSNSigningKey;

/// Runs a simple Notary with the provided connection to the Prover, like `run_notary` but with an extra arg which allows you to specify the signing key type.
pub async fn run_notary_full<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    conn: T,
    signing_key_type: TLSNSigningKeyTypeNames,
) {
    // Load the notary signing key
    let signing_key = match signing_key_type {
        TLSNSigningKeyTypeNames::P256 => {
            let signing_key_str = std::str::from_utf8(include_bytes!(
                "../../../notary-server/fixture/notary/notary.key"
            ))
            .unwrap();
            let p256_signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(signing_key_str).unwrap();

            TLSNSigningKey::from(p256_signing_key)
        }
        TLSNSigningKeyTypeNames::MinaSchnorr => {
            let signing_key_str = std::str::from_utf8(
                include_bytes!("../../../notary-server/fixture/schnorr/notary.key"),
            )
            .unwrap();

            let signing_key_schnorr = SecKey::from_base58(signing_key_str).unwrap();

            TLSNSigningKey::from(signing_key_schnorr)
        }
    };

    

    // Setup default config. Normally a different ID would be generated
    // for each notarization.
    let config = VerifierConfig::builder().id("example").build().unwrap();

    Verifier::new(config)
        .notarize::<_, TLSNSignature>(conn, &signing_key)
        .await
        .unwrap();

}


/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    conn: T,
) {
    // Load the notary signing key

    let signing_key_str = std::str::from_utf8(include_bytes!(
        "../../../notary-server/fixture/notary/notary.key"
    ))
    .unwrap();
    let p256_signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(signing_key_str).unwrap();

    let signing_key = TLSNSigningKey::P256(p256_signing_key);

    // Setup default config. Normally a different ID would be generated
    // for each notarization.
    let config = VerifierConfig::builder().id("example").build().unwrap();

    Verifier::new(config)
        .notarize::<_, TLSNSignature>(conn, &signing_key)
        .await
        .unwrap();
}

/// Requests notarization from the Notary server.
pub async fn request_notarization(
    host: &str,
    port: u16,
    max_transcript_size: Option<usize>,
) -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    // Connect to the Notary via TLS-TCP
    let pem_file = std::str::from_utf8(include_bytes!(
        "../../../notary-server/fixture/tls/rootCA.crt"
    ))
    .unwrap();
    let mut reader = std::io::BufReader::new(pem_file.as_bytes());
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_store = RootCertStore::empty();
    root_store.add(&certificate).unwrap();

    let client_notary_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

    let notary_socket = tokio::net::TcpStream::connect((host, port)).await.unwrap();

    let notary_tls_socket = notary_connector
        // Require the domain name of notary server to be the same as that in the server cert
        .connect("tlsnotaryserver.io".try_into().unwrap(), notary_socket)
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection to send request to the /session endpoint to configure notarization and obtain session id
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(notary_tls_socket))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Tcp,
        max_transcript_size,
    })
    .unwrap();

    let request = Request::builder()
        .uri(format!("https://{host}:{port}/session"))
        .method("POST")
        .header("Host", host)
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Either::Left(Full::new(Bytes::from(payload))))
        .unwrap();

    debug!("Sending configuration request");

    let configuration_response = request_sender.send_request(request).await.unwrap();

    debug!("Sent configuration request");

    assert!(configuration_response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = configuration_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
    let request = Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .uri(format!(
            "https://{host}:{port}/notarize?sessionId={}",
            notarization_response.session_id.clone()
        ))
        .method("GET")
        .header("Host", host)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        .body(Either::Right(Empty::<Bytes>::new()))
        .unwrap();

    debug!("Sending notarization request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent notarization request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    debug!("Switched protocol OK");

    // Claim back the TLS socket after HTTP exchange is done
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

    (
        notary_tls_socket.into_inner(),
        notarization_response.session_id,
    )
}

/// Returns the Notary pubkey type from the CLI args, defaults to P256
pub fn get_notary_pubkey_type(cli_args: Vec<String>) -> TLSNSigningKeyTypeNames {
    cli_args.get(1)
        .map(|sig_type| match sig_type.as_str() {
            "P256" => TLSNSigningKeyTypeNames::P256,
            "MinaSchnorr" => TLSNSigningKeyTypeNames::MinaSchnorr,
            _ => TLSNSigningKeyTypeNames::P256,
        })
        .unwrap_or(TLSNSigningKeyTypeNames::P256)
}

/// Returns the Notary pubkey from the fixture, depending on the signature type
pub fn notary_pubkey_full(signature_type: TLSNSigningKeyTypeNames) -> NotaryPublicKey {

    match signature_type {
        TLSNSigningKeyTypeNames::P256 => {
            let pem_file = str::from_utf8(include_bytes!(
                "../../../notary-server/fixture/notary/notary.pub"
            ))
            .unwrap();
            let pub_key_p256 = p256::PublicKey::from_public_key_pem(pem_file).unwrap();

            NotaryPublicKey::P256(pub_key_p256)
        }
        TLSNSigningKeyTypeNames::MinaSchnorr => {
            let pub_key_str = str::from_utf8(include_bytes!(
                "../../../notary-server/fixture/schnorr/notary.pub"
            )).unwrap();

            let pub_key_schnorr = PubKey::from_address(pub_key_str).unwrap();

            NotaryPublicKey::MinaSchnorr(pub_key_schnorr)
        }
    }
}