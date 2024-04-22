use std::{str, time::Duration, env};

use elliptic_curve::pkcs8::DecodePublicKey;

use mina_signer::PubKey;
use notary_server::TLSNSigningKeyTypeNames;
use tlsn_core::proof::{SessionProof, TlsProof};

use tlsn_core::signature::NotaryPublicKey;
use tlsn_examples::{get_notary_pubkey_type, notary_pubkey_full};

/// A simple verifier which reads a proof generated by `simple_prover.rs` from "proof.json", verifies
/// it and prints the verified data to the console.
fn main() {
    let cli_args: Vec<String> = env::args().collect();

    // let sig_type = if let Some(sig_type) = cli_args.get(1) {
    //     match sig_type.as_str() {
    //         "P256" => TLSNSigningKeyTypeNames::P256,
    //         "MinaSchnorr" => TLSNSigningKeyTypeNames::MinaSchnorr,
    //         // Defaults to P256
    //         _ => TLSNSigningKeyTypeNames::P256,
    //     }
    // } else {
    //     TLSNSigningKeyTypeNames::P256
    // };

    let sig_type = get_notary_pubkey_type(cli_args);

    println!("Verifying proof with {:?}", sig_type);

    // Deserialize the proof
    let proof = std::fs::read_to_string("simple_proof.json").unwrap();
    let proof: TlsProof = serde_json::from_str(proof.as_str()).unwrap();

    println!("Proof deserialized successfully.");

    let TlsProof {
        // The session proof establishes the identity of the server and the commitments
        // to the TLS transcript.
        session,
        // The substrings proof proves select portions of the transcript, while redacting
        // anything the Prover chose not to disclose.
        substrings,
    } = proof;


    // Verify the session proof against the Notary's public key
    //
    // This verifies the identity of the server using a default certificate verifier which trusts
    // the root certificates from the `webpki-roots` crate.
    session
        .verify_with_default_cert_verifier(notary_pubkey_full(sig_type))
        .unwrap();

    println!("Session proof verified successfully.");

    let SessionProof {
        // The session header that was signed by the Notary is a succinct commitment to the TLS transcript.
        header,
        // This is the session_info, which contains the server_name, that is checked against the
        // certificate chain shared in the TLS handshake.
        session_info,
        ..
    } = session;

    // The time at which the session was recorded
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(header.time());

    // Verify the substrings proof against the session header.
    //
    // This returns the redacted transcripts
    let (mut sent, mut recv) = substrings.verify(&header).unwrap();

    println!("Substrings proof verified successfully.");

    // Replace the bytes which the Prover chose not to disclose with 'X'
    sent.set_redacted(b'X');
    recv.set_redacted(b'X');

    println!("-------------------------------------------------------------------");
    println!(
        "Successfully verified that the bytes below came from a session with {:?} at {}.",
        session_info.server_name, time
    );
    println!("Note that the bytes which the Prover chose not to disclose are shown as X.");
    println!();
    println!("Bytes sent:");
    println!();
    print!("{}", String::from_utf8(sent.data().to_vec()).unwrap());
    println!();
    println!("Bytes received:");
    println!();
    println!("{}", String::from_utf8(recv.data().to_vec()).unwrap());
    println!("-------------------------------------------------------------------");
}

/// Returns a Notary pubkey trusted by this Verifier
/// Returns a Notary pubkey trusted by this Verifier
fn notary_pubkey() -> p256::PublicKey {
    let pem_file = str::from_utf8(include_bytes!(
        "../../../notary-server/fixture/notary/notary.pub"
    ))
    .unwrap();
    p256::PublicKey::from_public_key_pem(pem_file).unwrap()
}