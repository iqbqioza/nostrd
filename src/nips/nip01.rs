//! NIP-01: Basic Protocol Flow.
//!
//! Event format, canonical serialization, id computation and Schnorr
//! signature verification, plus the regular replaceable event range.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::event::Event;

pub const ID_BYTES: usize = 32;
pub const PK_BYTES: usize = 32;
pub const SIG_BYTES: usize = 64;

/// Canonical serialization of an event without the `id` and `sig` fields.
pub fn canonical_payload(event: &Event) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
    ]))
    .expect("canonical serialization cannot fail")
}

pub fn compute_id(event: &Event) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_payload(event));
    hex::encode(hasher.finalize())
}

/// Verifies the event id and the Schnorr signature.
pub fn verify(event: &Event, secp: &Secp256k1<secp256k1::All>) -> Result<()> {
    if event.id.len() != ID_BYTES * 2
        || event.pubkey.len() != PK_BYTES * 2
        || event.sig.len() != SIG_BYTES * 2
    {
        return Err(Error::Protocol("invalid id/pubkey/sig length".into()));
    }
    if compute_id(event) != event.id {
        return Err(Error::Protocol("invalid event id".into()));
    }
    let id_bytes: [u8; ID_BYTES] = event
        .id_bytes()
        .ok_or_else(|| Error::Protocol("invalid id hex".into()))?;
    let pk = XOnlyPublicKey::from_slice(&hex::decode(&event.pubkey)?)?;
    let sig = Signature::from_slice(&hex::decode(&event.sig)?)?;
    secp.verify_schnorr(&sig, &id_bytes, &pk)?;
    Ok(())
}

/// Signs an event with the given keypair: computes the id and the Schnorr
/// signature. Used by the relay for NIP-29 relay-generated events.
pub fn sign(event: &mut Event, keypair: &Keypair, secp: &Secp256k1<secp256k1::All>) -> Result<()> {
    event.id = compute_id(event);
    let id: [u8; ID_BYTES] = event
        .id_bytes()
        .ok_or_else(|| Error::Protocol("invalid id".into()))?;
    let mut aux = [0u8; 32];
    getrandom::getrandom(&mut aux).map_err(|_| Error::Protocol("rng failure".into()))?;
    event.sig = secp
        .sign_schnorr_with_aux_rand(&id, keypair, &aux)
        .to_string();
    Ok(())
}

/// Regular replaceable event kinds (NIP-01): kinds 0 and 3, plus 10000-19999.
pub fn is_replaceable_kind(kind: u64) -> bool {
    kind == 0 || kind == 3 || (10000..20000).contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> Event {
        Event {
            id: "4b5e47d19a5f6a4a1a4f1f2a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c".into(),
            pubkey: "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d".into(),
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![],
            content: "hello".into(),
            sig: "7f3a4c1e9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d".into(),
        }
    }

    #[test]
    fn canonical_payload_is_stable() {
        let ev = sample_event();
        assert_eq!(
            canonical_payload(&ev),
            b"[0,\"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d\",1600000000,1,[],\"hello\"]"
        );
    }

    #[test]
    fn replaceable_ranges() {
        assert!(is_replaceable_kind(0));
        assert!(is_replaceable_kind(3));
        assert!(is_replaceable_kind(10000));
        assert!(is_replaceable_kind(19999));
        assert!(!is_replaceable_kind(20000));
        assert!(!is_replaceable_kind(30023));
        assert!(!is_replaceable_kind(1));
    }

    #[test]
    fn signature_verification_roundtrip() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut event = Event {
            id: String::new(),
            pubkey,
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![],
            content: "signed message".into(),
            sig: String::new(),
        };
        sign(&mut event, &keypair, &secp).unwrap();
        assert_eq!(event.id.len(), 64);
        assert_eq!(event.sig.len(), 128);
        assert!(verify(&event, &secp).is_ok());

        // Tampering with the content invalidates the id.
        let mut tampered = event.clone();
        tampered.content = "tampered".into();
        assert!(verify(&tampered, &secp).is_err());

        // Tampering with the signature is caught by schnorr verification.
        let mut bad_sig = event.clone();
        bad_sig.sig = "1".repeat(128);
        assert!(verify(&bad_sig, &secp).is_err());

        // A signature from a different key fails.
        let other = Keypair::from_seckey_slice(&secp, &[9u8; 32]).unwrap();
        let mut forged = event.clone();
        sign(&mut forged, &other, &secp).unwrap();
        forged.pubkey = event.pubkey.clone();
        assert!(verify(&forged, &secp).is_err());
    }
}
