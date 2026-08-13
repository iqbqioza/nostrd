//! NIP-98: HTTP Auth.
//!
//! Verifies NIP-98 HTTP auth events (`kind:27235` events sent in the
//! `Authorization: Nostr <base64 event>` header), shared by the NIP-86
//! management API and the NIP-29 LiveKit token endpoint.

use base64::Engine;
use secp256k1::Secp256k1;

use crate::event::Event;
use crate::nips::nip01;
use crate::stats::unix_now;

pub const AUTH_KIND: u64 = 27235;
pub const PAYLOAD_TAG: &str = "payload";
pub const URL_TAG: &str = "u";
pub const METHOD_TAG: &str = "method";

/// Verifies an encoded NIP-98 event. When `expected_pubkey` is given the
/// event must be authored by it; when `require_payload` is set the event
/// must carry a `payload` tag (NIP-86 requires it); the `u` tag value is
/// checked with `url_matches` and the `method` tag must equal the HTTP
/// method of the request (NIP-98 requirement 4).
pub async fn verify(
    encoded: &str,
    expected_pubkey: Option<&str>,
    secp: &Secp256k1<secp256k1::All>,
    require_payload: bool,
    method: &str,
    url_matches: impl Fn(&str) -> bool,
) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let event: Event = serde_json::from_slice(&raw).ok()?;
    if event.kind != AUTH_KIND {
        return None;
    }
    if let Some(expected) = expected_pubkey
        && event.pubkey != expected
    {
        return None;
    }
    let now = unix_now();
    if event.created_at.abs_diff(now) > 60 {
        return None;
    }
    let url_ok = event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == URL_TAG && url_matches(&t[1]));
    if !url_ok {
        return None;
    }
    let method_ok = event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == METHOD_TAG && t[1] == method);
    if !method_ok {
        return None;
    }
    if require_payload {
        let has_payload = event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == PAYLOAD_TAG);
        if !has_payload {
            return None;
        }
    }
    if nip01::verify(&event, secp).is_err() {
        return None;
    }
    Some(event.pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nips::nip01::compute_id;
    use secp256k1::{Keypair, XOnlyPublicKey};

    fn signed_event(method: Option<&str>, url: &str, created: u64) -> Event {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut tags = vec![vec![URL_TAG.into(), url.into()]];
        if let Some(m) = method {
            tags.push(vec![METHOD_TAG.into(), m.into()]);
        }
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: AUTH_KIND,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    fn encode(ev: &Event) -> String {
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(ev).unwrap())
    }

    #[test]
    fn method_tag_must_match() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let secp = Secp256k1::new();
        let now = unix_now();
        rt.block_on(async {
            // Correct method and url: accepted.
            let ev = signed_event(Some("POST"), "https://relay.example.com/", now);
            assert!(
                verify(&encode(&ev), None, &secp, false, "POST", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_some()
            );
            // Wrong method: rejected (NIP-98 requirement 4).
            assert!(
                verify(&encode(&ev), None, &secp, false, "GET", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_none()
            );
            // Missing method tag: rejected.
            let bare = signed_event(None, "https://relay.example.com/", now);
            assert!(
                verify(&encode(&bare), None, &secp, false, "POST", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_none()
            );
        });
    }
}
