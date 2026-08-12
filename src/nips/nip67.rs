//! NIP-67: EOSE Completeness Hint.
//!
//! The relay appends a hint array to `EOSE` messages: `["EOSE", sub, ["finish"]]`
//! when every matching stored event was delivered, or `["EOSE", sub, ["more"]]`
//! when a limit stopped the scan early. The `more` flag is computed by the
//! database scan (`db::scan`) and the message is built in `ws::handle_req`;
//! this module exists to document the NIP.
