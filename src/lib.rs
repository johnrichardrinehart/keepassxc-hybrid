//! Answer a WebAuthn hybrid ("use your phone") QR code with KeePassXC.
//!
//! The QR code makes this machine the authenticator a phone would be: it
//! advertises over Bluetooth LE, meets the browser at a caBLE tunnel server,
//! and passes the browser's request to KeePassXC, which asks the user which
//! entry gets (or provides) the passkey.

pub mod advertiser;
pub mod backend;
pub mod keepassxc;
pub mod qr;
