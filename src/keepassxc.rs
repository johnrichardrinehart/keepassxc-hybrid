//! A client for KeePassXC's browser integration socket: the protocol
//! KeePassXC-Browser speaks, NaCl `crypto_box` messages over a Unix socket.
//!
//! Protocol: <https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md>

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use crypto_box::{
    aead::{generic_array::GenericArray, Aead},
    PublicKey, SalsaBox, SecretKey,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::{fs::OpenOptionsExt, net::UnixStream},
    path::{Path, PathBuf},
};
use tracing::{debug, info, trace};

const SOCKET_NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";
const NONCE_LEN: usize = 24;

/// Error codes from KeePassXC's `BrowserMessageBuilder.h`.
pub mod code {
    pub const DATABASE_NOT_OPENED: u32 = 1;
    pub const ACTION_CANCELLED_OR_DENIED: u32 = 6;
    pub const ASSOCIATION_FAILED: u32 = 8;
    pub const NO_LOGINS_FOUND: u32 = 15;
    pub const PASSKEYS_CREDENTIAL_IS_EXCLUDED: u32 = 21;
    pub const PASSKEYS_REQUEST_CANCELED: u32 = 22;
}

/// An error KeePassXC answered with.
#[derive(Debug)]
pub struct KeePassXcError {
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for KeePassXcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeePassXC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for KeePassXcError {}

/// The record of one database's approval of this client: KeePassXC stores
/// `key` under `id` in the database when the user approves `associate`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Association {
    pub id: String,
    /// Base64 identification public key. Anyone holding it can talk to the
    /// database as this client, so the file holding it is private.
    pub key: String,
}

pub struct Client {
    stream: UnixStream,
    incoming: serde_json::StreamDeserializer<'static, serde_json::de::IoRead<UnixStream>, Value>,
    client_id: String,
    session_secret: SecretKey,
    host_box: SalsaBox,
    associations: Vec<Association>,
    store: PathBuf,
}

impl Client {
    /// Connects to the running KeePassXC and exchanges session keys.
    /// `store` is the file that keeps the associations between runs.
    pub fn connect(store: PathBuf) -> Result<Self> {
        let path = socket_path()?;
        let stream = UnixStream::connect(&path).with_context(|| {
            format!(
                "connecting to KeePassXC at {}; is KeePassXC running, with \
                 Settings > Browser Integration > Enable browser integration on?",
                path.display()
            )
        })?;
        let incoming = serde_json::Deserializer::from_reader(stream.try_clone()?).into_iter();

        let session_secret = SecretKey::generate(&mut OsRng);
        let client_id = STANDARD.encode(random::<NONCE_LEN>());

        let mut client = Self {
            stream,
            incoming,
            client_id,
            host_box: SalsaBox::new(&session_secret.public_key(), &session_secret),
            session_secret,
            associations: load_associations(&store)?,
            store,
        };
        client.change_public_keys()?;
        Ok(client)
    }

    fn change_public_keys(&mut self) -> Result<()> {
        let nonce = random::<NONCE_LEN>();
        self.send(&json!({
            "action": "change-public-keys",
            "publicKey": STANDARD.encode(self.session_secret.public_key().as_bytes()),
            "nonce": STANDARD.encode(nonce),
            "clientID": self.client_id,
        }))?;
        let reply = self.receive("change-public-keys")?;
        let host_key = reply
            .get("publicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KeePassXC sent no public key: {reply}"))?;
        let host_key: [u8; 32] = STANDARD
            .decode(host_key)?
            .try_into()
            .map_err(|_| anyhow!("KeePassXC public key is not 32 bytes"))?;
        self.host_box = SalsaBox::new(&PublicKey::from(host_key), &self.session_secret);
        Ok(())
    }

    /// Makes sure the open database knows this client, asking KeePassXC to
    /// unlock it and the user to approve a new association as needed.
    pub fn ensure_associated(&mut self) -> Result<()> {
        let mut known = Vec::new();
        for association in self.associations.clone() {
            let message =
                json!({ "action": "test-associate", "id": association.id, "key": association.key });
            match self.request("test-associate", message) {
                Ok(_) => known.push(association),
                Err(e) if is_code(&e, code::ASSOCIATION_FAILED) => {
                    debug!(
                        id = association.id,
                        "association not known to the open database"
                    )
                }
                Err(e) => return Err(e),
            }
        }
        if !known.is_empty() {
            // Only the associations the open database knows identify this
            // client; the rest belong to other databases and stay stored.
            self.associations = known;
            return Ok(());
        }

        info!("asking KeePassXC to approve this client (name it, e.g. keepassxc-hybrid)");
        let id_key = STANDARD.encode(SecretKey::generate(&mut OsRng).public_key().as_bytes());
        let reply = self.request(
            "associate",
            json!({
                "action": "associate",
                "key": STANDARD.encode(self.session_secret.public_key().as_bytes()),
                "idKey": id_key,
            }),
        )?;
        let id = reply
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KeePassXC approved the association but sent no id"))?;
        let association = Association {
            id: id.to_string(),
            key: id_key,
        };

        let mut stored = load_associations(&self.store)?;
        stored.push(association.clone());
        save_associations(&self.store, &stored)?;
        self.associations = vec![association];
        Ok(())
    }

    /// Registers a passkey. KeePassXC asks the user where to store it.
    /// Returns the WebAuthn `PublicKeyCredential` JSON.
    pub fn passkeys_register(
        &mut self,
        public_key: Value,
        origin: &str,
        group: Option<&str>,
    ) -> Result<Value> {
        let mut message = json!({
            "action": "passkeys-register",
            "publicKey": public_key,
            "origin": origin,
            "keys": self.keys(),
        });
        if let Some(group) = group {
            message["groupName"] = json!(group);
        }
        passkey_response(self.request("passkeys-register", message)?)
    }

    /// Signs an assertion with a stored passkey the user picks.
    /// Returns the WebAuthn `PublicKeyCredential` JSON.
    pub fn passkeys_get(&mut self, public_key: Value, origin: &str) -> Result<Value> {
        let message = json!({
            "action": "passkeys-get",
            "publicKey": public_key,
            "origin": origin,
            "keys": self.keys(),
        });
        passkey_response(self.request("passkeys-get", message)?)
    }

    fn keys(&self) -> Value {
        Value::Array(
            self.associations
                .iter()
                .map(|a| json!({ "id": a.id, "key": a.key }))
                .collect(),
        )
    }

    /// Sends an encrypted request and returns the decrypted reply. A locked
    /// database makes KeePassXC show its unlock dialog; the request is sent
    /// again once the database is unlocked.
    fn request(&mut self, action: &str, message: Value) -> Result<Value> {
        loop {
            match self.request_once(action, &message) {
                Err(e) if is_code(&e, code::DATABASE_NOT_OPENED) => {
                    info!("waiting for the KeePassXC database to be unlocked");
                    self.wait_for_unlock()?;
                }
                result => return result,
            }
        }
    }

    fn request_once(&mut self, action: &str, message: &Value) -> Result<Value> {
        let nonce = random::<NONCE_LEN>();
        let ciphertext = self
            .host_box
            .encrypt(
                GenericArray::from_slice(&nonce),
                message.to_string().as_bytes(),
            )
            .map_err(|_| anyhow!("encrypting the {action} request"))?;
        self.send(&json!({
            "action": action,
            "message": STANDARD.encode(ciphertext),
            "nonce": STANDARD.encode(nonce),
            "clientID": self.client_id,
            "triggerUnlock": "true",
        }))?;

        let reply = self.receive(action)?;
        let reply_nonce = reply
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KeePassXC reply has no nonce: {reply}"))?;
        let reply_nonce = STANDARD.decode(reply_nonce)?;
        if reply_nonce != increment(nonce) {
            bail!("KeePassXC reply nonce does not follow the request nonce");
        }
        let ciphertext = reply
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KeePassXC reply has no message: {reply}"))?;
        let plaintext = self
            .host_box
            .decrypt(
                GenericArray::from_slice(&reply_nonce),
                STANDARD.decode(ciphertext)?.as_slice(),
            )
            .map_err(|_| anyhow!("decrypting the KeePassXC {action} reply"))?;
        let reply: Value = serde_json::from_slice(&plaintext)?;
        if reply.get("success").and_then(Value::as_str) != Some("true") {
            return Err(error_from(&reply).into());
        }
        Ok(reply)
    }

    fn send(&mut self, message: &Value) -> Result<()> {
        trace!(%message, "to KeePassXC");
        self.stream
            .write_all(message.to_string().as_bytes())
            .context("writing to the KeePassXC socket")
    }

    /// Reads messages until the reply to `action`. KeePassXC also pushes
    /// signals (`database-locked`, …) that are skipped here.
    fn receive(&mut self, action: &str) -> Result<Value> {
        loop {
            let message = self.next_message()?;
            if message.get("action").and_then(Value::as_str) != Some(action) {
                debug!(%message, "skipping KeePassXC message");
                continue;
            }
            if message.get("errorCode").is_some() {
                return Err(error_from(&message).into());
            }
            return Ok(message);
        }
    }

    fn wait_for_unlock(&mut self) -> Result<()> {
        loop {
            let message = self.next_message()?;
            if message.get("action").and_then(Value::as_str) == Some("database-unlocked") {
                return Ok(());
            }
        }
    }

    fn next_message(&mut self) -> Result<Value> {
        let message = self
            .incoming
            .next()
            .ok_or_else(|| anyhow!("KeePassXC closed the connection"))?
            .context("reading from the KeePassXC socket")?;
        trace!(%message, "from KeePassXC");
        Ok(message)
    }
}

/// Unwraps the `response` of a passkeys reply, which carries passkey errors
/// as `{"errorCode": …}`.
fn passkey_response(reply: Value) -> Result<Value> {
    let response = reply
        .get("response")
        .cloned()
        .ok_or_else(|| anyhow!("KeePassXC passkeys reply has no response: {reply}"))?;
    if response.get("errorCode").is_some() {
        return Err(error_from(&response).into());
    }
    Ok(response)
}

fn error_from(message: &Value) -> KeePassXcError {
    let code = match message.get("errorCode") {
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0) as u32,
        _ => 0,
    };
    let message = message
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| message.to_string());
    KeePassXcError { code, message }
}

pub fn is_code(error: &anyhow::Error, code: u32) -> bool {
    error
        .downcast_ref::<KeePassXcError>()
        .is_some_and(|e| e.code == code)
}

/// `sodium_increment`: the nonce as a little-endian number, plus one.
fn increment(mut nonce: [u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
    for byte in nonce.iter_mut() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            break;
        }
    }
    nonce
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// KeePassXC listens in `$XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC/`, and
/// links the socket into `$XDG_RUNTIME_DIR` too (not in Flatpak).
fn socket_path() -> Result<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("XDG_RUNTIME_DIR is not set"))?;
    let preferred = runtime
        .join("app/org.keepassxc.KeePassXC")
        .join(SOCKET_NAME);
    let legacy = runtime.join(SOCKET_NAME);
    Ok(if !preferred.exists() && legacy.exists() {
        legacy
    } else {
        preferred
    })
}

fn load_associations(store: &Path) -> Result<Vec<Association>> {
    match fs::read(store) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", store.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", store.display())),
    }
}

fn save_associations(store: &Path, associations: &[Association]) -> Result<()> {
    if let Some(dir) = store.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = store.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.write_all(&serde_json::to_vec_pretty(associations)?)?;
    file.sync_all()?;
    fs::rename(&tmp, store)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_carries_little_endian() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 0xff;
        nonce[1] = 0xff;
        nonce[2] = 0x01;
        let next = increment(nonce);
        assert_eq!(&next[..4], &[0x00, 0x00, 0x02, 0x00]);

        assert_eq!(increment([0xff; NONCE_LEN]), [0x00; NONCE_LEN]);
    }

    #[test]
    fn error_code_as_string_or_number() {
        let e = error_from(&json!({ "errorCode": "22", "error": "Request canceled" }));
        assert_eq!((e.code, e.message.as_str()), (22, "Request canceled"));
        assert_eq!(error_from(&json!({ "errorCode": 15 })).code, 15);
    }

    #[test]
    fn passkey_response_surfaces_error() {
        let err = passkey_response(json!({ "success": "true", "response": { "errorCode": 21 } }))
            .unwrap_err();
        assert!(is_code(&err, code::PASSKEYS_CREDENTIAL_IS_EXCLUDED));
    }

    #[test]
    fn associations_round_trip_private() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("sub/associations.json");
        assert!(load_associations(&store).unwrap().is_empty());

        let saved = vec![Association {
            id: "laptop".into(),
            key: "a2V5".into(),
        }];
        save_associations(&store, &saved).unwrap();
        assert_eq!(load_associations(&store).unwrap(), saved);

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
