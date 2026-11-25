//! The authenticator the caBLE tunnel talks to: CTAP2 requests answered by
//! KeePassXC's passkeys.
//!
//! In the hybrid transport the platform (browser) builds the client data and
//! sends only its hash. KeePassXC's browser API builds its own client data from
//! a challenge, so the request carries a placeholder challenge and:
//!
//! * registration works on stock KeePassXC: it uses `none` attestation, so
//!   nothing it returns depends on the client data;
//! * assertion signs `authenticatorData || clientDataHash`, which needs
//!   KeePassXC to take the platform's hash (`clientDataHash`, added by
//!   `patches/keepassxc-passkeys-client-data-hash.patch`).

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tracing::{error, info};
use uuid::uuid;
use webauthn_authenticator_rs::{
    ctap2::GetInfoResponse,
    error::{CtapError, WebauthnCError},
    AuthenticatorBackendHashedClientData,
};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs,
};

use crate::keepassxc::{self, Client};

/// KeePassXC's AAGUID, which it writes into the authenticator data.
const KEEPASSXC_AAGUID: uuid::Uuid = uuid!("fdb141b2-5d84-443e-8a35-4698c205a502");

/// Algorithms KeePassXC creates keys for: ES256, EdDSA, RS256.
const ALGORITHMS: [i64; 3] = [-7, -8, -257];

/// KeePassXC requires a challenge of at least 16 characters. Its value only
/// ends up in client data that is thrown away.
const PLACEHOLDER_CHALLENGE: [u8; 32] = [0; 32];

/// How long KeePassXC's dialog waits for the user.
const DIALOG_TIMEOUT_MS: u32 = 120_000;

pub struct KeePassXcBackend {
    client: Client,
    group: Option<String>,
}

impl KeePassXcBackend {
    pub fn new(client: Client, group: Option<String>) -> Self {
        Self { client, group }
    }
}

/// What the authenticator tells the platform about itself.
pub fn get_info() -> GetInfoResponse {
    GetInfoResponse {
        versions: BTreeSet::from(["FIDO_2_0".to_string(), "FIDO_2_1".to_string()]),
        aaguid: Some(KEEPASSXC_AAGUID),
        algorithms: Some(
            ALGORITHMS
                .iter()
                .map(|&alg| webauthn_rs_proto::PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg,
                })
                .collect(),
        ),
        ..Default::default()
    }
}

/// `https://<rp id>`: the origin KeePassXC checks the RP ID against and
/// records as the entry URL. The platform already checked the real origin.
fn origin(rp_id: &str) -> String {
    format!("https://{rp_id}")
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Credential descriptors without transports: KeePassXC skips credentials
/// whose transports do not include one of its own, and an RP may list only
/// `hybrid` for a passkey made through this tool.
fn descriptors<'a>(ids: impl Iterator<Item = &'a [u8]>) -> Value {
    Value::Array(
        ids.map(|id| json!({ "type": "public-key", "id": b64(id) }))
            .collect(),
    )
}

pub fn creation_options(options: &PublicKeyCredentialCreationOptions) -> Value {
    json!({
        "challenge": b64(&PLACEHOLDER_CHALLENGE),
        "rp": { "id": options.rp.id, "name": options.rp.name },
        "user": {
            "id": b64(&options.user.id),
            "name": options.user.name,
            "displayName": options.user.display_name,
        },
        "pubKeyCredParams": options
            .pub_key_cred_params
            .iter()
            .map(|p| json!({ "type": p.type_, "alg": p.alg }))
            .collect::<Vec<_>>(),
        "excludeCredentials": descriptors(
            options.exclude_credentials.iter().flatten().map(|c| c.id.as_slice())
        ),
        // Hybrid passkeys are discoverable: the platform asks for one without
        // knowing the account. User verification as phones always report it:
        // the CTAP request does not say what the RP asked for, and RPs that
        // require it (most) reject a credential without the UV flag.
        "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
        "attestation": "none",
        "timeout": DIALOG_TIMEOUT_MS,
    })
}

pub fn request_options(
    client_data_hash: &[u8],
    options: &PublicKeyCredentialRequestOptions,
) -> Value {
    json!({
        "challenge": b64(&PLACEHOLDER_CHALLENGE),
        "clientDataHash": b64(client_data_hash),
        "rpId": options.rp_id,
        "allowCredentials": descriptors(options.allow_credentials.iter().map(|c| c.id.as_slice())),
        "userVerification": "required",
        "timeout": DIALOG_TIMEOUT_MS,
    })
}

fn field<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str> {
    path.iter()
        .try_fold(value, |v, key| v.get(key))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("KeePassXC response has no {}", path.join(".")))
}

fn decode(value: &Value, path: &[&str]) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(field(value, path)?.trim_end_matches('='))
        .with_context(|| format!("decoding {}", path.join(".")))
}

pub fn registration_from(response: &Value) -> Result<RegisterPublicKeyCredential> {
    let id = field(response, &["id"])?.to_string();
    Ok(RegisterPublicKeyCredential {
        raw_id: decode(response, &["id"])?,
        id,
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: decode(response, &["response", "attestationObject"])?,
            client_data_json: Vec::new(),
            transports: None,
        },
        type_: "public-key".to_string(),
        extensions: RegistrationExtensionsClientOutputs::default(),
    })
}

pub fn assertion_from(response: &Value) -> Result<PublicKeyCredential> {
    // KeePassXC without the clientDataHash patch ignores the hash, signs its
    // own client data and returns it. That signature would fail at the RP.
    if response["response"].get("clientDataJSON").is_some() {
        return Err(anyhow!(
            "KeePassXC signed its own client data instead of the browser's: \
             it lacks patches/keepassxc-passkeys-client-data-hash.patch"
        ));
    }
    let user_handle = match field(response, &["response", "userHandle"]) {
        Ok(h) if !h.is_empty() => Some(decode(response, &["response", "userHandle"])?),
        _ => None,
    };
    let id = field(response, &["id"])?.to_string();
    Ok(PublicKeyCredential {
        raw_id: decode(response, &["id"])?,
        id,
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: decode(response, &["response", "authenticatorData"])?,
            client_data_json: Vec::new(),
            signature: decode(response, &["response", "signature"])?,
            user_handle,
        },
        extensions: AuthenticationExtensionsClientOutputs::default(),
        type_: "public-key".to_string(),
    })
}

/// The CTAP status the platform gets for a failure, so it can tell the user
/// (e.g. "already registered") instead of a generic error.
fn ctap_error(error: anyhow::Error) -> WebauthnCError {
    error!("{error:#}");
    let code = error
        .downcast_ref::<keepassxc::KeePassXcError>()
        .map(|e| e.code);
    WebauthnCError::Ctap(match code {
        Some(keepassxc::code::PASSKEYS_CREDENTIAL_IS_EXCLUDED) => {
            CtapError::Ctap2CredentialExcluded
        }
        Some(keepassxc::code::PASSKEYS_REQUEST_CANCELED)
        | Some(keepassxc::code::ACTION_CANCELLED_OR_DENIED) => CtapError::Ctap2OperationDenied,
        Some(keepassxc::code::NO_LOGINS_FOUND) => CtapError::Ctap2NoCredentials,
        _ => CtapError::Ctap2NotAllowed,
    })
}

impl AuthenticatorBackendHashedClientData for KeePassXcBackend {
    fn perform_register(
        &mut self,
        _client_data_hash: Vec<u8>,
        options: PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        info!(
            rp = options.rp.id,
            user = options.user.name,
            "registering a passkey; answer KeePassXC's dialog"
        );
        let origin = origin(&options.rp.id);
        self.client
            .passkeys_register(creation_options(&options), &origin, self.group.as_deref())
            .and_then(|r| registration_from(&r))
            .map_err(ctap_error)
    }

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialRequestOptions,
        _timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        info!(
            rp = options.rp_id,
            "signing in with a passkey; answer KeePassXC's dialog"
        );
        let origin = origin(&options.rp_id);
        self.client
            .passkeys_get(request_options(&client_data_hash, &options), &origin)
            .and_then(|r| assertion_from(&r))
            .map_err(ctap_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_rs_proto::{
        AllowCredentials, PubKeyCredParams, PublicKeyCredentialDescriptor, RelyingParty, User,
    };

    #[test]
    fn creation_options_for_keepassxc() {
        let options = PublicKeyCredentialCreationOptions {
            rp: RelyingParty {
                name: "Example".into(),
                id: "example.com".into(),
            },
            user: User {
                id: vec![1, 2, 3],
                name: "alice".into(),
                display_name: "Alice".into(),
            },
            challenge: Vec::new(),
            pub_key_cred_params: vec![PubKeyCredParams {
                type_: "public-key".into(),
                alg: -7,
            }],
            timeout: None,
            exclude_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: "public-key".into(),
                id: vec![0xff, 0xee],
                transports: Some(vec![webauthn_rs_proto::AuthenticatorTransport::Hybrid]),
            }]),
            hints: None,
            attestation: None,
            attestation_formats: None,
            authenticator_selection: None,
            extensions: None,
        };

        let json = creation_options(&options);
        assert_eq!(json["user"]["id"], "AQID");
        assert_eq!(json["rp"]["id"], "example.com");
        assert_eq!(
            json["excludeCredentials"],
            json!([{ "type": "public-key", "id": "_-4" }])
        );
        assert!(json["challenge"].as_str().unwrap().len() >= 16);
        assert_eq!(json["attestation"], "none");
    }

    #[test]
    fn request_options_carry_platform_hash() {
        let options = PublicKeyCredentialRequestOptions {
            challenge: Vec::new(),
            timeout: None,
            rp_id: "example.com".into(),
            allow_credentials: vec![AllowCredentials {
                type_: "public-key".into(),
                id: vec![0xff, 0xee],
                transports: Some(vec![webauthn_rs_proto::AuthenticatorTransport::Hybrid]),
            }],
            user_verification: webauthn_rs_proto::UserVerificationPolicy::Preferred,
            hints: None,
            extensions: None,
        };

        let json = request_options(&[7; 32], &options);
        assert_eq!(json["clientDataHash"], b64(&[7; 32]));
        assert_eq!(
            json["allowCredentials"],
            json!([{ "type": "public-key", "id": "_-4" }])
        );
    }

    #[test]
    fn assertion_from_patched_keepassxc() {
        let cred = assertion_from(&json!({
            "id": "AQI",
            "type": "public-key",
            "response": { "authenticatorData": "AwQ", "signature": "BQY", "userHandle": "Bwg" },
        }))
        .unwrap();
        assert_eq!(cred.raw_id, vec![1, 2]);
        assert_eq!(cred.response.authenticator_data, vec![3, 4]);
        assert_eq!(cred.response.signature, vec![5, 6]);
        assert_eq!(cred.response.user_handle, Some(vec![7, 8]));
    }

    #[test]
    fn assertion_from_unpatched_keepassxc_fails() {
        let err = assertion_from(&json!({
            "id": "AQI",
            "response": { "authenticatorData": "AwQ", "clientDataJSON": "e30", "signature": "BQY", "userHandle": "Bwg" },
        }))
        .unwrap_err();
        assert!(err.to_string().contains("client-data-hash.patch"), "{err}");
    }

    #[test]
    fn registration_from_keepassxc() {
        let cred = registration_from(&json!({
            "id": "AQI",
            "response": { "attestationObject": "o2NmbXRkbm9uZQ", "clientDataJSON": "e30" },
        }))
        .unwrap();
        assert_eq!(cred.raw_id, vec![1, 2]);
        assert_eq!(
            cred.response.attestation_object,
            URL_SAFE_NO_PAD.decode("o2NmbXRkbm9uZQ").unwrap()
        );
    }

    #[test]
    fn keepassxc_errors_become_ctap_statuses() {
        let excluded = anyhow::Error::new(keepassxc::KeePassXcError {
            code: 21,
            message: String::new(),
        });
        assert!(matches!(
            ctap_error(excluded),
            WebauthnCError::Ctap(CtapError::Ctap2CredentialExcluded)
        ));
        let canceled = anyhow::Error::new(keepassxc::KeePassXcError {
            code: 22,
            message: String::new(),
        });
        assert!(matches!(
            ctap_error(canceled),
            WebauthnCError::Ctap(CtapError::Ctap2OperationDenied)
        ));
    }
}
