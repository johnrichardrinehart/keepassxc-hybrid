//! Registers a passkey in a running KeePassXC and signs in with it, through
//! the same CTAP requests and responses a browser exchanges with this tool
//! over the caBLE tunnel, and checks both ceremonies with webauthn-rs as the
//! relying party. Only the tunnel and Bluetooth are left out.
//!
//! KeePassXC shows its dialogs as usual; `scripts/live-test.sh` runs this
//! against a throwaway KeePassXC in a headless compositor and answers them.
//!
//!     cargo run --example live_keepassxc -- <associations.json>

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use keepassxc_hybrid::{backend::KeePassXcBackend, keepassxc::Client};
use serde_cbor_2::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use webauthn_authenticator_rs::{
    ctap2::{
        commands::{
            GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest,
            MakeCredentialResponse,
        },
        CBORResponse,
    },
    perform_auth_with_request, perform_register_with_request,
};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, RegistrationExtensionsClientOutputs,
};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

/// The client data a browser builds and keeps, sending only its hash.
fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes()
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let store = std::env::args()
        .nth(1)
        .context("usage: live_keepassxc <associations.json>")?;
    let mut client = Client::connect(store.into())?;
    client.ensure_associated()?;
    let mut backend = KeePassXcBackend::new(client, None);

    let webauthn = WebauthnBuilder::new(RP_ID, &Url::parse(ORIGIN)?)?.build()?;
    let user_id = Uuid::new_v4();

    // Registration: authenticatorMakeCredential, as the browser sends it.
    let (ccr, registration) =
        webauthn.start_passkey_registration(user_id, "alice", "Alice", None)?;
    let options = ccr.public_key;
    let client_data_json = client_data("webauthn.create", &options.challenge);
    let request = MakeCredentialRequest {
        client_data_hash: Sha256::digest(&client_data_json).to_vec(),
        rp: options.rp,
        user: options.user,
        pub_key_cred_params: options.pub_key_cred_params,
        exclude_list: options.exclude_credentials.unwrap_or_default(),
        options: Some(BTreeMap::from([
            ("rk".to_string(), true),
            ("uv".to_string(), true),
        ])),
        pin_uv_auth_param: None,
        pin_uv_auth_proto: None,
        enterprise_attest: None,
    };
    let response = perform_register_with_request(&mut backend, request, 30_000)
        .map_err(|e| anyhow!("makeCredential: {e:?}"))?;
    let response = <MakeCredentialResponse as CBORResponse>::try_from(response.as_slice())
        .map_err(|e| anyhow!("parsing makeCredential response: {e:?}"))?;

    // The browser turns the CTAP response into an attestation object, and
    // takes the credential ID from the attested credential data:
    // rpIdHash(32) flags(1) signCount(4) aaguid(16) idLength(2) id.
    let auth_data = response.auth_data.context("no authData")?;
    let Value::Bytes(auth_data_bytes) = &auth_data else {
        return Err(anyhow!("authData is not a byte string"));
    };
    let id_len = u16::from_be_bytes([auth_data_bytes[53], auth_data_bytes[54]]) as usize;
    let credential_id = auth_data_bytes[55..55 + id_len].to_vec();
    let attestation_object = serde_cbor_2::to_vec(&BTreeMap::from([
        (
            "fmt".to_string(),
            Value::Text(response.fmt.context("no fmt")?),
        ),
        ("authData".to_string(), auth_data),
        (
            "attStmt".to_string(),
            response.att_stmt.context("no attStmt")?,
        ),
    ]))?;
    let passkey = webauthn.finish_passkey_registration(
        &RegisterPublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&credential_id),
            raw_id: credential_id,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json,
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        },
        &registration,
    )?;
    println!(
        "registered: credential {}",
        URL_SAFE_NO_PAD.encode(passkey.cred_id())
    );

    // Sign-in without naming the account: authenticatorGetAssertion with an
    // empty allow list, so the response has to carry the user handle.
    let (rcr, authentication) = webauthn.start_discoverable_authentication()?;
    let client_data_json = client_data("webauthn.get", &rcr.public_key.challenge);
    let request = GetAssertionRequest {
        rp_id: RP_ID.to_string(),
        client_data_hash: Sha256::digest(&client_data_json).to_vec(),
        allow_list: Vec::new(),
        options: Some(BTreeMap::from([("uv".to_string(), true)])),
        pin_uv_auth_param: None,
        pin_uv_auth_proto: None,
    };
    let response = perform_auth_with_request(&mut backend, request, 30_000)
        .map_err(|e| anyhow!("getAssertion: {e:?}"))?;
    let response = <GetAssertionResponse as CBORResponse>::try_from(response.as_slice())
        .map_err(|e| anyhow!("parsing getAssertion response: {e:?}"))?;
    let credential_id = response.credential.context("no credential")?.id;
    let assertion = PublicKeyCredential {
        id: URL_SAFE_NO_PAD.encode(&credential_id),
        raw_id: credential_id,
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: response.auth_data.context("no authData")?,
            client_data_json,
            signature: response.signature.context("no signature")?,
            user_handle: response.user_handle,
        },
        extensions: AuthenticationExtensionsClientOutputs::default(),
        type_: "public-key".to_string(),
    };

    let (identified, _) = webauthn.identify_discoverable_authentication(&assertion)?;
    if identified != user_id {
        return Err(anyhow!(
            "user handle {identified} is not the registered user {user_id}"
        ));
    }
    let result =
        webauthn.finish_discoverable_authentication_v2(&assertion, authentication, &passkey)?;
    println!(
        "signed in: user {identified}, user verified: {}",
        result.user_verified()
    );
    Ok(())
}
