//! Command line: decode the QR code, then serve the browser's request from
//! KeePassXC over the caBLE tunnel.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use keepassxc_hybrid::{advertiser, backend, keepassxc, qr};
use std::{io::IsTerminal, path::PathBuf, time::Duration};
use tracing::info;
use tracing_subscriber::EnvFilter;
use webauthn_authenticator_rs::{
    cable::{share_cable_authenticator, ShareCableAuthenticatorOptions},
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// A `FIDO:/` URL, an image (PNG, JPEG, WebP) containing the QR code, or
    /// `-` to read the image from stdin, e.g. `grim -g "$(slurp)" - | keepassxc-hybrid -`.
    input: String,

    /// KeePassXC group for new passkey entries (KeePassXC's default otherwise).
    #[arg(long)]
    group: Option<String>,

    /// Tunnel server to use: 0 is Google's, 1 is Apple's.
    #[arg(long, default_value_t = 0)]
    tunnel_server: u16,

    /// File holding this client's KeePassXC associations.
    #[arg(long, env = "KEEPASSXC_HYBRID_ASSOCIATIONS")]
    associations: Option<PathBuf>,

    /// Seconds to wait for the browser to connect and the request to finish.
    #[arg(long, default_value_t = 180)]
    timeout: u64,
}

/// Logs the tunnel's progress; the user interacts with KeePassXC's dialogs.
#[derive(Debug)]
struct Status;

impl UiCallback for Status {
    fn request_pin(&self) -> Option<String> {
        None
    }

    fn request_touch(&self) {}

    fn processing(&self) {}

    fn fingerprint_enrollment_feedback(
        &self,
        _remaining_samples: u32,
        _feedback: Option<EnrollSampleStatus>,
    ) {
    }

    fn cable_qr_code(&self, _request_type: CableRequestType, _url: String) {}

    fn dismiss_qr_code(&self) {}

    fn cable_status_update(&self, state: CableState) {
        info!(?state, "tunnel");
    }
}

fn default_associations() -> Result<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or_else(|| anyhow!("neither XDG_CONFIG_HOME nor HOME is set"))?;
    Ok(config.join("keepassxc-hybrid/associations.json"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let cli = Cli::parse();

    let url = qr::fido_url(&cli.input)?;

    // KeePassXC first: unlocking the database or approving this client can
    // take longer than the browser waits once the tunnel is up.
    let associations = cli.associations.map_or_else(default_associations, Ok)?;
    let mut client = keepassxc::Client::connect(associations)?;
    client.ensure_associated()?;
    let mut backend = backend::KeePassXcBackend::new(client, cli.group);

    let mut advertiser = advertiser::BluezAdvertiser::new()
        .await
        .context("starting Bluetooth LE advertising through BlueZ")?;

    info!("waiting for the browser; it must be near this machine's Bluetooth");
    let session = share_cable_authenticator(
        &mut backend,
        backend::get_info(),
        &url,
        &mut advertiser,
        &Status,
        ShareCableAuthenticatorOptions::default().tunnel_server_id(cli.tunnel_server),
    );
    tokio::time::timeout(Duration::from_secs(cli.timeout), session)
        .await
        .map_err(|_| {
            anyhow!(
                "the browser did not finish within {}s; is it within Bluetooth range?",
                cli.timeout
            )
        })?
        .map_err(|e| anyhow!("caBLE session failed: {e:?}"))?;
    info!("done");
    Ok(())
}
