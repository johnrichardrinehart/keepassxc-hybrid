//! The Bluetooth LE advertisement that proves to the browser this
//! authenticator is nearby, sent through BlueZ.

use async_trait::async_trait;
use bluer::adv::{Advertisement, AdvertisementHandle, Type};
use std::{collections::BTreeMap, time::Duration};
use tracing::debug;
use webauthn_authenticator_rs::{cable::Advertiser, error::WebauthnCError};

pub struct BluezAdvertiser {
    adapter: bluer::Adapter,
    handle: Option<AdvertisementHandle>,
}

impl BluezAdvertiser {
    pub async fn new() -> anyhow::Result<Self> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        if !adapter.is_powered().await? {
            adapter.set_powered(true).await?;
        }
        Ok(Self {
            adapter,
            handle: None,
        })
    }
}

fn bt_error(e: bluer::Error) -> WebauthnCError {
    WebauthnCError::BluetoothError(e.to_string())
}

/// A 16-bit UUID in the Bluetooth base UUID.
fn uuid_from_u16(short: u16) -> bluer::Uuid {
    bluer::Uuid::from_u128(((short as u128) << 96) | 0x0000_0000_0000_1000_8000_0080_5f9b_34fb)
}

#[async_trait]
impl Advertiser for BluezAdvertiser {
    async fn start_advertising(
        &mut self,
        service_uuid: u16,
        payload: &[u8],
    ) -> Result<(), WebauthnCError> {
        debug!(service_uuid, "advertising");
        let advertisement = Advertisement {
            advertisement_type: Type::Broadcast,
            service_data: BTreeMap::from([(uuid_from_u16(service_uuid), payload.to_vec())]),
            min_interval: Some(Duration::from_millis(100)),
            max_interval: Some(Duration::from_millis(500)),
            ..Default::default()
        };
        self.handle = Some(
            self.adapter
                .advertise(advertisement)
                .await
                .map_err(bt_error)?,
        );
        Ok(())
    }

    async fn stop_advertising(&mut self) -> Result<(), WebauthnCError> {
        // Dropping the handle unregisters the advertisement.
        self.handle.take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fido_service_uuid() {
        assert_eq!(
            uuid_from_u16(0xfff9).to_string(),
            "0000fff9-0000-1000-8000-00805f9b34fb"
        );
    }
}
