//! Finding the `FIDO:/` URL a browser shows as a QR code.

use anyhow::{bail, Context, Result};
use std::io::Read;

/// Returns the `FIDO:/` URL from `input`: the URL itself, a path to an image
/// holding its QR code, or `-` for an image on stdin.
pub fn fido_url(input: &str) -> Result<String> {
    if is_fido_url(input) {
        return Ok(normalize(input));
    }

    let image = if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading the image from stdin")?;
        buf
    } else {
        std::fs::read(input).with_context(|| format!("reading {input}"))?
    };

    from_image(&image)
}

/// Decodes every QR code in an encoded image (PNG, JPEG or WebP) and returns
/// the `FIDO:/` URL among them. The image may be a whole screen.
pub fn from_image(encoded: &[u8]) -> Result<String> {
    let luma = image::load_from_memory(encoded)
        .context("decoding the image")?
        .to_luma8();
    let (width, height) = luma.dimensions();

    let found =
        rxing::helpers::detect_multiple_in_luma(luma.into_raw(), width, height).unwrap_or_default();
    match found.iter().map(|r| r.getText()).find(|t| is_fido_url(t)) {
        Some(url) => Ok(normalize(url)),
        None if found.is_empty() => bail!("no QR code found in the image"),
        None => bail!(
            "the image has {} QR code(s), but none is a FIDO:/ (passkey) code",
            found.len()
        ),
    }
}

fn is_fido_url(s: &str) -> bool {
    s.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("FIDO:/"))
}

/// The caBLE handshake parser wants the scheme in capitals, as QR codes encode it.
fn normalize(url: &str) -> String {
    format!("FIDO:/{}", &url[6..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, ImageFormat, Luma};
    use std::io::Cursor;

    /// A QR code Chromium drew in its passkey dialog: dots, rounded finder
    /// patterns and an icon over the middle.
    const CHROMIUM_QR: &[u8] = include_bytes!("../tests/fixtures/chromium-hybrid-qr.png");
    const CHROMIUM_URL_PREFIX: &str = "FIDO:/46441181283352742352457356";

    fn png(image: &GrayImage) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        image.write_to(&mut out, ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn decodes_chromium_dialog_qr() {
        let url = from_image(CHROMIUM_QR).unwrap();
        assert!(url.starts_with(CHROMIUM_URL_PREFIX), "{url}");
    }

    #[test]
    fn finds_qr_in_full_screen_capture() {
        // The dialog QR code placed off-centre on a 2880x1317 screen with
        // window-like clutter around it.
        let qr = image::load_from_memory(CHROMIUM_QR).unwrap().to_luma8();
        let mut screen = GrayImage::from_fn(2880, 1317, |x, y| {
            if (x / 40 + y / 25) % 7 == 0 {
                Luma([90])
            } else {
                Luma([235])
            }
        });
        image::imageops::replace(
            &mut screen,
            &GrayImage::from_pixel(700, 600, Luma([255])),
            1800,
            250,
        );
        image::imageops::replace(&mut screen, &qr, 1935, 375);

        let url = from_image(&png(&screen)).unwrap();
        assert!(url.starts_with(CHROMIUM_URL_PREFIX), "{url}");
    }

    #[test]
    fn rejects_image_without_qr() {
        let blank = GrayImage::from_pixel(200, 200, Luma([255]));
        let err = from_image(&png(&blank)).unwrap_err();
        assert_eq!(err.to_string(), "no QR code found in the image");
    }

    #[test]
    fn passes_url_through() {
        assert_eq!(fido_url("FIDO:/123").unwrap(), "FIDO:/123");
        assert_eq!(fido_url("fido:/123").unwrap(), "FIDO:/123");
    }
}
