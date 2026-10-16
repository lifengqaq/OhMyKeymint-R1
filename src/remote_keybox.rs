//! Downloads, verifies, and installs the signed Keybox published by the OMK
//! distribution endpoint configured under `[server]` in `config.toml`.
//!
//! The Keybox and its signed manifest are served by the endpoint's single
//! `index.php` front controller:
//!
//!   `<base_url>/index.php?action=manifest`  signed manifest (sha256 + Ed25519)
//!   `<base_url>/index.php?action=keybox`    current keybox.xml
//!
//! The PIF fingerprint feed is unrelated and still served as static files.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use ureq::http::Uri;

use crate::{config, keybox, webui_http};

/// Compiled-in Ed25519 trust anchor for the default OMK distribution endpoint.
///
/// This is the base64 public key (`sign_public`) published by the server. It is
/// used whenever `server.trusted_keybox_pubkey` is left empty, so a stock build
/// verifies cloud Keybox updates without any client-side setup.
const TRUSTED_PUBKEY_B64: &str = "KJSC4WN6GpiHemdQ4N/DYGBZnWM/uPJkbHFFoCGAd8Q=";

/// Front-controller path shared by the Keybox and manifest actions.
const INDEX_PATH: &str = "index.php";
/// Query strings accepted on `index.php`.
const QUERY_MANIFEST: &str = "action=manifest";
const QUERY_KEYBOX: &str = "action=keybox";

const MANIFEST_URL: &str = "Cloud Keybox manifest";
const KEYBOX_URL: &str = "Cloud Keybox";
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of a cloud Keybox refresh request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudKeyboxOutcome {
    Updated,
    UpToDate,
}

impl CloudKeyboxOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::UpToDate => "up_to_date",
        }
    }
}

#[derive(Debug, Deserialize)]
struct Manifest {
    keybox: ManifestKeybox,
}

#[derive(Debug, Deserialize)]
struct ManifestKeybox {
    sha256: String,
    #[serde(default)]
    signature: Option<String>,
}

/// Resolve the configured endpoint and trust anchor.
///
/// An explicitly configured `server.trusted_keybox_pubkey` takes precedence;
/// otherwise the compiled-in [`TRUSTED_PUBKEY_B64`] anchor is used.
fn resolve_endpoint() -> Result<(Uri, [u8; 32])> {
    let config_file = config::load_config_file().context("failed to load config.toml")?;
    let server = &config_file.server;

    let base_url = server
        .base_url()
        .context("invalid [server] config")?
        .to_string();
    let trusted = match server
        .trusted_keybox_pubkey()
        .context("invalid [server] config")?
    {
        Some(key) => key,
        None => compiled_trusted_pubkey()?,
    };

    let base: Uri = base_url
        .parse()
        .with_context(|| format!("server.base_url {base_url:?} is not a valid URL"))?;
    Ok((base, trusted))
}

/// Decode the compiled-in Ed25519 trust anchor.
fn compiled_trusted_pubkey() -> Result<[u8; 32]> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(TRUSTED_PUBKEY_B64)
        .context("compiled-in OMK trust anchor is not valid base64")?;
    if decoded.len() != 32 {
        bail!("compiled-in OMK trust anchor must encode 32 bytes");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Best-effort reachability check for the configured cloud endpoint.
///
/// Used by the boot-time module status script. A failure means the endpoint is
/// disabled, unreachable, or served an unusable manifest; it never mutates any
/// installed state.
pub fn check_reachable() -> Result<()> {
    let (base, _trusted) = resolve_endpoint()?;
    let manifest_uri = action_uri(&base, QUERY_MANIFEST)?;
    let allow = |uri: &Uri| is_allowed_uri(uri, &base);
    let manifest_text = download(
        manifest_uri,
        MANIFEST_URL,
        "256 KiB",
        MAX_MANIFEST_BYTES,
        allow,
    )?;
    let manifest: Manifest =
        serde_json::from_str(&manifest_text).context("Cloud Keybox manifest is not valid JSON")?;
    let expected_sha = manifest.keybox.sha256.trim().to_ascii_lowercase();
    if expected_sha.len() != 64 || !expected_sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Cloud Keybox manifest sha256 is not a 64-character hex digest");
    }
    Ok(())
}

/// Fetch the current signed Keybox and install it when it differs from the
/// installed copy. The configured Ed25519 public key is the only trust anchor;
/// a missing or invalid signature is a hard failure with no fallback.
pub fn update_from_cloud() -> Result<CloudKeyboxOutcome> {
    let (base, trusted) = resolve_endpoint()?;
    let manifest_uri = action_uri(&base, QUERY_MANIFEST)?;
    let keybox_uri = action_uri(&base, QUERY_KEYBOX)?;

    let allow = |uri: &Uri| is_allowed_uri(uri, &base);

    let manifest_text = download(
        manifest_uri,
        MANIFEST_URL,
        "256 KiB",
        MAX_MANIFEST_BYTES,
        allow,
    )?;
    let manifest: Manifest =
        serde_json::from_str(&manifest_text).context("Cloud Keybox manifest is not valid JSON")?;

    let expected_sha = manifest.keybox.sha256.trim().to_ascii_lowercase();
    if expected_sha.len() != 64 || !expected_sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Cloud Keybox manifest sha256 is not a 64-character hex digest");
    }
    let signature = manifest
        .keybox
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Cloud Keybox manifest is missing a signature"))?;

    let keybox_text = download(
        keybox_uri,
        KEYBOX_URL,
        "64 KiB",
        keybox::MAX_KEYBOX_XML_BYTES,
        allow,
    )?;
    let keybox_bytes = keybox_text.as_bytes();

    verify_sha256(keybox_bytes, &expected_sha)?;
    verify_signature(keybox_bytes, signature, &trusted)?;

    if installed_matches(&expected_sha) {
        return Ok(CloudKeyboxOutcome::UpToDate);
    }

    keybox::install_keybox_xml(keybox_bytes).context("failed to install the cloud Keybox")?;
    Ok(CloudKeyboxOutcome::Updated)
}

fn download<F>(
    uri: Uri,
    resource: &'static str,
    size_label: &'static str,
    max_bytes: usize,
    is_allowed: F,
) -> Result<String>
where
    F: Fn(&Uri) -> bool,
{
    webui_http::download_https_utf8(
        uri,
        &webui_http::DownloadPolicy {
            resource,
            redirect_allowlist: "the configured OMK server host",
            max_bytes,
            max_size_label: size_label,
            max_redirects: MAX_REDIRECTS,
            timeout: REQUEST_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
        },
        is_allowed,
    )
}

fn verify_sha256(contents: &[u8], expected_hex: &str) -> Result<()> {
    let digest = ring::digest::digest(&ring::digest::SHA256, contents);
    let actual = hex::encode(digest.as_ref());
    if actual != expected_hex {
        bail!("Cloud Keybox content does not match the manifest sha256");
    }
    Ok(())
}

fn verify_signature(contents: &[u8], signature_b64: &str, trusted: &[u8; 32]) -> Result<()> {
    use base64::Engine;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .context("Cloud Keybox signature is not valid base64")?;
    UnparsedPublicKey::new(&ED25519, trusted)
        .verify(contents, &signature)
        .map_err(|_| anyhow!("Cloud Keybox signature verification failed"))
}

fn installed_matches(expected_sha: &str) -> bool {
    match std::fs::read(keybox::KEYBOX_PATH) {
        Ok(contents) => {
            let digest = ring::digest::digest(&ring::digest::SHA256, &contents);
            hex::encode(digest.as_ref()) == expected_sha
        }
        Err(_) => false,
    }
}

fn action_uri(base: &Uri, query: &str) -> Result<Uri> {
    format!(
        "{}/{INDEX_PATH}?{query}",
        base.to_string().trim_end_matches('/')
    )
    .parse()
    .context("failed to build the request URL")
}

/// Accept only the two `index.php?action=` requests on the configured host, so
/// redirects and the requested URL cannot escape the endpoint's Keybox paths.
fn is_allowed_uri(uri: &Uri, base: &Uri) -> bool {
    if uri.scheme_str() != Some("https") {
        return false;
    }
    if uri.authority() != base.authority() {
        return false;
    }
    let base_path = base.path().trim_end_matches('/');
    if uri.path() != format!("{base_path}/{INDEX_PATH}") {
        return false;
    }
    matches!(uri.query(), Some(QUERY_MANIFEST) | Some(QUERY_KEYBOX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_anchor_decodes_to_32_bytes() {
        let key = compiled_trusted_pubkey().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn action_uri_targets_index_php_on_the_base_path() {
        let base: Uri = "https://omk.5ijxa.com/api/omk".parse().unwrap();
        assert_eq!(
            action_uri(&base, QUERY_MANIFEST).unwrap().to_string(),
            "https://omk.5ijxa.com/api/omk/index.php?action=manifest"
        );
        assert_eq!(
            action_uri(&base, QUERY_KEYBOX).unwrap().to_string(),
            "https://omk.5ijxa.com/api/omk/index.php?action=keybox"
        );
    }

    #[test]
    fn allowlist_accepts_only_the_two_actions() {
        let base: Uri = "https://omk.5ijxa.com/api/omk".parse().unwrap();
        for url in [
            "https://omk.5ijxa.com/api/omk/index.php?action=manifest",
            "https://omk.5ijxa.com/api/omk/index.php?action=keybox",
        ] {
            assert!(is_allowed_uri(&url.parse().unwrap(), &base), "{url}");
        }
        for url in [
            "http://omk.5ijxa.com/api/omk/index.php?action=keybox",
            "https://evil.example/api/omk/index.php?action=keybox",
            "https://omk.5ijxa.com/api/omk/index.php",
            "https://omk.5ijxa.com/api/omk/index.php?action=other",
            "https://omk.5ijxa.com/api/omk/index.php?action=keybox&x=1",
            "https://omk.5ijxa.com/api/omk/keybox.xml",
            "https://omk.5ijxa.com/index.php?action=keybox",
        ] {
            assert!(!is_allowed_uri(&url.parse().unwrap(), &base), "{url}");
        }
    }
}
