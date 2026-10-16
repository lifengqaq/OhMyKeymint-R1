use std::{
    fs::{self, File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::runtime::fs::atomic_replace_preserving_metadata;
use pif_common::{
    parse_catalog, validate_product, DeviceEntry, PifOptions, PifProfile, MAX_CATALOG_BYTES,
    MAX_PROP_BYTES,
};
use serde::Serialize;
use ureq::http::Uri;

use crate::{
    config,
    plat::resetprop::{self, SYSTEM_SECURITY_PATCH_PROPERTY},
    security_patch, webui_http,
};

// The vendored Zygisk payload reads `pif.prop` from its own module directory.
// MODULE_ID must stay in sync with `MODULE_ID` in build.py and the `id` field
// of template/module.prop.
const MODULE_ID: &str = "oh_my_keymint";
const PIF_PROP_FILE: &str = "pif.prop";

// The OMK distribution endpoint aggregates the upstream PIF sources and serves
// a normalized feed under <base_url>/pif/.
const FEED_DIR: &str = "pif";
const MAX_REDIRECTS: usize = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn pif_prop_path() -> PathBuf {
    Path::new("/data/adb/modules")
        .join(MODULE_ID)
        .join(PIF_PROP_FILE)
}

#[derive(Debug, Clone)]
enum FeedResource {
    Catalog,
    Profile(String),
}

impl FeedResource {
    fn relative_path(&self) -> String {
        match self {
            Self::Catalog => "device_list.json".to_string(),
            Self::Profile(product) => format!("device_prop/{product}.prop"),
        }
    }

    fn max_bytes(&self) -> usize {
        match self {
            Self::Catalog => MAX_CATALOG_BYTES,
            Self::Profile(_) => MAX_PROP_BYTES,
        }
    }

    fn size_label(&self) -> &'static str {
        match self {
            Self::Catalog => "64 KiB",
            Self::Profile(_) => "4 KiB",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Catalog => "PIF device catalog",
            Self::Profile(_) => "PIF device profile",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OptionsState {
    spoof_build: bool,
    spoof_props: bool,
    spoof_provider: bool,
    spoof_signature: bool,
    spoof_vending_build: bool,
    spoof_vending_sdk: bool,
    debug: bool,
}

impl From<PifOptions> for OptionsState {
    fn from(options: PifOptions) -> Self {
        Self {
            spoof_build: options.spoof_build,
            spoof_props: options.spoof_props,
            spoof_provider: options.spoof_provider,
            spoof_signature: options.spoof_signature,
            spoof_vending_build: options.spoof_vending_build,
            spoof_vending_sdk: options.spoof_vending_sdk,
            debug: options.debug,
        }
    }
}

#[derive(Debug, Serialize)]
struct DisabledState {
    enabled: bool,
    options: OptionsState,
}

#[derive(Debug, Serialize)]
struct EnabledState<'a> {
    enabled: bool,
    model: &'a str,
    product: &'a str,
    fingerprint: &'a str,
    security_patch: &'a str,
    options: OptionsState,
}

pub fn list_devices() -> Result<String> {
    let entries = download_catalog()?;
    serde_json::to_string(&entries).context("failed to serialize PIF device catalog")
}

pub fn fingerprint_state() -> Result<String> {
    state_json(load_profile(&pif_prop_path())?.as_ref())
}

pub fn apply_fingerprint(product: &str, options: PifOptions) -> Result<String> {
    validate_product(product).map_err(anyhow::Error::msg)?;
    let catalog = download_catalog()?;
    let selected = catalog
        .iter()
        .find(|entry| entry.product == product)
        .ok_or_else(|| anyhow!("selected product is not present in the current PIF catalog"))?;
    let resource = FeedResource::Profile(product.to_string());
    let contents = download_feed(&resource)?;
    let mut profile = PifProfile::from_source(selected, contents.as_bytes())
        .map_err(anyhow::Error::msg)
        .context("downloaded PIF profile failed validation")?
        .with_options(options);

    let path = pif_prop_path();
    let _lock = security_patch::acquire_data_operation_lock(&path)?;
    align_profile_security_patch(
        &mut profile,
        resetprop::read_string_property(SYSTEM_SECURITY_PATCH_PROPERTY),
    )
    .context("failed to align the PIF security patch with the hardware patch date")?;
    persist_profile(&path, &profile)?;
    refresh_target_processes()?;
    state_json(Some(&profile))
}

pub fn disable_fingerprint() -> Result<String> {
    let path = pif_prop_path();
    let _lock = security_patch::acquire_data_operation_lock(&path)?;
    remove_profile(&path)?;
    refresh_target_processes()?;
    state_json(None)
}

fn download_catalog() -> Result<Vec<DeviceEntry>> {
    let contents = download_feed(&FeedResource::Catalog)?;
    parse_catalog(contents.as_bytes()).map_err(anyhow::Error::msg)
}

fn download_feed(resource: &FeedResource) -> Result<String> {
    let config_file = config::load_config_file().context("failed to load config.toml")?;
    let base_url = config_file
        .server
        .base_url()
        .context("invalid [server] config")?
        .to_string();
    let base: Uri = base_url
        .parse()
        .with_context(|| format!("server.base_url {base_url:?} is not a valid URL"))?;
    let uri: Uri = format!(
        "{}/{FEED_DIR}/{}",
        base.to_string().trim_end_matches('/'),
        resource.relative_path()
    )
    .parse()
    .with_context(|| format!("{} URL is invalid", resource.label()))?;
    if !is_allowed_feed_uri(&uri, &base, resource) {
        bail!("{} URL is outside the OMK feed path", resource.label());
    }

    webui_http::download_https_utf8(
        uri,
        &webui_http::DownloadPolicy {
            resource: resource.label(),
            redirect_allowlist: "the configured OMK server host",
            max_bytes: resource.max_bytes(),
            max_size_label: resource.size_label(),
            max_redirects: MAX_REDIRECTS,
            timeout: REQUEST_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
        },
        |uri| is_allowed_feed_uri(uri, &base, resource),
    )
}

fn is_allowed_feed_uri(uri: &Uri, base: &Uri, resource: &FeedResource) -> bool {
    if uri.scheme_str() != Some("https") || uri.query().is_some() {
        return false;
    }
    if uri.authority() != base.authority() {
        return false;
    }
    let base_path = base.path().trim_end_matches('/');
    let expected = format!("{base_path}/{FEED_DIR}/{}", resource.relative_path());
    uri.path() == expected
}

/// Google's hardware-backed evaluation requires the software-layer patch date
/// reported by the target process to match the hardware-layer patch date. OMK
/// keeps the hardware-layer date in the runtime
/// `ro.build.version.security_patch` property, so the stored PIF profile is
/// aligned to that exact value before it is persisted. The feed's own
/// `SECURITY_PATCH` must still be a valid date but never reaches target
/// processes unchanged.
fn align_profile_security_patch(
    profile: &mut PifProfile,
    runtime_patch: Option<String>,
) -> Result<()> {
    let aligned = runtime_patch
        .ok_or_else(|| anyhow!("{SYSTEM_SECURITY_PATCH_PROPERTY} is missing or empty"))?;
    if !config::is_security_patch_date(&aligned) {
        bail!("{SYSTEM_SECURITY_PATCH_PROPERTY} is not an exact YYYY-MM-DD date");
    }
    profile.security_patch = aligned;
    Ok(())
}

fn state_json(profile: Option<&PifProfile>) -> Result<String> {
    match profile {
        Some(profile) => {
            profile.validate().map_err(anyhow::Error::msg)?;
            serde_json::to_string(&EnabledState {
                enabled: true,
                model: &profile.model,
                product: &profile.product,
                fingerprint: &profile.fingerprint,
                security_patch: &profile.security_patch,
                options: profile.options.into(),
            })
        }
        None => serde_json::to_string(&DisabledState {
            enabled: false,
            options: PifOptions::default().into(),
        }),
    }
    .context("failed to serialize PIF fingerprint state")
}

fn load_profile(path: &Path) -> Result<Option<PifProfile>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect PIF profile {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("PIF profile path is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_PROP_BYTES as u64 {
        bail!("PIF profile exceeds the 4 KiB limit");
    }
    let contents =
        fs::read(path).with_context(|| format!("failed to read PIF profile {}", path.display()))?;
    let profile = PifProfile::from_prop(&contents).map_err(anyhow::Error::msg)?;
    if contents != profile.to_prop().map_err(anyhow::Error::msg)?.as_bytes() {
        bail!("PIF profile is not in canonical form");
    }
    Ok(Some(profile))
}

fn persist_profile(path: &Path, profile: &PifProfile) -> Result<()> {
    let contents = profile.to_prop().map_err(anyhow::Error::msg)?;
    validate_profile_target(path)?;
    // The WebUI bridge runs as root; the Zygisk companion (also root) reads the
    // file, so 0644 lets the payload read it after any module re-init.
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o644, 0, 0).with_context(
        || {
            format!(
                "failed to atomically replace PIF profile {}",
                path.display()
            )
        },
    )?;
    validate_profile_target(path)?;
    enforce_profile_metadata(path, 0, 0)?;
    let saved = load_profile(path)?.ok_or_else(|| anyhow!("PIF profile vanished after write"))?;
    if &saved != profile {
        bail!("PIF profile read-back does not match the requested profile");
    }
    Ok(())
}

fn validate_profile_target(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("PIF profile path has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect PIF state directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        bail!(
            "PIF state parent is not a real directory: {}",
            parent.display()
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!("PIF profile path is not a regular file: {}", path.display());
        }
    }
    Ok(())
}

fn enforce_profile_metadata(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to reopen PIF profile {}", path.display()))?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PIF profile owner");
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PIF profile mode");
    }
    file.sync_all()
        .context("failed to sync PIF profile metadata")?;
    Ok(())
}

fn remove_profile(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            bail!("PIF profile path is not a regular file: {}", path.display())
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect PIF profile before removal"),
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("PIF profile path has no parent"))?;
    fs::remove_file(path)
        .with_context(|| format!("failed to remove PIF profile {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to sync PIF state directory after removal")
}

fn refresh_target_processes() -> Result<()> {
    const PROCESS_NAMES: [&[u8]; 2] = [b"com.google.android.gms.unstable", b"com.android.vending"];
    let entries = fs::read_dir("/proc").context("failed to scan processes after PIF update")?;
    let mut failures = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let name = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
        if !is_target_process_name(name, &PROCESS_NAMES) {
            continue;
        }
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            // A matching process can exit between the /proc scan and kill.
            // Treat that expected race as an already-refreshed process.
            if error.raw_os_error() != Some(libc::ESRCH) {
                failures.push(format!(
                    "{} (pid {pid}): {error}",
                    String::from_utf8_lossy(name)
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to stop PIF target process(es): {}",
            failures.join("; ")
        )
    }
}

fn is_target_process_name(name: &[u8], bases: &[&[u8]]) -> bool {
    bases.iter().any(|base| {
        name == *base
            || (name.len() > base.len() + 1 && name.starts_with(base) && name[base.len()] == b':')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const PROP: &str = "FINGERPRINT=google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel 6\nSECURITY_PATCH=2026-08-05\n";

    fn sample_profile() -> PifProfile {
        PifProfile::from_source(
            &DeviceEntry {
                model: "Pixel 6".to_string(),
                product: "oriole_beta".to_string(),
            },
            PROP.as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn feed_allowlist_accepts_only_exact_resource_paths() {
        let catalog = FeedResource::Catalog;
        let base: Uri = "https://omk.5ijxa.com/api/omk".parse().unwrap();
        assert!(is_allowed_feed_uri(
            &"https://omk.5ijxa.com/api/omk/pif/device_list.json"
                .parse()
                .unwrap(),
            &base,
            &catalog
        ));
        for url in [
            "http://omk.5ijxa.com/api/omk/pif/device_list.json",
            "https://evil.example/api/omk/pif/device_list.json",
            "https://omk.5ijxa.com/api/omk/pif/other.json",
            "https://omk.5ijxa.com/pif/device_list.json",
            "https://omk.5ijxa.com/api/omk/pif/device_list.json?x=1",
        ] {
            assert!(
                !is_allowed_feed_uri(&url.parse().unwrap(), &base, &catalog),
                "{url}"
            );
        }
    }

    #[test]
    fn profile_allowlist_binds_the_validated_product_to_the_path() {
        let base: Uri = "https://omk.5ijxa.com/api/omk".parse().unwrap();
        let profile = FeedResource::Profile("oriole_beta".to_string());
        assert!(is_allowed_feed_uri(
            &"https://omk.5ijxa.com/api/omk/pif/device_prop/oriole_beta.prop"
                .parse()
                .unwrap(),
            &base,
            &profile
        ));
        assert!(!is_allowed_feed_uri(
            &"https://omk.5ijxa.com/api/omk/pif/device_prop/raven_beta.prop"
                .parse()
                .unwrap(),
            &base,
            &profile
        ));
    }

    #[test]
    fn alignment_overrides_the_feed_security_patch_with_the_runtime_date() {
        let mut profile = sample_profile();
        assert_eq!(profile.security_patch, "2026-08-05");
        align_profile_security_patch(&mut profile, Some("2026-10-05".to_string())).unwrap();
        assert_eq!(profile.security_patch, "2026-10-05");
    }

    #[test]
    fn alignment_rejects_missing_or_non_date_runtime_values() {
        let mut profile = sample_profile();
        for runtime in [
            None,
            Some(String::new()),
            Some("auto".to_string()),
            Some("2026-13-05".to_string()),
        ] {
            assert!(align_profile_security_patch(&mut profile, runtime).is_err());
            assert_eq!(profile.security_patch, "2026-08-05");
        }
    }

    #[test]
    fn state_json_matches_the_webui_canonical_contract() {
        let profile = sample_profile();
        assert_eq!(
            state_json(None).unwrap(),
            r#"{"enabled":false,"options":{"spoofBuild":true,"spoofProps":true,"spoofProvider":false,"spoofSignature":false,"spoofVendingBuild":true,"spoofVendingSdk":false,"debug":false}}"#
        );
        assert_eq!(
            state_json(Some(&profile)).unwrap(),
            r#"{"enabled":true,"model":"Pixel 6","product":"oriole_beta","fingerprint":"google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys","security_patch":"2026-08-05","options":{"spoofBuild":true,"spoofProps":true,"spoofProvider":false,"spoofSignature":false,"spoofVendingBuild":true,"spoofVendingSdk":false,"debug":false}}"#
        );
    }

    #[test]
    fn profile_persistence_is_atomic_and_verified() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pif.prop");
        let profile = sample_profile();
        fs::write(&path, b"stale").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        persist_profile(&path, &profile).unwrap();
        assert_eq!(load_profile(&path).unwrap(), Some(profile));
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o644);
    }

    #[test]
    fn loader_rejects_symlinks_and_noncanonical_props() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::write(&real, sample_profile().to_prop().unwrap()).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(load_profile(&link).is_err());

        let noncanonical = temp.path().join("noncanonical");
        fs::write(&noncanonical, "MODEL=Pixel 6\n").unwrap();
        assert!(load_profile(&noncanonical).is_err());
    }

    #[test]
    fn refresh_matching_accepts_supported_colon_processes_only() {
        let bases: [&[u8]; 2] = [b"com.google.android.gms.unstable", b"com.android.vending"];
        for name in [
            b"com.google.android.gms.unstable".as_slice(),
            b"com.google.android.gms.unstable:background".as_slice(),
            b"com.android.vending".as_slice(),
            b"com.android.vending:instant".as_slice(),
        ] {
            assert!(
                is_target_process_name(name, &bases),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        for name in [
            b"com.google.android.gms".as_slice(),
            b"com.google.android.gms.unstable2".as_slice(),
            b"com.google.android.gms.unstable:".as_slice(),
            b"com.android.vending.evil".as_slice(),
            b"com.android.vending/child".as_slice(),
        ] {
            assert!(
                !is_target_process_name(name, &bases),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }
}
