use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const MAX_CATALOG_BYTES: usize = 64 * 1024;
pub const MAX_CATALOG_ENTRIES: usize = 64;
pub const MAX_PROP_BYTES: usize = 4 * 1024;
pub const MAX_VALUE_BYTES: usize = 126;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceEntry {
    pub model: String,
    pub product: String,
}

/// Boolean switches understood by the vendored Zygisk payload's `pif.prop`.
/// The defaults mirror the upstream `pif.prop` shipped by PlayIntegrityFix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PifOptions {
    pub spoof_build: bool,
    pub spoof_props: bool,
    pub spoof_provider: bool,
    pub spoof_signature: bool,
    pub spoof_vending_build: bool,
    pub spoof_vending_sdk: bool,
    pub debug: bool,
}

impl Default for PifOptions {
    fn default() -> Self {
        Self {
            spoof_build: true,
            spoof_props: true,
            spoof_provider: false,
            spoof_signature: false,
            spoof_vending_build: true,
            spoof_vending_sdk: false,
            debug: false,
        }
    }
}

impl PifOptions {
    /// The seven `pif.prop` keys in their canonical emission order.
    pub fn to_pairs(self) -> [(&'static str, bool); 7] {
        [
            ("spoofBuild", self.spoof_build),
            ("spoofProps", self.spoof_props),
            ("spoofProvider", self.spoof_provider),
            ("spoofSignature", self.spoof_signature),
            ("spoofVendingBuild", self.spoof_vending_build),
            ("spoofVendingSdk", self.spoof_vending_sdk),
            ("DEBUG", self.debug),
        ]
    }

    fn from_map(map: &BTreeMap<String, String>) -> Result<Self, String> {
        let mut options = Self::default();
        for (key, value) in map {
            let slot = match key.as_str() {
                "spoofBuild" => &mut options.spoof_build,
                "spoofProps" => &mut options.spoof_props,
                "spoofProvider" => &mut options.spoof_provider,
                "spoofSignature" => &mut options.spoof_signature,
                "spoofVendingBuild" => &mut options.spoof_vending_build,
                "spoofVendingSdk" => &mut options.spoof_vending_sdk,
                "DEBUG" => &mut options.debug,
                _ => continue,
            };
            *slot = parse_bool(key, value)?;
        }
        Ok(options)
    }
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("{key} must be true or false")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PifProfile {
    pub model: String,
    pub manufacturer: String,
    pub fingerprint: String,
    pub security_patch: String,
    pub device_initial_sdk_int: String,
    pub brand: String,
    pub product: String,
    pub device: String,
    pub release: String,
    pub id: String,
    pub incremental: String,
    pub build_type: String,
    pub tags: String,
    pub options: PifOptions,
}

#[derive(Debug, Clone)]
struct SourceProfile {
    fingerprint: String,
    manufacturer: String,
    model: String,
    security_patch: String,
    device_initial_sdk_int: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct FingerprintParts<'a> {
    brand: &'a str,
    product: &'a str,
    device: &'a str,
    release: &'a str,
    id: &'a str,
    incremental: &'a str,
    build_type: &'a str,
    tags: &'a str,
}

/// Keys accepted in a downloaded feed profile. The OMK feed carries metadata
/// only; the payload switches are supplied by the caller.
const SOURCE_KEYS: [&str; 5] = [
    "FINGERPRINT",
    "MANUFACTURER",
    "MODEL",
    "SECURITY_PATCH",
    "DEVICE_INITIAL_SDK_INT",
];

/// Keys accepted in a stored `pif.prop`: the feed metadata plus the switches.
const STORED_KEYS: [&str; 12] = [
    "FINGERPRINT",
    "MANUFACTURER",
    "MODEL",
    "SECURITY_PATCH",
    "DEVICE_INITIAL_SDK_INT",
    "spoofBuild",
    "spoofProps",
    "spoofProvider",
    "spoofSignature",
    "spoofVendingBuild",
    "spoofVendingSdk",
    "DEBUG",
];

impl DeviceEntry {
    pub fn validate(&self) -> Result<(), String> {
        validate_display_value("model", &self.model)?;
        validate_product(&self.product)
    }
}

impl PifProfile {
    /// Parse a downloaded feed profile. Option switches default to the upstream
    /// values and are overridden by [`PifProfile::with_options`].
    pub fn from_source(selected: &DeviceEntry, contents: &[u8]) -> Result<Self, String> {
        selected.validate()?;
        let map = parse_prop_map(contents)?;
        reject_unknown_keys(&map, &SOURCE_KEYS)?;
        let source = source_from_map(&map)?;
        if source.model != selected.model {
            return Err("profile MODEL does not match the selected catalog entry".to_string());
        }
        let fingerprint = parse_fingerprint(&source.fingerprint)?;
        if fingerprint.product != selected.product {
            return Err("fingerprint PRODUCT does not match the selected product".to_string());
        }
        if source.manufacturer != "Google" || fingerprint.brand != "google" {
            return Err("PIF profile must describe a Google device".to_string());
        }
        if fingerprint.build_type != "user" || fingerprint.tags != "release-keys" {
            return Err("fingerprint must describe a user/release-keys build".to_string());
        }
        validate_security_patch_date(&source.security_patch)?;

        let brand = fingerprint.brand.to_string();
        let product = fingerprint.product.to_string();
        let device = fingerprint.device.to_string();
        let release = fingerprint.release.to_string();
        let id = fingerprint.id.to_string();
        let incremental = fingerprint.incremental.to_string();
        let build_type = fingerprint.build_type.to_string();
        let tags = fingerprint.tags.to_string();

        let profile = Self {
            model: source.model,
            manufacturer: source.manufacturer,
            fingerprint: source.fingerprint,
            security_patch: source.security_patch,
            device_initial_sdk_int: source
                .device_initial_sdk_int
                .unwrap_or_else(|| "32".to_string()),
            brand,
            product,
            device,
            release,
            id,
            incremental,
            build_type,
            tags,
            options: PifOptions::default(),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Parse a stored `pif.prop`, including the option switches.
    pub fn from_prop(contents: &[u8]) -> Result<Self, String> {
        let map = parse_prop_map(contents)?;
        reject_unknown_keys(&map, &STORED_KEYS)?;
        let source = source_from_map(&map)?;
        let fingerprint = parse_fingerprint(&source.fingerprint)?;
        let brand = fingerprint.brand.to_string();
        let product = fingerprint.product.to_string();
        let device = fingerprint.device.to_string();
        let release = fingerprint.release.to_string();
        let id = fingerprint.id.to_string();
        let incremental = fingerprint.incremental.to_string();
        let build_type = fingerprint.build_type.to_string();
        let tags = fingerprint.tags.to_string();
        let profile = Self {
            model: source.model,
            manufacturer: source.manufacturer,
            fingerprint: source.fingerprint,
            security_patch: source.security_patch,
            device_initial_sdk_int: source
                .device_initial_sdk_int
                .unwrap_or_else(|| "32".to_string()),
            brand,
            product,
            device,
            release,
            id,
            incremental,
            build_type,
            tags,
            options: PifOptions::from_map(&map)?,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn with_options(mut self, options: PifOptions) -> Self {
        self.options = options;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_display_value("model", &self.model)?;
        validate_product(&self.product)?;
        validate_display_value("manufacturer", &self.manufacturer)?;
        validate_security_patch_date(&self.security_patch)?;
        validate_launch_sdk(&self.device_initial_sdk_int)?;

        let parts = parse_fingerprint(&self.fingerprint)?;
        let expected = [
            ("brand", self.brand.as_str(), parts.brand),
            ("product", self.product.as_str(), parts.product),
            ("device", self.device.as_str(), parts.device),
            ("release", self.release.as_str(), parts.release),
            ("id", self.id.as_str(), parts.id),
            ("incremental", self.incremental.as_str(), parts.incremental),
            ("build_type", self.build_type.as_str(), parts.build_type),
            ("tags", self.tags.as_str(), parts.tags),
        ];
        for (name, actual, from_fingerprint) in expected {
            validate_component(name, actual)?;
            if actual != from_fingerprint {
                return Err(format!("stored {name} does not match fingerprint"));
            }
        }
        if self.manufacturer != "Google" || self.brand != "google" {
            return Err("stored PIF profile must describe a Google device".to_string());
        }
        if self.build_type != "user" || self.tags != "release-keys" {
            return Err("stored fingerprint must describe a user/release-keys build".to_string());
        }
        Ok(())
    }

    /// Render the canonical `pif.prop` consumed by the vendored payload.
    pub fn to_prop(&self) -> Result<String, String> {
        self.validate()?;
        let mut out = String::new();
        out.push_str(&format!("FINGERPRINT={}\n", self.fingerprint));
        out.push_str(&format!("MANUFACTURER={}\n", self.manufacturer));
        out.push_str(&format!("MODEL={}\n", self.model));
        out.push_str(&format!("SECURITY_PATCH={}\n", self.security_patch));
        out.push_str(&format!(
            "DEVICE_INITIAL_SDK_INT={}\n",
            self.device_initial_sdk_int
        ));
        for (key, value) in self.options.to_pairs() {
            out.push_str(&format!("{key}={}\n", if value { "true" } else { "false" }));
        }
        if out.len() > MAX_PROP_BYTES {
            return Err("serialized PIF profile exceeds the 4 KiB limit".to_string());
        }
        Ok(out)
    }
}

pub fn parse_catalog(contents: &[u8]) -> Result<Vec<DeviceEntry>, String> {
    if contents.len() > MAX_CATALOG_BYTES {
        return Err("PIF device catalog exceeds the 64 KiB limit".to_string());
    }
    let entries: Vec<DeviceEntry> = serde_json::from_slice(contents)
        .map_err(|error| format!("invalid PIF device catalog JSON: {error}"))?;
    if entries.is_empty() {
        return Err("PIF device catalog is empty".to_string());
    }
    if entries.len() > MAX_CATALOG_ENTRIES {
        return Err(format!(
            "PIF device catalog contains more than {MAX_CATALOG_ENTRIES} entries"
        ));
    }

    let mut products = BTreeSet::new();
    for entry in &entries {
        entry.validate()?;
        if !products.insert(entry.product.as_str()) {
            return Err(format!(
                "PIF device catalog contains duplicate product {}",
                entry.product
            ));
        }
    }
    Ok(entries)
}

pub fn validate_product(value: &str) -> Result<(), String> {
    validate_length_and_ascii("product", value)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err("product must not be empty".to_string());
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err("product must start with a lowercase ASCII letter or digit".to_string());
    }
    if !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
        return Err("product contains an unsupported character".to_string());
    }
    Ok(())
}

fn parse_prop_map(contents: &[u8]) -> Result<BTreeMap<String, String>, String> {
    if contents.len() > MAX_PROP_BYTES {
        return Err("PIF profile exceeds the 4 KiB limit".to_string());
    }
    let text = std::str::from_utf8(contents)
        .map_err(|error| format!("PIF profile is not UTF-8: {error}"))?;
    if text.contains('\0') {
        return Err("PIF profile contains NUL".to_string());
    }

    let normalized = text.replace("\r\n", "\n");
    if normalized.contains('\r') {
        return Err("PIF profile contains an invalid line ending".to_string());
    }
    let lines: Vec<&str> = normalized.split('\n').collect();
    let mut map = BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() && index + 1 == lines.len() {
            continue;
        }
        if line.is_empty() {
            return Err("PIF profile contains an empty line".to_string());
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("PIF profile line {} has no '='", index + 1))?;
        validate_length_and_ascii(key, value)?;
        if map.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("PIF profile contains duplicate key {key}"));
        }
    }
    Ok(map)
}

fn reject_unknown_keys(map: &BTreeMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("PIF profile contains unknown key {key}"));
        }
    }
    Ok(())
}

fn source_from_map(map: &BTreeMap<String, String>) -> Result<SourceProfile, String> {
    let device_initial_sdk_int = match map.get("DEVICE_INITIAL_SDK_INT") {
        Some(value) => {
            validate_launch_sdk(value)?;
            Some(value.clone())
        }
        None => None,
    };
    let source = SourceProfile {
        fingerprint: required(map, "FINGERPRINT")?,
        manufacturer: required(map, "MANUFACTURER")?,
        model: required(map, "MODEL")?,
        security_patch: required(map, "SECURITY_PATCH")?,
        device_initial_sdk_int,
    };
    validate_display_value("MANUFACTURER", &source.manufacturer)?;
    validate_display_value("MODEL", &source.model)?;
    Ok(source)
}

fn required(map: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    map.get(key)
        .cloned()
        .ok_or_else(|| format!("PIF profile lacks {key}"))
}

fn validate_launch_sdk(value: &str) -> Result<(), String> {
    if !value.bytes().all(|byte| byte.is_ascii_digit())
        || !matches!(value.parse::<i32>(), Ok(sdk) if sdk > 0)
    {
        return Err("DEVICE_INITIAL_SDK_INT must be a positive 32-bit integer".to_string());
    }
    Ok(())
}

fn parse_fingerprint(value: &str) -> Result<FingerprintParts<'_>, String> {
    validate_length_and_ascii("FINGERPRINT", value)?;
    let colon_parts: Vec<&str> = value.split(':').collect();
    if colon_parts.len() != 3 {
        return Err("fingerprint must contain exactly eight components".to_string());
    }
    let identity: Vec<&str> = colon_parts[0].split('/').collect();
    let build: Vec<&str> = colon_parts[1].split('/').collect();
    let variant: Vec<&str> = colon_parts[2].split('/').collect();
    if identity.len() != 3 || build.len() != 3 || variant.len() != 2 {
        return Err("fingerprint must contain exactly eight components".to_string());
    }
    let parts = FingerprintParts {
        brand: identity[0],
        product: identity[1],
        device: identity[2],
        release: build[0],
        id: build[1],
        incremental: build[2],
        build_type: variant[0],
        tags: variant[1],
    };
    for (name, part) in [
        ("brand", parts.brand),
        ("product", parts.product),
        ("device", parts.device),
        ("release", parts.release),
        ("id", parts.id),
        ("incremental", parts.incremental),
        ("build_type", parts.build_type),
        ("tags", parts.tags),
    ] {
        validate_component(name, part)?;
    }
    validate_product(parts.product)?;
    Ok(parts)
}

fn validate_component(name: &str, value: &str) -> Result<(), String> {
    validate_length_and_ascii(name, value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'+' | b',')
    }) {
        return Err(format!("{name} contains an unsupported character"));
    }
    Ok(())
}

fn validate_display_value(name: &str, value: &str) -> Result<(), String> {
    validate_length_and_ascii(name, value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b' ' | b'_' | b'.' | b'-' | b'+' | b'(' | b')')
    }) {
        return Err(format!("{name} contains an unsupported character"));
    }
    Ok(())
}

fn validate_length_and_ascii(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(format!("{name} exceeds the {MAX_VALUE_BYTES} byte limit"));
    }
    if value.trim() != value || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(format!("{name} must be trimmed printable ASCII"));
    }
    Ok(())
}

fn validate_security_patch_date(value: &str) -> Result<(), String> {
    validate_length_and_ascii("SECURITY_PATCH", value)?;
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err("SECURITY_PATCH must use YYYY-MM-DD".to_string());
    }
    let year = value[0..4].parse::<u32>().map_err(|_| "invalid year")?;
    let month = value[5..7].parse::<u32>().map_err(|_| "invalid month")?;
    let day = value[8..10].parse::<u32>().map_err(|_| "invalid day")?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err("SECURITY_PATCH contains an invalid month".to_string()),
    };
    if year < 2000 || day == 0 || day > max_day {
        return Err("SECURITY_PATCH is not a valid calendar date".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROP: &str = "FINGERPRINT=google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel 6\nSECURITY_PATCH=2026-08-05\n";

    fn selected() -> DeviceEntry {
        DeviceEntry {
            model: "Pixel 6".to_string(),
            product: "oriole_beta".to_string(),
        }
    }

    fn sample() -> PifProfile {
        PifProfile::from_source(&selected(), PROP.as_bytes()).unwrap()
    }

    #[test]
    fn parses_catalog_and_rejects_duplicates_or_unknown_fields() {
        let catalog = br#"[{"model":"Pixel 6","product":"oriole_beta"}]"#;
        assert_eq!(parse_catalog(catalog).unwrap(), vec![selected()]);
        assert!(parse_catalog(
            br#"[{"model":"Pixel 6","product":"oriole_beta"},{"model":"Other","product":"oriole_beta"}]"#
        )
        .is_err());
        assert!(parse_catalog(
            br#"[{"model":"Pixel 6","product":"oriole_beta","url":"https://example.com"}]"#
        )
        .is_err());
    }

    #[test]
    fn catalog_enforces_entry_and_byte_limits() {
        let entries = (0..=MAX_CATALOG_ENTRIES)
            .map(|index| format!(r#"{{"model":"Pixel {index}","product":"pixel_{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_catalog(format!("[{entries}]").as_bytes()).is_err());
        assert!(parse_catalog(&vec![b' '; MAX_CATALOG_BYTES + 1]).is_err());
    }

    #[test]
    fn product_validation_blocks_path_syntax_and_mixed_case() {
        for product in ["oriole_beta", "pixel10", "a_b"] {
            validate_product(product).unwrap();
        }
        for product in ["", "../oriole", "oriole.prop", "Pixel_6", "a-b", "_oriole"] {
            assert!(validate_product(product).is_err(), "{product}");
        }
    }

    #[test]
    fn source_profile_expands_all_fingerprint_fields() {
        let profile = sample();
        assert_eq!(profile.brand, "google");
        assert_eq!(profile.product, "oriole_beta");
        assert_eq!(profile.device, "oriole");
        assert_eq!(profile.release, "CANARY");
        assert_eq!(profile.id, "ZP11.260717.006");
        assert_eq!(profile.incremental, "16004061");
        assert_eq!(profile.build_type, "user");
        assert_eq!(profile.tags, "release-keys");
        assert_eq!(profile.device_initial_sdk_int, "32");
    }

    #[test]
    fn source_profile_accepts_optional_launch_sdk() {
        for sdk in ["21", "32", "37"] {
            let source = format!("{PROP}DEVICE_INITIAL_SDK_INT={sdk}\n");
            let profile = PifProfile::from_source(&selected(), source.as_bytes()).unwrap();
            assert_eq!(profile.device_initial_sdk_int, sdk);
        }
    }

    #[test]
    fn source_profile_rejects_unknown_keys_and_missing_fields() {
        assert!(PifProfile::from_source(
            &selected(),
            format!("{PROP}spoofBuild=true\n").as_bytes()
        )
        .is_err());
        assert!(PifProfile::from_source(&selected(), b"MODEL=Pixel 6\n").is_err());
        assert!(
            PifProfile::from_source(&selected(), format!("{PROP}MODEL=Pixel 6\n").as_bytes())
                .is_err()
        );
    }

    #[test]
    fn round_trips_through_pif_prop_with_options() {
        let options = PifOptions {
            spoof_build: true,
            spoof_props: false,
            spoof_provider: true,
            spoof_signature: true,
            spoof_vending_build: false,
            spoof_vending_sdk: true,
            debug: true,
        };
        let profile = sample().with_options(options);
        let rendered = profile.to_prop().unwrap();
        assert!(rendered.contains("spoofProvider=true\n"));
        assert!(rendered.contains("spoofProps=false\n"));
        assert!(rendered.contains("DEBUG=true\n"));
        assert_eq!(PifProfile::from_prop(rendered.as_bytes()).unwrap(), profile);
    }

    #[test]
    fn stored_prop_rejects_unknown_keys_and_bad_bools() {
        let rendered = sample().to_prop().unwrap();
        assert!(PifProfile::from_prop(format!("{rendered}extra=1\n").as_bytes()).is_err());
        assert!(PifProfile::from_prop(
            rendered
                .replace("spoofBuild=true", "spoofBuild=yes")
                .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn source_profile_requires_catalog_model_and_product_match() {
        assert!(PifProfile::from_source(
            &DeviceEntry {
                model: "Pixel 6 Pro".to_string(),
                product: "oriole_beta".to_string(),
            },
            PROP.as_bytes(),
        )
        .is_err());
        assert!(PifProfile::from_source(
            &DeviceEntry {
                model: "Pixel 6".to_string(),
                product: "raven_beta".to_string(),
            },
            PROP.as_bytes(),
        )
        .is_err());
    }

    #[test]
    fn source_profile_rejects_non_google_devices() {
        let non_google = PROP
            .replace("google/oriole_beta", "example/oriole_beta")
            .replace("MANUFACTURER=Google", "MANUFACTURER=Example");
        assert!(PifProfile::from_source(&selected(), non_google.as_bytes()).is_err());
    }

    #[test]
    fn validates_real_calendar_patch_dates() {
        let mut profile = sample();
        for valid in ["2024-02-29", "2026-08-05"] {
            profile.security_patch = valid.to_string();
            profile.validate().unwrap();
        }
        for invalid in ["2023-02-29", "2026-13-05", "2026-04-31", "1999-12-31"] {
            profile.security_patch = invalid.to_string();
            assert!(profile.validate().is_err(), "{invalid}");
        }
    }

    #[test]
    fn every_external_value_obeys_the_byte_limit() {
        let oversized = "A".repeat(MAX_VALUE_BYTES + 1);
        let malformed = PROP.replace("Pixel 6", &oversized);
        assert!(PifProfile::from_source(&selected(), malformed.as_bytes()).is_err());
    }
}
