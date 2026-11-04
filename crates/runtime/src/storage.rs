use crate::carrier::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};
#[cfg(not(windows))]
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};
use tether_core::Identity;

/// Portable bound on the serialized plaintext profile, before encryption or replacement.
pub const MAX_PROFILE_BYTES: usize = 131_072;

#[cfg(windows)]
#[path = "windows_storage.rs"]
mod windows_private;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Tcp,
    Udp,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub kind: ServiceKind,
    pub target: SocketAddr,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub public_key: String,
    pub services: BTreeSet<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub version: u32,
    pub app_id: String,
    pub private_key: String,
    pub registration_key: String,
    pub services: BTreeMap<String, Service>,
    pub devices: BTreeMap<String, Device>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub version: u32,
    pub app_id: String,
    pub private_key: String,
    pub host_key: String,
    pub host_id: Option<String>,
    pub relay_url: Option<String>,
    pub direct: Option<String>,
    #[serde(default)]
    pub confirmed: bool,
}

pub fn app_id(app: &str) -> Result<()> {
    if app.is_empty()
        || app.len() > 64
        || !app
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
    {
        return Err(
            "app ID must be 1-64 ASCII letters, digits, dots, hyphens or underscores".into(),
        );
    }
    Ok(())
}
pub fn key(text: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(text)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
    if STANDARD.encode(key) != text {
        return Err("noncanonical key encoding".into());
    }
    Ok(key)
}
pub fn device_id(public: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(public)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
impl HostConfig {
    pub fn new(app: &str, services: BTreeMap<String, Service>) -> Result<Self> {
        app_id(app)?;
        let identity = Identity::generate()?;
        let mut registration = [0; 32];
        OsRng.fill_bytes(&mut registration);
        let config = Self {
            version: 1,
            app_id: app.to_owned(),
            private_key: STANDARD.encode(identity.private()),
            registration_key: STANDARD.encode(registration),
            services,
            devices: BTreeMap::new(),
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        app_id(&self.app_id)?;
        if self.version != 1
            || self.services.is_empty()
            || self.services.len() > 32
            || self.devices.len() > 256
        {
            return Err("invalid host configuration".into());
        }
        key(&self.private_key)?;
        key(&self.registration_key)?;
        for (name, service) in &self.services {
            app_id(name)?;
            if !service.target.ip().is_loopback() || service.target.port() == 0 {
                return Err("service targets must be fixed loopback addresses".into());
            }
        }
        for (id, device) in &self.devices {
            if *id != device_id(&key(&device.public_key)?) {
                return Err("invalid device identity".into());
            }
            if device
                .services
                .iter()
                .any(|name| !self.services.contains_key(name))
            {
                return Err("device permission names an unknown service".into());
            }
        }
        Ok(())
    }
    pub fn identity(&self) -> Result<Identity> {
        Ok(Identity::from_private(key(&self.private_key)?)?)
    }
    pub fn authorize(&self, peer: &[u8; 32], service: &str) -> bool {
        self.devices.get(&device_id(peer)).is_some_and(|device| {
            key(&device.public_key).ok().as_ref() == Some(peer) && device.services.contains(service)
        })
    }
}

#[cfg(not(windows))]
pub fn load<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    require_private_filesystem()?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("configuration must be a regular private file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o77 != 0 {
            return Err("configuration permissions must be 0600".into());
        }
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take((MAX_PROFILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err("configuration exceeds limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
#[cfg(not(windows))]
pub fn create<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serialized(value)?;
    prepare_parent(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}
#[cfg(windows)]
pub fn load<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&windows_private::read(path)?)?)
}
#[cfg(windows)]
pub fn create<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serialized(value)?;
    windows_private::create(path, &bytes)
}
fn serialized<T: Serialize>(value: &T) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec_pretty(value)?);
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err("configuration exceeds limit".into());
    }
    Ok(bytes)
}
fn private_lock(path: &Path) -> Result<fs::File> {
    #[cfg(windows)]
    {
        windows_private::open_lock(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Ok(options.open(path)?)
    }
}
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(not(windows))]
    fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    #[cfg(windows)]
    let _ = path; // Writes are flushed and replacements use MOVEFILE_WRITE_THROUGH.
    Ok(())
}
fn replace_private(from: &Path, to: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows_private::replace(from, to)
    }
    #[cfg(not(windows))]
    {
        Ok(fs::rename(from, to)?)
    }
}
pub fn update_host<T>(
    path: &Path,
    operation: impl FnOnce(&mut HostConfig) -> Result<T>,
) -> Result<T> {
    prepare_parent(path)?;
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let lock = private_lock(&lock_path)?;
    lock.lock_exclusive()?;
    let mut config: HostConfig = load(path)?;
    config.validate()?;
    let result = operation(&mut config)?;
    config.validate()?;
    let temporary = PathBuf::from(format!("{}.{}.tmp", path.display(), rand::random::<u128>()));
    create(&temporary, &config)?;
    if let Err(error) = replace_private(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    sync_parent(path)?;
    Ok(result)
}
pub fn confirm_client(path: &Path, expected: &ClientConfig) -> Result<()> {
    prepare_parent(path)?;
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let lock = private_lock(&lock_path)?;
    lock.lock_exclusive()?;
    let mut config: ClientConfig = load(path)?;
    if &config != expected {
        return Err("client configuration changed during confirmation".into());
    }
    config.confirmed = true;
    let temporary = PathBuf::from(format!("{}.{}.tmp", path.display(), rand::random::<u128>()));
    create(&temporary, &config)?;
    if let Err(error) = replace_private(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    sync_parent(path)?;
    Ok(())
}
/// Explicit owner recovery. A confirmed pairing or another application's record is never removed.
pub fn abandon_pending(path: &Path, expected_app: &str) -> Result<String> {
    app_id(expected_app)?;
    prepare_parent(path)?;
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let lock = private_lock(&lock_path)?;
    lock.lock_exclusive()?;
    let config: ClientConfig = load(path)?;
    if config.version != 1 || config.app_id != expected_app || config.confirmed {
        return Err("only an unconfirmed pairing for this application may be abandoned".into());
    }
    let identity = Identity::from_private(key(&config.private_key)?)?;
    let public = device_id(&identity.public());
    fs::remove_file(path)?;
    sync_parent(path)?;
    Ok(public)
}
#[cfg(not(windows))]
fn prepare_parent(path: &Path) -> Result<()> {
    require_private_filesystem()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent)?;
    }
    if fs::symlink_metadata(parent)?.file_type().is_symlink() {
        return Err("configuration parent must not be a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(parent)?.permissions().mode() & 0o77 != 0 {
            return Err("configuration directory must be 0700".into());
        }
    }
    Ok(())
}
pub fn fixed_error(_: Error) -> &'static str {
    "operation failed; check endpoint, pairing and permissions"
}

// The CLI's secret-file policy is POSIX-specific. Native non-Unix consumers use their own
// protected store with the socket-free core; silently skipping ACL checks is not a fallback.
#[cfg(not(windows))]
fn require_private_filesystem() -> Result<()> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err("CLI private-file storage requires Unix permissions; use a native protected-store adapter".into())
    }
}

#[cfg(windows)]
fn prepare_parent(path: &Path) -> Result<()> {
    windows_private::prepare_parent(path)
}

#[cfg(test)]
mod profile_limit_tests {
    use super::*;
    #[test]
    fn oversized_create_and_host_replacement_never_write_or_change_prior_bytes() {
        let parent =
            std::env::temp_dir().join(format!("tether-profile-limit-{}", rand::random::<u128>()));
        let path = parent.join("host.profile");
        let initial = HostConfig::new(
            "test.limit",
            BTreeMap::from([(
                "api".into(),
                Service {
                    kind: ServiceKind::Tcp,
                    target: "127.0.0.1:1234".parse().unwrap(),
                },
            )]),
        )
        .unwrap();
        create(&path, &initial).unwrap();
        let before = fs::read(&path).unwrap();
        let huge = parent.join("oversized.profile");
        assert!(create(&huge, &vec![0u8; MAX_PROFILE_BYTES]).is_err());
        assert!(!huge.exists());
        assert!(update_host(&path, |config| {
            for i in 0..31 {
                config.services.insert(
                    format!("service{:0>57}", i),
                    Service {
                        kind: ServiceKind::Udp,
                        target: "127.0.0.1:1234".parse().unwrap(),
                    },
                );
            }
            for i in 0..=255u8 {
                let key = [i; 32];
                config.devices.insert(
                    device_id(&key),
                    Device {
                        public_key: STANDARD.encode(key),
                        services: config.services.keys().cloned().collect(),
                    },
                );
            }
            config.validate()?;
            assert!(serde_json::to_vec_pretty(config)?.len() > MAX_PROFILE_BYTES);
            Ok(())
        })
        .is_err());
        assert!(fs::read(&path).unwrap() == before);
        let loaded: HostConfig = load(&path).unwrap();
        assert!(loaded.devices.is_empty());
        fs::remove_dir_all(parent).unwrap();
    }
}
