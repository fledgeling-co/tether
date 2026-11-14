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
    /// A base64 32-byte key shared with the target. When set, the host proves the connecting
    /// device to the target before forwarding (see `identify`). TCP services only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub public_key: String,
    pub services: BTreeSet<String>,
    /// The label the device gave when it paired nearby. Shown to the owner, never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
            if let Some(identity) = &service.identity {
                if service.kind != ServiceKind::Tcp {
                    return Err("only TCP services can identify the connecting device".into());
                }
                key(identity)?;
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

/// How long a configuration write waits for another holder before it gives up and says so.
/// A caller that waits for ever has no way to tell a slow write from a wedged one.
pub const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Pause between attempts while waiting.
const LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(25);

/// The exclusive lock around one configuration file, with a bounded wait and a cleanup protocol.
///
/// There is no stale *lock*: the operating system releases an `flock` when its holder dies, so a
/// lock file left behind by a crash blocks nothing. What is stale is the file, and removing it is
/// what races a second caller between its `open` and its lock. The protocol closes that race
/// rather than leaving the file behind:
///
/// * the holder unlinks the lock file while it still holds the lock, so nobody can open it again
///   under that name before the lock is released;
/// * every acquirer, having taken the lock, checks that the file it locked is still the one at
///   that path. A caller that locked a file somebody else had already unlinked starts again, so
///   two callers can never hold locks on two different files for the same configuration.
///
/// Windows needs neither half: `open_lock` opens without `FILE_SHARE_DELETE`, so the file cannot
/// be unlinked while any holder has it open, and the removal is attempted after the handle closes
/// and fails harmlessly when another holder has taken it by then.
struct ConfigLock {
    /// Taken only so the lock lives as long as the operation. `Drop` closes it before the
    /// Windows removal, because a lock file open without `FILE_SHARE_DELETE` cannot be unlinked.
    #[allow(
        dead_code,
        reason = "held for the lock's lifetime; read by Drop on Windows"
    )]
    file: Option<fs::File>,
    path: PathBuf,
}

impl ConfigLock {
    /// Takes the lock for `config`, waiting at most [`LOCK_TIMEOUT`].
    fn acquire(config: &Path) -> Result<Self> {
        let path = PathBuf::from(format!("{}.lock", config.display()));
        let deadline = std::time::Instant::now() + LOCK_TIMEOUT;
        loop {
            let file = private_lock(&path)?;
            loop {
                match file.try_lock_exclusive() {
                    Ok(()) => break,
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(LOCK_RETRY)
                    }
                    Err(_) => return Err(busy(&path).into()),
                }
            }
            if same_lock_file(&file, &path)? {
                record_holder(&file);
                return Ok(Self {
                    file: Some(file),
                    path,
                });
            }
            // The file we locked had already been unlinked by its previous holder; the live lock
            // is whatever is at that path now, so take it from the top.
            drop(file);
            if std::time::Instant::now() >= deadline {
                return Err(busy(&path).into());
            }
        }
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        // Unix: removed while the lock is still held, which is what makes the acquirer's identity
        // check sufficient. Windows: removed after the handle closes, and refused if another
        // holder has it open, which is equally safe because it cannot be removed while open.
        #[cfg(not(windows))]
        let _ = fs::remove_file(&self.path);
        #[cfg(windows)]
        {
            drop(self.file.take());
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// What a caller is told when the wait runs out. It names the file and the holder it could find,
/// because "operation failed" over a lock is the message that sends people looking at the wrong
/// thing — a lock file lying beside a configuration is inert, and a live holder is not.
fn busy(lock_path: &Path) -> String {
    let holder = fs::read_to_string(lock_path)
        .ok()
        .and_then(|text| {
            let line = text.lines().next()?.trim().to_owned();
            (!line.is_empty() && line.len() <= 64).then_some(line)
        })
        .unwrap_or_else(|| "unknown".into());
    format!(
        "another process is still writing this configuration: waited {}s for {} (holder: {}). \
         Retry, or stop the process holding it; the lock file alone blocks nothing.",
        LOCK_TIMEOUT.as_secs(),
        lock_path.display(),
        holder
    )
}

/// Leaves the holder's process id in the lock file for the message above. Diagnostic only:
/// nothing reads it to decide whether the lock is held, which is the operating system's answer.
fn record_holder(file: &fs::File) {
    #[cfg(not(windows))]
    {
        use std::io::{Seek, SeekFrom};
        let mut handle = file;
        let _ = handle.seek(SeekFrom::Start(0));
        let _ = file.set_len(0);
        let _ = handle.write_all(format!("pid {}\n", std::process::id()).as_bytes());
        let _ = file.sync_data();
    }
    #[cfg(windows)]
    let _ = file;
}

/// Whether the locked file is still the one at `path`. On Windows nothing can unlink an open
/// lock file, so there is nothing to re-check.
fn same_lock_file(file: &fs::File, path: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let held = file.metadata()?;
        Ok(match fs::metadata(path) {
            Ok(current) => current.dev() == held.dev() && current.ino() == held.ino(),
            Err(_) => false,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        Ok(true)
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
    let _lock = ConfigLock::acquire(path)?;
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
    let _lock = ConfigLock::acquire(path)?;
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
    let _lock = ConfigLock::acquire(path)?;
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
mod lock_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn fixture() -> (PathBuf, PathBuf) {
        let parent =
            std::env::temp_dir().join(format!("tether-config-lock-{}", rand::random::<u128>()));
        let path = parent.join("host.profile");
        let config = HostConfig::new(
            "test.lock",
            BTreeMap::from([(
                "api".into(),
                Service {
                    kind: ServiceKind::Tcp,
                    target: "127.0.0.1:1234".parse().unwrap(),
                    identity: None,
                },
            )]),
        )
        .unwrap();
        create(&path, &config).unwrap();
        (parent, path)
    }

    #[test]
    fn a_live_holder_times_out_with_a_message_naming_the_lock_and_its_holder() {
        let (parent, path) = fixture();
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        // A second file description in this process conflicts exactly as another process does:
        // flock locks the description, not the process.
        let held = ConfigLock::acquire(&path).unwrap();
        let started = Instant::now();
        let error = update_host(&path, |_| Ok(()))
            .expect_err("a live holder must not be waited on for ever");
        let waited = started.elapsed();
        let text = format!("{error:?}");
        assert!(
            text.contains("another process is still writing this configuration"),
            "{text}"
        );
        assert!(text.contains(&lock_path.display().to_string()), "{text}");
        assert!(
            text.contains(&format!("pid {}", std::process::id())),
            "the holder is named rather than guessed at: {text}"
        );
        assert!(
            waited >= LOCK_TIMEOUT && waited < LOCK_TIMEOUT + Duration::from_secs(5),
            "waited {waited:?}, which is not the declared timeout"
        );
        drop(held);
        // With the holder gone the same write succeeds, so the timeout is a wait and not a refusal.
        update_host(&path, |config| {
            config.services.insert(
                "second".into(),
                Service {
                    kind: ServiceKind::Udp,
                    target: "127.0.0.1:1235".parse().unwrap(),
                    identity: None,
                },
            );
            Ok(())
        })
        .unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn the_lock_file_does_not_outlive_the_operation_that_created_it() {
        let (parent, path) = fixture();
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        assert!(!lock_path.exists(), "nothing holds a lock yet");
        update_host(&path, |_| Ok(())).unwrap();
        assert!(
            !lock_path.exists(),
            "every configuration accumulated one of these"
        );
        // An operation that fails inside the closure cleans up too.
        assert!(update_host(&path, |_| Err::<(), Error>("no".into())).is_err());
        assert!(!lock_path.exists());
        // A leftover lock file from an older release is taken over and then removed, not waited on.
        fs::write(&lock_path, b"pid 999999\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let started = Instant::now();
        update_host(&path, |_| Ok(())).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a lock file with no live holder blocks nothing"
        );
        assert!(!lock_path.exists());
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_taken_on_an_already_unlinked_file_is_not_accepted() {
        let (parent, path) = fixture();
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        // The race the cleanup protocol closes: one caller opened the lock file, a previous
        // holder unlinked it, and the open file description is all that is left. Locking that
        // must not count, or two callers hold two locks over one configuration.
        let orphan = private_lock(&lock_path).unwrap();
        fs::remove_file(&lock_path).unwrap();
        orphan.try_lock_exclusive().unwrap();
        assert!(
            !same_lock_file(&orphan, &lock_path).unwrap(),
            "the file at that path is not the one this lock is on"
        );
        // So a real acquirer creates a fresh lock file and takes it without waiting.
        let started = Instant::now();
        let fresh = ConfigLock::acquire(&path).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(same_lock_file(fresh.file.as_ref().unwrap(), &lock_path).unwrap());
        drop(fresh);
        drop(orphan);
        fs::remove_dir_all(parent).unwrap();
    }
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
                    identity: None,
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
                        identity: None,
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
                        name: None,
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
