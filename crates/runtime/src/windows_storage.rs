//! Current-user DPAPI with an owner-only, protected DACL established at creation time.
//! Refuse broad existing directories, reparse points, wrong owners and corrupt envelopes.
use crate::carrier::Result;
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT,
        },
        Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
        *,
    },
    Storage::FileSystem::*,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
use zeroize::Zeroizing;
const MAGIC: &[u8] = b"TETHER-DPAPI-USER\0\x01";
const MAX: usize = super::MAX_PROFILE_BYTES;
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
fn checked(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("Windows protected storage refused".into())
    }
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    checked(
        matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_))),
    )?;
    checked(!path.as_os_str().encode_wide().any(|c| c == 0))?;
    Ok(path)
}
fn no_reparse(path: &Path) -> Result<()> {
    for component in path.ancestors() {
        let attributes = unsafe { GetFileAttributesW(wide(component).as_ptr()) };
        if attributes != INVALID_FILE_ATTRIBUTES {
            checked(attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0)?;
        }
    }
    Ok(())
}
fn current_sid() -> Result<Vec<u8>> {
    unsafe {
        let mut token: HANDLE = null_mut();
        checked(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0)?;
        let result = (|| {
            let mut size = 0;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);
            checked(size > 0 && size <= 65536)?;
            let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
            checked(
                GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size)
                    != 0,
            )?;
            let sid = (*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid;
            checked(IsValidSid(sid) != 0)?;
            let length = GetLengthSid(sid);
            let mut copy = vec![0u8; length as usize];
            checked(CopySid(length, copy.as_mut_ptr().cast(), sid) != 0)?;
            Ok(copy)
        })();
        CloseHandle(token);
        result
    }
}
fn descriptor() -> Result<Local> {
    unsafe {
        let sid = current_sid()?;
        let mut text = null_mut();
        checked(ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut text) != 0)?;
        let allocation = Local(text.cast());
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sid_text = String::from_utf16(std::slice::from_raw_parts(text, len))?;
        drop(allocation);
        let sddl: Vec<u16> = format!("O:{sid_text}D:P(A;;FA;;;{sid_text})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut sd = null_mut();
        checked(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                null_mut(),
            ) != 0,
        )?;
        Ok(Local(sd))
    }
}
fn with_security<T>(operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> Result<T>) -> Result<T> {
    let sd = descriptor()?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    operation(&attrs)
}
pub(crate) fn validate_private(path: &Path) -> Result<()> {
    let path = absolute(path)?;
    no_reparse(&path)?;
    unsafe {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut sd = null_mut();
        checked(
            GetNamedSecurityInfoW(
                wide(&path).as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            ) == 0,
        )?;
        let _allocation = Local(sd);
        validate_security(sd, owner, dacl)
    }
}
unsafe fn validate_security(sd: *mut c_void, owner: *mut c_void, dacl: *mut ACL) -> Result<()> {
    let sid = current_sid()?;
    checked(
        !owner.is_null() && !dacl.is_null() && EqualSid(owner, sid.as_ptr().cast_mut().cast()) != 0,
    )?;
    let mut control = 0;
    let mut revision = 0;
    checked(
        GetSecurityDescriptorControl(sd, &mut control, &mut revision) != 0
            && control & SE_DACL_PROTECTED != 0,
    )?;
    let mut info: ACL_SIZE_INFORMATION = zeroed();
    checked(
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) != 0
            && info.AceCount == 1,
    )?;
    let mut ace = null_mut();
    checked(GetAce(dacl, 0, &mut ace) != 0 && !ace.is_null())?;
    let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
    let trustee = (&ace.SidStart as *const u32).cast_mut().cast();
    checked(
        ace.Header.AceType == 0
            && ace.Header.AceFlags == 0
            && ace.Mask == FILE_ALL_ACCESS
            && IsValidSid(trustee) != 0
            && EqualSid(trustee, sid.as_ptr().cast_mut().cast()) != 0,
    )
}
fn validate_handle(file: &File) -> Result<()> {
    unsafe {
        let handle = file.as_raw_handle();
        let mut attributes: FILE_ATTRIBUTE_TAG_INFO = zeroed();
        checked(
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            ) != 0
                && attributes.FileAttributes
                    & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                    == 0,
        )?;
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut sd = null_mut();
        checked(
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            ) == 0,
        )?;
        let _allocation = Local(sd);
        validate_security(sd, owner, dacl)
    }
}
fn validate_ancestors(path: &Path) -> Result<()> {
    let sid = current_sid()?;
    for parent in path.ancestors().skip(1).filter(|p| p.exists()) {
        unsafe {
            let mut dacl = null_mut();
            let mut sd = null_mut();
            checked(
                GetNamedSecurityInfoW(
                    wide(parent).as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut dacl,
                    null_mut(),
                    &mut sd,
                ) == 0,
            )?;
            let _allocation = Local(sd);
            checked(!dacl.is_null())?;
            for index in 0..u32::from((*dacl).AceCount) {
                let mut ace = null_mut();
                checked(GetAce(dacl, index, &mut ace) != 0 && !ace.is_null())?;
                let header = &*ace.cast::<ACE_HEADER>();
                if header.AceType != 0 || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                let trustee = (&ace.SidStart as *const u32).cast_mut().cast();
                if EqualSid(trustee, sid.as_ptr().cast_mut().cast()) != 0
                    || IsWellKnownSid(trustee, WinLocalSystemSid) != 0
                    || IsWellKnownSid(trustee, WinBuiltinAdministratorsSid) != 0
                {
                    continue;
                }
                let mut text = null_mut();
                checked(ConvertSidToStringSidW(trustee, &mut text) != 0)?;
                let _text = Local(text.cast());
                let mut len = 0;
                while *text.add(len) != 0 {
                    len += 1;
                }
                let name = String::from_utf16(std::slice::from_raw_parts(text, len))?;
                if name.starts_with("S-1-5-80-") {
                    continue;
                }
                checked(ace.Mask & (FILE_DELETE_CHILD | 0x10000 | 0x40000 | 0x80000) == 0)?;
            }
        }
    }
    Ok(())
}
pub(crate) fn prepare_parent(path: &Path) -> Result<()> {
    let path = absolute(path)?;
    let parent = path
        .parent()
        .ok_or("configuration needs a parent directory")?;
    no_reparse(parent)?;
    validate_ancestors(parent)?;
    let mut missing = Vec::new();
    let mut next = parent;
    while !next.exists() {
        missing.push(next.to_path_buf());
        next = next.parent().ok_or("invalid configuration directory")?;
    }
    for directory in missing.iter().rev() {
        with_security(|attrs| {
            checked(unsafe { CreateDirectoryW(wide(directory).as_ptr(), attrs) } != 0)
        })?;
        validate_private(directory)?;
    }
    validate_private(parent)
}
fn open(path: &Path, create: bool, write: bool) -> Result<File> {
    let path = absolute(path)?;
    no_reparse(&path)?;
    validate_ancestors(&path)?;
    if !create {
        validate_private(&path)?;
    }
    let file = with_security(|attrs| {
        let access = FILE_GENERIC_READ | if write { FILE_GENERIC_WRITE } else { 0 };
        let handle = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                attrs,
                if create { CREATE_NEW } else { OPEN_EXISTING },
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        checked(handle != INVALID_HANDLE_VALUE)?;
        Ok(unsafe { File::from_raw_handle(handle) })
    })?;
    validate_handle(&file)?;
    checked(file.metadata()?.is_file())?;
    Ok(file)
}
fn protect(bytes: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    checked(bytes.len() <= MAX + 16384)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let entropy = b"tether.windows.profile.v1";
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr().cast_mut(),
    };
    unsafe {
        let mut output: CRYPT_INTEGER_BLOB = zeroed();
        let ok = if decrypt {
            CryptUnprotectData(
                &input,
                null_mut(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                null(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        checked(ok != 0)?;
        let allocation = Local(output.pbData.cast());
        let result = if output.cbData as usize > MAX + 16384 {
            Err("protected storage limit exceeded".into())
        } else {
            Ok(Zeroizing::new(
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec(),
            ))
        };
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        drop(allocation);
        result
    }
}
pub(crate) fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Vec::new();
    open(path, false, false)?
        .take((MAX + 16385) as u64)
        .read_to_end(&mut bytes)?;
    checked(bytes.len() <= MAX + 16384 && bytes.starts_with(MAGIC))?;
    let plain = protect(&bytes[MAGIC.len()..], true)?;
    checked(plain.len() <= MAX)?;
    Ok(plain)
}
pub(crate) fn create(path: &Path, plain: &[u8]) -> Result<()> {
    checked(plain.len() <= MAX)?;
    prepare_parent(path)?;
    let encrypted = protect(plain, false)?;
    let mut file = open(path, true, true)?;
    let result = (|| -> Result<()> {
        file.write_all(MAGIC)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}
pub(crate) fn open_lock(path: &Path) -> Result<File> {
    if path.exists() {
        open(path, false, true)
    } else {
        match open(path, true, true) {
            Ok(file) => Ok(file),
            Err(_) if path.exists() => open(path, false, true),
            Err(e) => Err(e),
        }
    }
}
pub(crate) fn replace(from: &Path, to: &Path) -> Result<()> {
    validate_private(from)?;
    validate_private(to)?;
    checked(
        unsafe {
            MoveFileExW(
                wide(from).as_ptr(),
                wide(to).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } != 0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dpapi_current_user_roundtrip_corruption_and_plaintext_refusal() {
        let root =
            std::env::temp_dir().join(format!("tether-windows-store-{}", rand::random::<u128>()));
        let path = root.join("profile");
        let secret = b"synthetic-store-key-not-for-logs";
        create(&path, secret).unwrap();
        validate_private(&path).unwrap();
        assert_eq!(&**read(&path).unwrap(), secret);
        let mut encoded = std::fs::read(&path).unwrap();
        assert!(!encoded.windows(secret.len()).any(|b| b == secret));
        let i = encoded.len() - 1;
        encoded[i] ^= 1;
        std::fs::write(&path, encoded).unwrap();
        assert!(read(&path).is_err());
        std::fs::write(&path, secret).unwrap();
        assert!(read(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn inherited_acl_directory_is_refused_without_tightening() {
        let root =
            std::env::temp_dir().join(format!("tether-public-store-{}", rand::random::<u128>()));
        std::fs::create_dir(&root).unwrap();
        assert!(create(&root.join("profile"), b"secret").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
