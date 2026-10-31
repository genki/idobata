use crate::error::{INVALID, Result, STORAGE};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
pub fn random_id() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn canonical<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(v).map_err(|_| INVALID)
}
pub fn valid_id(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_alias(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}
pub fn read_bounded(path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path).map_err(|_| STORAGE)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > max {
        return Err(STORAGE);
    }
    let mut v = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(|_| STORAGE)?
        .take(max + 1)
        .read_to_end(&mut v)
        .map_err(|_| STORAGE)?;
    if v.len() as u64 > max {
        return Err(STORAGE);
    }
    Ok(v)
}
pub fn protected(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| STORAGE)?;
    if m.file_type().is_symlink() {
        return Err(STORAGE);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.mode() & 0o077 != 0 || (m.uid() != unsafe { libc::geteuid() } && m.uid() != 0) {
            return Err(STORAGE);
        }
    }
    #[cfg(windows)]
    crate::windows_security::validate(path)?;
    Ok(())
}
pub fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        protected(path)?;
        if !path.is_dir() {
            return Err(STORAGE);
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = fs::DirBuilder::new();
        b.recursive(true).mode(0o700);
        b.create(path).map_err(|_| STORAGE)?;
    }
    #[cfg(windows)]
    {
        fs::create_dir_all(path).map_err(|_| STORAGE)?;
        windows_acl(path)?;
    }
    Ok(())
}
#[cfg(windows)]
pub fn current_sid() -> Result<String> {
    static SID: std::sync::OnceLock<Result<String>> = std::sync::OnceLock::new();
    SID.get_or_init(|| {
        let out = std::process::Command::new("whoami.exe")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .map_err(|_| STORAGE)?;
        let text = String::from_utf8_lossy(&out.stdout);
        let sid = text
            .split('"')
            .find(|s| {
                s.starts_with("S-1-")
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
            })
            .ok_or(STORAGE)?;
        Ok(sid.to_string())
    })
    .clone()
}
#[cfg(windows)]
fn windows_acl(path: &Path) -> Result<()> {
    let sid = current_sid()?;
    let grant = format!("*{sid}:(OI)(CI)F");
    let out = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant, "*S-1-5-18:(OI)(CI)F"])
        .output()
        .map_err(|_| STORAGE)?;
    if !out.status.success() {
        return Err(STORAGE);
    }
    Ok(())
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(STORAGE)?;
    let tmp = parent.join(format!(".{}.tmp", random_id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp).map_err(|_| STORAGE)?;
        f.write_all(bytes).map_err(|_| STORAGE)?;
        f.sync_all().map_err(|_| STORAGE)?;
        fs::rename(&tmp, path).map_err(|_| STORAGE)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| STORAGE)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
pub fn disable_core_dumps() {
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
        libc::umask(0o077);
    }
}
