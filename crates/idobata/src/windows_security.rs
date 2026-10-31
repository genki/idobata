//! Validate the actual filesystem DACL. SYSTEM and local administrators are trusted OS principals.
use crate::error::{Result, STORAGE};
use std::{ffi::c_void, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, GetAce, OWNER_SECURITY_INFORMATION,
    },
    System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
};
unsafe fn sid_string(sid: *mut c_void) -> Result<String> {
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(STORAGE);
    }
    let mut len = 0;
    while len < 256 && unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    let text = if len >= 256 {
        Err(STORAGE)
    } else {
        String::from_utf16(unsafe { std::slice::from_raw_parts(value, len) }).map_err(|_| STORAGE)
    };
    unsafe {
        LocalFree(value as *mut c_void);
    }
    text
}
pub fn validate(path: &Path) -> Result<()> {
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(STORAGE);
    }
    let result = (|| {
        if owner.is_null() || dacl.is_null() {
            return Err(STORAGE);
        }
        let own = crate::util::current_sid()?;
        let owner_sid = unsafe { sid_string(owner) }?;
        if ![own.as_str(), "S-1-5-18", "S-1-5-32-544"].contains(&owner_sid.as_str()) {
            return Err(STORAGE);
        }
        for index in 0..unsafe { (*dacl).AceCount } as u32 {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(STORAGE);
            }
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            if header.AceType as u32 == ACCESS_DENIED_ACE_TYPE {
                continue;
            }
            if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE {
                return Err(STORAGE);
            }
            let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
            let sid = unsafe { sid_string(&allowed.SidStart as *const u32 as *mut c_void) }?;
            if ![own.as_str(), "S-1-5-18", "S-1-5-32-544"].contains(&sid.as_str()) {
                return Err(STORAGE);
            }
        }
        Ok(())
    })();
    unsafe {
        LocalFree(descriptor);
    }
    result
}
