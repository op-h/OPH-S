//! FFI to the C++ helpers in `native/oph_native.cpp` plus small OS utilities.

#[cfg(windows)]
extern "C" {
    fn oph_trim_working_sets() -> i32;
    fn oph_trim_self() -> i32;
    fn oph_background_mode(enable: i32) -> i32;
    fn oph_is_elevated() -> i32;
    fn oph_logical_drives() -> u32;
    fn oph_protect(input: *const u8, len: u32, out: *mut *mut u8, out_len: *mut u32, decrypt: i32) -> i32;
    fn oph_free(p: *mut u8);
    fn oph_known_folder(which: i32, out: *mut u16, cap: i32) -> i32;
    fn oph_delete_on_reboot(path: *const u16) -> i32;
    fn oph_volume_guid(letter: u16, out: *mut u16, cap: i32) -> i32;
}

/// Real path of a Windows known folder (follows OneDrive / moved-folder redirection).
/// 0 Desktop, 1 Documents, 2 Downloads, 3 Startup (user), 4 Startup (all users).
pub fn known_folder(which: i32) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    unsafe {
        let mut buf = [0u16; 1024];
        let n = oph_known_folder(which, buf.as_mut_ptr(), buf.len() as i32);
        if n > 0 {
            return Some(std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n as usize])));
        }
    }
    let _ = which;
    None
}

/// Ask Windows to delete `path` at the next restart.
pub fn delete_on_reboot(path: &std::path::Path) -> bool {
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        let w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        return oph_delete_on_reboot(w.as_ptr()) == 1;
    }
    #[allow(unreachable_code)]
    {
        let _ = path;
        false
    }
}

/// Volume GUID path for a drive letter (Windows), e.g. `\\?\Volume{…}\`.
pub fn volume_guid(letter: char) -> Option<String> {
    #[cfg(windows)]
    unsafe {
        let mut buf = [0u16; 64];
        let n = oph_volume_guid(letter as u16, buf.as_mut_ptr(), buf.len() as i32);
        if n > 0 {
            return Some(String::from_utf16_lossy(&buf[..n as usize]));
        }
    }
    let _ = letter;
    None
}

/// Current drive letter of a volume identified by its GUID path.
pub fn letter_for_volume(guid: &str) -> Option<char> {
    #[cfg(windows)]
    unsafe {
        let mask = oph_logical_drives();
        for i in 0..26u32 {
            if mask & (1 << i) != 0 {
                let l = (b'A' + i as u8) as char;
                if volume_guid(l).as_deref().map(|g| g.eq_ignore_ascii_case(guid)).unwrap_or(false) {
                    return Some(l);
                }
            }
        }
    }
    let _ = guid;
    None
}

pub fn trim_working_sets() -> i32 {
    #[cfg(windows)]
    unsafe {
        oph_trim_working_sets()
    }
    #[cfg(not(windows))]
    0
}

pub fn trim_self() {
    #[cfg(windows)]
    unsafe {
        oph_trim_self();
    }
}

/// Lowest CPU / IO / memory priority for the calling thread while `f` runs.
pub fn background<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(windows)]
    unsafe {
        oph_background_mode(1);
    }
    let r = f();
    #[cfg(windows)]
    unsafe {
        oph_background_mode(0);
    }
    r
}

pub fn is_elevated() -> bool {
    #[cfg(windows)]
    unsafe {
        oph_is_elevated() == 1
    }
    #[cfg(not(windows))]
    false
}

/// Run a console program without flashing a window. Returns (exit ok, stdout).
pub fn run_hidden(cmd: &str, args: &[&str]) -> std::io::Result<(bool, String)> {
    let mut c = std::process::Command::new(cmd);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = c.output()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        text.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Ok((out.status.success(), text))
}

/// Encrypt (`decrypt = false`) or decrypt a secret with Windows DPAPI for the current user.
/// Only this Windows account on this PC can decrypt it.
pub fn dpapi(data: &[u8], decrypt: bool) -> Option<Vec<u8>> {
    #[cfg(windows)]
    unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut n: u32 = 0;
        if oph_protect(data.as_ptr(), data.len() as u32, &mut out, &mut n, decrypt as i32) == 1 {
            let v = std::slice::from_raw_parts(out, n as usize).to_vec();
            oph_free(out);
            return Some(v);
        }
    }
    let _ = (data, decrypt);
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn dpapi_roundtrip() {
        let enc = super::dpapi(b"deco-secret", false).expect("protect");
        assert_ne!(enc, b"deco-secret");
        assert_eq!(super::dpapi(&enc, true).expect("unprotect"), b"deco-secret");
    }
}
