// OPH Sentinel — native Win32 helpers (C++).
// Kept deliberately small: only APIs where a direct native call is the
// cheapest path. Exposed with C linkage for Rust FFI.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <vector>

extern "C" {

// Trim the working set of every process we are allowed to open.
// Pages move to the standby list; Windows faults them back in on demand.
// Returns the number of processes trimmed.
int oph_trim_working_sets(void) {
    std::vector<DWORD> pids(4096);
    DWORD bytes = 0;
    if (!EnumProcesses(pids.data(), (DWORD)(pids.size() * sizeof(DWORD)), &bytes)) return 0;
    const DWORD count = bytes / sizeof(DWORD);
    int trimmed = 0;
    for (DWORD i = 0; i < count; ++i) {
        if (pids[i] == 0) continue;
        HANDLE h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!h) continue;
        if (EmptyWorkingSet(h)) ++trimmed;
        CloseHandle(h);
    }
    return trimmed;
}

// Trim only our own process (used after the UI window is closed).
int oph_trim_self(void) {
    return EmptyWorkingSet(GetCurrentProcess()) ? 1 : 0;
}

// Enter/leave background processing mode for the calling thread:
// lowest CPU, I/O and memory priority. Used for cleaner scans.
int oph_background_mode(int enable) {
    return SetThreadPriority(GetCurrentThread(),
        enable ? THREAD_MODE_BACKGROUND_BEGIN : THREAD_MODE_BACKGROUND_END) ? 1 : 0;
}

// 1 if the process token is elevated (Run as administrator).
int oph_is_elevated(void) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    TOKEN_ELEVATION el{};
    DWORD len = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &el, sizeof(el), &len);
    CloseHandle(token);
    return ok && el.TokenIsElevated ? 1 : 0;
}

// DPAPI: encrypt/decrypt a secret for the current Windows user (CurrentUser scope).
// Output buffer is LocalAlloc'd by Windows; free it with oph_free.
int oph_protect(const unsigned char* in, unsigned int len, unsigned char** out, unsigned int* out_len, int decrypt) {
    DATA_BLOB src{ len, const_cast<BYTE*>(in) }, dst{ 0, nullptr };
    BOOL ok = decrypt
        ? CryptUnprotectData(&src, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &dst)
        : CryptProtectData(&src, L"OPH-S router credential", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &dst);
    if (!ok) return 0;
    *out = dst.pbData;
    *out_len = dst.cbData;
    return 1;
}

void oph_free(void* p) {
    if (p) LocalFree(p);
}

// Real location of a user folder, following redirection (OneDrive Desktop/Documents,
// Downloads moved to another drive, ...). which: 0 Desktop, 1 Documents, 2 Downloads,
// 3 Startup (user), 4 Startup (all users). Returns length written, 0 on failure.
int oph_known_folder(int which, wchar_t* out, int cap) {
    const KNOWNFOLDERID* ids[] = { &FOLDERID_Desktop, &FOLDERID_Documents, &FOLDERID_Downloads, &FOLDERID_Startup, &FOLDERID_CommonStartup };
    if (which < 0 || which > 4) return 0;
    PWSTR path = nullptr;
    if (FAILED(SHGetKnownFolderPath(*ids[which], KF_FLAG_DEFAULT, nullptr, &path))) return 0;
    int n = (int)wcslen(path);
    int ok = n < cap ? n : 0;
    if (ok) wcscpy_s(out, cap, path);
    CoTaskMemFree(path);
    return ok;
}

// Bitmask of present drive letters (bit 0 = A:).
unsigned int oph_logical_drives(void) {
    return (unsigned int)GetLogicalDrives();
}

// Volume GUID path ("\\?\Volume{...}\") of a drive letter, as UTF-16 into `out`.
// Stable across drive-letter changes, so an external disk is recognised wherever
// Windows mounts it. Returns the length written, or 0.
int oph_volume_guid(wchar_t letter, wchar_t* out, int cap) {
    wchar_t root[4] = { letter, L':', L'\\', 0 };
    if (cap < 50) return 0;
    if (!GetVolumeNameForVolumeMountPointW(root, out, (DWORD)cap)) return 0;
    return (int)wcslen(out);
}

}  // extern "C"
