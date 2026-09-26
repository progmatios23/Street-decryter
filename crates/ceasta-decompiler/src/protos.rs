//! Well-known WinAPI / libc prototypes for call-site argument naming.

use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Clone, Debug)]
pub struct ProtoParam {
    pub ty: String,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct Prototype {
    pub ret: String,
    pub name: String,
    pub params: Vec<ProtoParam>,
    pub variadic: bool,
    pub stdcall: bool,
}

impl Prototype {
    pub fn format(&self) -> String {
        let mut s = format!("{} {}(", self.ret, self.name);
        if self.params.is_empty() && !self.variadic {
            s.push_str("void");
        } else {
            for (i, p) in self.params.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&p.ty);
                if !p.name.is_empty() {
                    s.push(' ');
                    s.push_str(&p.name);
                }
            }
            if self.variadic {
                if !self.params.is_empty() {
                    s.push_str(", ");
                }
                s.push_str("...");
            }
        }
        s.push(')');
        s
    }
}

/// Look up a well-known prototype by the name a call shows
/// (`CreateFileW`, `__imp_CreateFileW`, `j_printf`, `printf@plt`, `_Sleep@4`).
pub fn known_prototype(name: &str) -> Option<&'static Prototype> {
    let n = normalize_name(name);
    TABLE.get(n.as_str()).or_else(|| {
        // Strip trailing stdcall decoration leftovers.
        let bare = n.trim_end_matches(|c: char| c.is_ascii_digit() || c == '@');
        if bare != n {
            TABLE.get(bare)
        } else {
            None
        }
    })
}

fn normalize_name(name: &str) -> String {
    let mut n = name.trim().to_string();
    for prefix in ["__imp_", "j_", "_imp_"] {
        if let Some(rest) = n.strip_prefix(prefix) {
            n = rest.to_string();
            break;
        }
    }
    if let Some(i) = n.find("@plt") {
        n.truncate(i);
    }
    if let Some(i) = n.find('@') {
        // `_Sleep@4` → `Sleep` after leading underscore strip below
        n.truncate(i);
    }
    if n.starts_with('_') && n.len() > 1 && n.as_bytes()[1].is_ascii_alphabetic() {
        // `_CreateFileW` / `_printf`
        n.remove(0);
    }
    n
}

static TABLE: LazyLock<HashMap<String, Prototype>> = LazyLock::new(build_table);

fn build_table() -> HashMap<String, Prototype> {
    let mut map = HashMap::new();
    for line in PROTOS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(p) = parse_line(line) {
            insert_expanded(&mut map, p);
        }
    }
    map
}

fn insert_expanded(map: &mut HashMap<String, Prototype>, p: Prototype) {
    if p.name.contains('%') {
        for (suffix, subst) in [('A', "CHAR"), ('W', "WCHAR")] {
            let mut q = p.clone();
            q.name = p.name.replace('%', &suffix.to_string());
            for param in &mut q.params {
                param.ty = expand_tchar(&param.ty, subst);
            }
            map.insert(q.name.clone(), q);
        }
    } else {
        map.insert(p.name.clone(), p);
    }
}

fn expand_tchar(ty: &str, wchar_or_char: &str) -> String {
    ty.replace("LPCTSTR", &format!("LPC{wchar_or_char}"))
        .replace("LPTSTR", &format!("LP{wchar_or_char}"))
        .replace("TCHAR", wchar_or_char)
}

fn parse_line(text: &str) -> Option<Prototype> {
    let text = text.trim().trim_end_matches(';');
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let head = text[..open].trim();
    let args = text[open + 1..close].trim();

    let mut words: Vec<&str> = head.split_whitespace().collect();
    if words.is_empty() {
        return None;
    }
    let mut stdcall = false;
    words.retain(|w| {
        if matches!(
            *w,
            "WINAPI" | "__stdcall" | "NTAPI" | "APIENTRY" | "CALLBACK" | "WSAAPI"
        ) {
            stdcall = true;
            false
        } else {
            !matches!(
                *w,
                "__cdecl" | "__fastcall" | "WINBASEAPI" | "WINUSERAPI" | "extern" | "static"
            )
        }
    });
    if words.is_empty() {
        return None;
    }
    let name = words.pop()?.to_string();
    let ret = if words.is_empty() {
        "int".into()
    } else {
        words.join(" ")
    };

    let mut params = Vec::new();
    let mut variadic = false;
    if !args.is_empty() && args != "void" {
        for part in split_args(args) {
            let part = part.trim();
            if part == "..." {
                variadic = true;
                continue;
            }
            if part.is_empty() {
                continue;
            }
            let (ty, pname) = split_param(part, params.len());
            params.push(ProtoParam { ty, name: pname });
        }
    }
    if variadic {
        stdcall = false;
    }
    Some(Prototype {
        ret,
        name,
        params,
        variadic,
        stdcall,
    })
}

fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' | '[' | '<' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '>' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn split_param(text: &str, idx: usize) -> (String, String) {
    let t = text.trim();
    // Function pointer: keep whole type, invent a name.
    if t.contains("(*") {
        return (squeeze(t), format!("a{}", idx + 1));
    }
    let bytes = t.as_bytes();
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1].is_ascii_alphanumeric() || bytes[end - 1] == b'_') {
        end -= 1;
    }
    let last = t[end..].trim();
    let rest = t[..end].trim();
    let type_words = [
        "char", "short", "int", "long", "float", "double", "void", "signed", "unsigned", "const",
        "volatile", "struct", "union", "enum", "bool", "size_t", "ssize_t", "DWORD", "HANDLE",
        "BOOL", "LPVOID", "LPCVOID", "LPSTR", "LPCSTR", "LPWSTR", "LPCWSTR", "SIZE_T", "UINT",
        "ULONG", "PVOID", "BYTE", "WORD", "LONG", "HMODULE", "HWND", "HKEY", "SOCKET", "FILE",
        "time_t", "mode_t", "off_t", "uid_t", "gid_t", "NTSTATUS", "FARPROC",
    ];
    if !last.is_empty()
        && !type_words.iter().any(|w| *w == last)
        && !rest.is_empty()
        && !matches!(rest, "const" | "struct" | "unsigned" | "signed")
    {
        (squeeze(rest), last.to_string())
    } else {
        (squeeze(t), format!("a{}", idx + 1))
    }
}

fn squeeze(s: &str) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = true;
            continue;
        }
        if space
            && !out.is_empty()
            && c != '*'
            && c != '&'
            && c != ')'
            && c != ']'
            && out.chars().last() != Some('(')
        {
            out.push(' ');
        }
        space = false;
        out.push(c);
    }
    out
}

/// Curated subset of the C++ `protos.cpp` tables (kernel32 + libc essentials).
const PROTOS: &str = r#"
HANDLE WINAPI CreateFile%(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
BOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
BOOL WINAPI CloseHandle(HANDLE hObject)
BOOL WINAPI DeleteFile%(LPCTSTR lpFileName)
DWORD WINAPI GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
DWORD WINAPI GetFileAttributes%(LPCTSTR lpFileName)
HMODULE WINAPI GetModuleHandle%(LPCTSTR lpModuleName)
HMODULE WINAPI LoadLibrary%(LPCTSTR lpLibFileName)
BOOL WINAPI FreeLibrary(HMODULE hLibModule)
FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
LPVOID WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
BOOL WINAPI VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
BOOL WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
BOOL WINAPI ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
BOOL WINAPI WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
BOOL WINAPI CreateProcess%(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
void WINAPI ExitProcess(UINT uExitCode)
HANDLE WINAPI GetCurrentProcess(void)
DWORD WINAPI GetCurrentProcessId(void)
HANDLE WINAPI GetCurrentThread(void)
DWORD WINAPI GetCurrentThreadId(void)
void WINAPI Sleep(DWORD dwMilliseconds)
DWORD WINAPI GetLastError(void)
void WINAPI SetLastError(DWORD dwErrCode)
BOOL WINAPI IsDebuggerPresent(void)
void WINAPI OutputDebugString%(LPCTSTR lpOutputString)
LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
HANDLE WINAPI GetProcessHeap(void)
int WINAPI MessageBox%(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
LONG WINAPI RegOpenKeyEx%(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
LONG WINAPI RegQueryValueEx%(HKEY hKey, LPCTSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
LONG WINAPI RegCloseKey(HKEY hKey)
int WINAPI WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
SOCKET WINAPI socket(int af, int type, int protocol)
int WINAPI closesocket(SOCKET s)
int WINAPI connect(SOCKET s, const struct sockaddr* name, int namelen)
int WINAPI send(SOCKET s, const char* buf, int len, int flags)
int WINAPI recv(SOCKET s, char* buf, int len, int flags)
int printf(const char* format, ...)
int fprintf(FILE* stream, const char* format, ...)
int sprintf(char* str, const char* format, ...)
int snprintf(char* str, size_t size, const char* format, ...)
int puts(const char* s)
int putchar(int c)
int getchar(void)
FILE* fopen(const char* pathname, const char* mode)
int fclose(FILE* stream)
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
void* malloc(size_t size)
void* calloc(size_t nmemb, size_t size)
void* realloc(void* ptr, size_t size)
void free(void* ptr)
void* memcpy(void* dest, const void* src, size_t n)
void* memmove(void* dest, const void* src, size_t n)
void* memset(void* s, int c, size_t n)
int memcmp(const void* s1, const void* s2, size_t n)
size_t strlen(const char* s)
char* strcpy(char* dest, const char* src)
char* strncpy(char* dest, const char* src, size_t n)
char* strcat(char* dest, const char* src)
int strcmp(const char* s1, const char* s2)
int strncmp(const char* s1, const char* s2, size_t n)
char* strchr(const char* s, int c)
char* strstr(const char* haystack, const char* needle)
char* strdup(const char* s)
int atoi(const char* nptr)
long atol(const char* nptr)
void exit(int status)
void abort(void)
char* getenv(const char* name)
int system(const char* command)
time_t time(time_t* tloc)
int open(const char* pathname, int flags, ...)
int close(int fd)
ssize_t read(int fd, void* buf, size_t count)
ssize_t write(int fd, const void* buf, size_t count)
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_create_file_w() {
        let p = known_prototype("CreateFileW").expect("CreateFileW");
        assert_eq!(p.ret, "HANDLE");
        assert!(p.stdcall);
        assert!(p.params.len() >= 5);
        assert_eq!(p.params[0].name, "lpFileName");
    }

    #[test]
    fn strips_imp_prefix() {
        assert!(known_prototype("__imp_printf").is_some());
        assert!(known_prototype("printf@plt").is_some());
    }

    #[test]
    fn formats_variadic() {
        let p = known_prototype("printf").unwrap();
        let s = p.format();
        assert!(s.contains("..."));
    }
}
