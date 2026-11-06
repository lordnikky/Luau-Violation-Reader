import ctypes
from ctypes import wintypes
import time
import subprocess

# Windows API stuff

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32Threads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260)
    ]

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260)
    ]

kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

class off:
    # version-5a21b87bbc2641cf
    dm_arbiter = 0x8D06600
    arbiter_to_dm = 0x1f0
    facets = 0x98
    facets_end = 0xA0
    global_state = 0x220
    actor_state = 0x530
    l_global = 0x38
    registry_free = 0x628

# As is on .cpp: "uhm, im lazy to auto find offsets runtime :freezing_face:, so ill just drop em every build or sum"

hProc = None
baseAddr = 0

def read_mem(addr, out):
    n = ctypes.c_size_t(0)
    size = ctypes.sizeof(out)
    res = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), ctypes.byref(out), size, ctypes.byref(n))
    return bool(res) and n.value == size

def pid(name):
    # Bypass to run this without running as Administrator
    try:
        output = subprocess.check_output(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"], stderr=subprocess.DEVNULL)
        lines = output.decode('utf-8', errors='ignore').strip().split('\n')
        for line in lines:
            if line.strip().startswith('"'):
                parts = line.split('","')
                if len(parts) >= 2:
                    exe = parts[0].strip('"')
                    if exe.lower() == name.lower():
                        return int(parts[1])
    except Exception:
        pass

    # Fallback, same logic from .cpp
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE: return 0

    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(pe)
    found = 0

    if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower():
                found = pe.th32ProcessID
                break
            if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                break

    kernel32.CloseHandle(snap)
    return found

def module_base(pid, name):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE: return 0

    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(me)
    result = 0

    if kernel32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == name.lower():
                result = me.modBaseAddr or 0
                break
            if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                break

    kernel32.CloseHandle(snap)
    return result

def decrypt_state(at, outState):
    lo = ctypes.c_uint32(0); hi = ctypes.c_uint32(0)
    if not read_mem(at,     lo): return False
    if not read_mem(at + 4, hi): return False

    key = at & 0xFFFFFFFF
    outState.value = ((key ^ hi.value) << 32) | (key ^ lo.value)
    return True

def looks_like_ptr(p):
    return p >= 0x10000 and p < 0x00007FFFFFFE0000

def is_valid_lua_state(L):
    if not looks_like_ptr(L): return False

    g = ctypes.c_uint64(0)
    if not read_mem(L + off.l_global, g): return False
    if not looks_like_ptr(g.value): return False

    flags = ctypes.c_uint32(0)
    return read_mem(g.value + off.registry_free, flags)

def is_script_context(ptr):
    if not looks_like_ptr(ptr): return False

    s1 = ctypes.c_uint64(0); s2 = ctypes.c_uint64(0)
    if not decrypt_state(ptr + off.global_state, s1): return False
    if not decrypt_state(ptr + off.actor_state, s2): return False

    if s1.value and not is_valid_lua_state(s1.value): return False
    if s2.value and not is_valid_lua_state(s2.value): return False
    
    return bool(s1.value or s2.value)

def script_context(dm):
    beg = ctypes.c_uint64(0); end = ctypes.c_uint64(0)
    if not read_mem(dm + off.facets,     beg): return 0
    if not read_mem(dm + off.facets_end, end): return 0
    if not looks_like_ptr(beg.value) or end.value <= beg.value: return 0
    
    p = beg.value
    while p < end.value:
        candidate = ctypes.c_uint64(0)
        if read_mem(p, candidate) and is_script_context(candidate.value):
            return candidate.value
        p += 16
    
    return 0

def get_security(stateAddr, bit, ok):
    L = ctypes.c_uint64(0)
    ok[0] = decrypt_state(stateAddr, L)
    if not ok[0]: return False
    if not L.value: return True

    g = ctypes.c_uint64(0)
    if not read_mem(L.value + off.l_global, g) or not g.value: return False

    flags = ctypes.c_uint32(0)
    if not read_mem(g.value + off.registry_free, flags): return False

    return bool((flags.value >> bit) & 1)

def are_we_dtc(sc, ok):
    ok[0] = True
    mask = 0

    for i in range(3):
        okA = [False]; okB = [False]
        a = get_security(sc + off.global_state, 28 + i, okA)
        b = get_security(sc + off.actor_state,  28 + i, okB)
        
        if not okA[0] or not okB[0]: 
            ok[0] = False
            return 0
        
        if a and b: 
            mask |= (1 << i)

    return mask

def main():
    global hProc, baseAddr
    roblox_pid = pid("RobloxPlayerBeta.exe")
    if not roblox_pid:
        print("ERROR: RobloxPlayerBeta.exe not found.")
        return 1

    hProc = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, roblox_pid)
    if not hProc:
        print(f"ERROR: OpenProcess failed. Error code: 0x{ctypes.get_last_error():x}")
        print("Try running this as Administrator.")
        return 1
    
    baseAddr = module_base(roblox_pid, "RobloxPlayerBeta.exe")
    if not baseAddr:
        print("ERROR: Failed to find module base.")
        return 1

    print(f"Successfully attached to Roblox (PID: {roblox_pid}). Monitoring...\n")
    
    while True:
        arbiter = ctypes.c_uint64(0)
        if not read_mem(baseAddr + off.dm_arbiter, arbiter) or not looks_like_ptr(arbiter.value):
            time.sleep(0.5)
            continue

        sc = script_context(arbiter.value + off.arbiter_to_dm)

        if not sc:
            time.sleep(0.5)
            continue

        ok = [False]
        v = are_we_dtc(sc, ok)

        if not ok[0]:
            print("Failed to read state.")
            time.sleep(0.5)
            continue

        print(f"Violations: 0x{v:x}" + (" (clean)" if v == 0x7 else " (detected)"))

        time.sleep(1)

if __name__ == "__main__":
    main()
