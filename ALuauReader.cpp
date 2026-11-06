#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <iostream>

namespace off {
    constexpr uintptr_t dm_arbiter = 0x8eb6960; // this is just a datamodel idk why i named it an arbiter
    constexpr uintptr_t arbiter_to_dm = 0x1F0;
    constexpr uintptr_t facets = 0x98;
    constexpr uintptr_t facets_end = 0xA0;
    constexpr uintptr_t global_state = 0x210;
    constexpr uintptr_t actor_state = 0x520;
    constexpr uintptr_t l_global = 0x50;
    constexpr uintptr_t registry_free = 0x640;
}

// uhm, im lazy to auto find offsets runtime :freezing_face:, so ill just drop em every build or sum

static HANDLE hProc = nullptr;
static uintptr_t baseAddr = 0;

template<typename T>
static bool read_mem(uintptr_t addr, T& out) {	
    SIZE_T n = 0;
    return ReadProcessMemory(hProc, (LPCVOID)addr, &out, sizeof(T), &n) && n == sizeof(T);
}

static DWORD pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

static uintptr_t module_base(DWORD pid, const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    uintptr_t result = 0;

    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, name) == 0) {
                result = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
    return result;
}

static bool decrypt_state(uintptr_t at, uintptr_t& outState) {
    uint32_t lo = 0, hi = 0;
    if (!read_mem(at,     lo)) return false;
    if (!read_mem(at + 4, hi)) return false;

    uint32_t key = static_cast<uint32_t>(at);
    outState = (static_cast<uintptr_t>(key - hi) << 32) | (key - lo);
    return true;
}

static bool looks_like_ptr(uintptr_t p) {
    return p >= 0x10000 && p < 0x00007FFFFFFE0000ULL;
}

static bool is_valid_lua_state(uintptr_t L) {
    if (!looks_like_ptr(L)) return false;

    uintptr_t g = 0;
    if (!read_mem(L + off::l_global, g)) return false;
    if (!looks_like_ptr(g)) return false;

    uint32_t flags = 0;
    return read_mem(g + off::registry_free, flags);
}

static bool is_script_context(uintptr_t ptr) {
    if (!looks_like_ptr(ptr)) return false;

    uintptr_t s1 = 0, s2 = 0;
    if (!decrypt_state(ptr + off::global_state, s1)) return false;
    if (!decrypt_state(ptr + off::actor_state,  s2)) return false;

    if (s1 && !is_valid_lua_state(s1)) return false;
    if (s2 && !is_valid_lua_state(s2)) return false;

    return s1 || s2;
}

static uintptr_t script_context(uintptr_t dm) {
    uintptr_t beg = 0, end = 0;
    if (!read_mem(dm + off::facets,     beg)) return 0;
    if (!read_mem(dm + off::facets_end, end)) return 0;
    if (!looks_like_ptr(beg) || end <= beg) return 0;

    for (uintptr_t p = beg; p < end; p += 16) {
        uintptr_t candidate = 0;
        if (read_mem(p, candidate) && is_script_context(candidate))
            return candidate;
    }

    return 0;
}

static bool get_security(uintptr_t stateAddr, int bit, bool& ok) {
    uintptr_t L = 0;
    ok = decrypt_state(stateAddr, L);
    if (!ok) return false;
    if (!L) return true;

    uintptr_t g = 0;
    if (!read_mem(L + off::l_global, g) || !g) return false;

    uint32_t flags = 0;
    if (!read_mem(g + off::registry_free, flags)) return false;

    return (flags >> bit) & 1u;
}

static uint32_t are_we_dtc(uintptr_t sc, bool& ok) {
    ok = true;
    uint32_t mask = 0;

    for (int i = 0; i < 3; ++i) {
        bool okA = false, okB = false;
        bool a = get_security(sc + off::global_state, 28 + i, okA);
        bool b = get_security(sc + off::actor_state,  28 + i, okB);

        if (!okA || !okB) { ok = false; return 0; }
        if (a && b) mask |= (1u << i);
    }

    return mask;
}

int main() {
    DWORD roblox_pid = pid("RobloxPlayerBeta.exe");
    if (!roblox_pid) return 1;

    hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, roblox_pid);
    if (!hProc) return 1;

    baseAddr = module_base(roblox_pid, "RobloxPlayerBeta.exe");
    if (!baseAddr) return 1;

    for (;;) {
        uintptr_t arbiter = 0;
        if (!read_mem(baseAddr + off::dm_arbiter, arbiter) || !looks_like_ptr(arbiter)) {
            Sleep(500);
            continue;
        }

        uintptr_t sc = script_context(arbiter + off::arbiter_to_dm);

        if (!sc) {
            Sleep(500);
            continue;
        }

        bool ok = false;
        uint32_t v = are_we_dtc(sc, ok);

        if (!ok) {
            std::cout << "failed to read state\n";
            Sleep(500);
            continue;
        }

        std::cout << "violations: 0x" << std::hex << v
                  << (v == 0x7 ? " (clean)" : " (detected)") << "\n";

        Sleep(1000);
    }

    return 0;
}
