#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <vector>

namespace off {
    constexpr uintptr_t global_state = 0x418;
    constexpr uintptr_t actor_state = 0x708;
    constexpr uintptr_t l_global = 0x68;
    constexpr uintptr_t registry_free = 0x628;
    constexpr uintptr_t script_context_vtable = 0x7118e40;
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

static bool looks_like_ptr(uintptr_t p);
static bool is_valid_lua_state(uintptr_t L);

static bool decrypt_state(uintptr_t at, uintptr_t& outState) {
    outState = 0;

    uint32_t lo = 0, hi = 0;
    if (!read_mem(at, lo)) return false;
    if (!read_mem(at + 4, hi)) return false;

    if (lo == 0 && hi == 0) return true;   // empty slot

    const uint32_t key = static_cast<uint32_t>(at);
    const uint32_t arena = static_cast<uint32_t>(at >> 32);

    const uintptr_t cands[3] = {
        (static_cast<uintptr_t>(static_cast<uint32_t>(hi ^ key)) << 32) |
         static_cast<uint32_t>(lo ^ key), // xor
        (static_cast<uintptr_t>(static_cast<uint32_t>(hi - key)) << 32) |
         static_cast<uint32_t>(lo - key), // add
        (static_cast<uintptr_t>(static_cast<uint32_t>(key - hi)) << 32) |
         static_cast<uint32_t>(key - lo), // sub
    };

    int best = 0;
    uintptr_t winner = 0;
    for (int i = 0; i < 3; ++i) {
        const uintptr_t L = cands[i];
        if (!looks_like_ptr(L)) continue;
        int score = 0;
        if (static_cast<uint32_t>(L >> 32) == arena) score += 8;
        if ((L & 0xF) == 0) score += 4;
        if (is_valid_lua_state(L)) score += 2;
        if (score > best) { best = score; winner = L; }
    }

    if (best < 10) return false;
    outState = winner;
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

static std::vector<uintptr_t> find_all_sc() {
    std::vector<uintptr_t> out;

    const uintptr_t want  = baseAddr + off::script_context_vtable;
    uintptr_t addr  = 0x10000;
    const uintptr_t limit = 0x00007FFFFFFE0000ULL;

    while (addr < limit) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) break;

        uintptr_t start = (uintptr_t)mbi.BaseAddress;
        uintptr_t size = (uintptr_t)mbi.RegionSize;
        if (!size) break;

        DWORD protect = mbi.Protect & 0xFF;
        bool readable = mbi.State == MEM_COMMIT
            && !(mbi.Protect & PAGE_GUARD)
            && (protect == PAGE_READONLY || protect == PAGE_READWRITE
                || protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_READ
                || protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY);

        if (readable) {
            const size_t chunk = 1 << 20;
            std::vector<uint8_t> buf;
            for (uintptr_t off = 0; off < size; off += chunk) {
                size_t n = (size_t)std::min<uintptr_t>(chunk, size - off);
                buf.resize(n);
                SIZE_T got = 0;
                if (!ReadProcessMemory(hProc, (LPCVOID)(start + off), buf.data(), n, &got) || got != n)
                    continue;

                for (size_t i = 0; i + 8 <= n; i += 8) {
                    uint64_t q = 0;
                    std::memcpy(&q, buf.data() + i, 8);
                    if (q != want) continue;
                    uintptr_t candidate = start + off + i;
                    if (is_script_context(candidate)
                        && std::find(out.begin(), out.end(), candidate) == out.end())
                        out.push_back(candidate);
                }
            }
        }

        if (start + size <= addr) break;
        addr = start + size;
    }

    return out;
}
static bool state_bits(uintptr_t stateAddr, uint32_t& bits) {
    bits = 0x7;

    uintptr_t L = 0;
    if (!decrypt_state(stateAddr, L)) return false;
    if (!L) return true;

    uintptr_t g = 0;
    if (!read_mem(L + off::l_global, g) || !g) return false;

    uint32_t flags = 0;
    if (!read_mem(g + off::registry_free, flags)) return false;

    bits = (flags >> 28) & 0x7u;
    return true;
}

static uint32_t are_we_dtc(uintptr_t sc, bool& ok, uint32_t& gBits, uint32_t& aBits) {
    gBits = 0;
    aBits = 0;
    bool gOk = state_bits(sc + off::global_state, gBits);
    bool aOk = state_bits(sc + off::actor_state, aBits);
    ok = gOk && aOk;
    return ok ? (gBits & aBits) : 0;
}

static const char* bit_tag(unsigned bit) {
    if (bit == 28) return "vm-operand";
    if (bit == 29) return "gc-object";
    if (bit == 30) return "bytecode-sig";
    if (bit == 31) return "what? how";
    return "?";
}

int main() {
    DWORD roblox_pid = pid("RobloxPlayerBeta.exe");
    if (!roblox_pid) return 1;

    hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, roblox_pid);
    if (!hProc) return 1;

    baseAddr = module_base(roblox_pid, "RobloxPlayerBeta.exe");
    if (!baseAddr) return 1;

    std::vector<uintptr_t> scs;
    unsigned tick = 0;

    for (;;) {
        if (scs.empty() || (++tick % 15) == 0) {
            std::vector<uintptr_t> fresh = find_all_sc();
            for (size_t i = 0; i < fresh.size(); ++i)
                if (std::find(scs.begin(), scs.end(), fresh[i]) == scs.end())
                    scs.push_back(fresh[i]);
        }

        if (scs.empty()) {
            Sleep(500);
            continue;
        }

        bool any = false;
        uint32_t worst = 0x8, wg = 0, wa = 0;

        for (size_t i = 0; i < scs.size(); ++i) {
            bool ok = false;
            uint32_t g = 0, a = 0;
            uint32_t v = are_we_dtc(scs[i], ok, g, a);

            if (!ok) continue;
            any = true;

            if (v < worst) { worst = v; wg = g; wa = a; }
        }

        if (!any) {
            std::cout << "failed to read state\n" << std::flush;
            Sleep(500);
            continue;
        }

        uint32_t v = worst, g = wg, a = wa;

        std::cout << "violations: 0x" << std::hex << v
                  << (v == 0x7 ? " (clean)" : " (detected)")
                  << " g=0x" << g << " a=0x" << a << std::dec;

        uint32_t cleared = (~v) & 0x7u;
        if (cleared) {
            std::cout << " cleared=";
            bool first = true;
            for (int i = 0; i < 3; ++i) {
                if (cleared & (1u << i)) {
                    if (!first) std::cout << ",";
                    std::cout << bit_tag(28 + i) << "(" << (28 + i) << ")";
                    first = false;
                }
            }
        }

        std::cout << "\n" << std::flush;
        Sleep(1000);
    }

    return 0;
}
