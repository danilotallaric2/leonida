// Debug probes: LEONIDA_PROBES="rva[,rva...]" (hex) places a one-shot int3 at each RVA of the main image. When a
// probe is hit, the general registers and the top of the stack go to stderr, the original byte is put back and the
// thread resumes at the same instruction. This exists because the runtime re-launches itself (base_reservation),
// so an external debugger attached to the first process never sees the title's code.
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace leonida::probes {

struct Probe {
    uint8_t* at = nullptr;
    uint8_t original = 0;
    bool armed = false;
};

inline Probe g_probes[64];
inline int g_count = 0;
inline uint8_t* g_base = nullptr;
inline std::mutex g_lock;

inline void write_byte(uint8_t* p, uint8_t v) {
    DWORD old = 0;
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
    *p = v;
    DWORD ignored = 0;
    VirtualProtect(p, 1, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), p, 1);
}

inline LONG CALLBACK handler(EXCEPTION_POINTERS* info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    auto* addr = static_cast<uint8_t*>(info->ExceptionRecord->ExceptionAddress);
    std::lock_guard<std::mutex> guard(g_lock);
    for (int i = 0; i < g_count; ++i) {
        Probe& p = g_probes[i];
        if (p.at != addr) continue;
        CONTEXT* c = info->ContextRecord;
        if (p.armed) {
            write_byte(p.at, p.original);
            p.armed = false;
        }
        c->Rip = reinterpret_cast<DWORD64>(p.at);
        const auto* sp = reinterpret_cast<const uint64_t*>(c->Rsp);
        std::fprintf(stderr,
                     "[probe] +0x%llx tid=%lu rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx r9=%llx "
                     "eflags=%lx rsp=%llx [rsp]=%llx %llx %llx %llx\n",
                     static_cast<unsigned long long>(p.at - g_base), GetCurrentThreadId(), c->Rax, c->Rbx, c->Rcx,
                     c->Rdx, c->Rsi, c->Rdi, c->R8, c->R9, c->EFlags, c->Rsp, sp[0], sp[1], sp[2], sp[3]);
        // 32 bytes from 16 before each pointer-like register, when that memory is readable.
        const struct { const char* name; DWORD64 value; } regs[] = {{"rcx", c->Rcx}, {"rdx", c->Rdx},
                                                                     {"r14", c->R14}, {"rdi", c->Rdi}};
        for (const auto& r : regs) {
            const auto* at = reinterpret_cast<const uint8_t*>(r.value) - 16;
            MEMORY_BASIC_INFORMATION mbi{};
            if (r.value < 0x10000 || !VirtualQuery(at, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
                reinterpret_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize < at + 32)
                continue;
            std::fprintf(stderr, "[probe]   %s-16:", r.name);
            for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%s%02x", i == 16 ? " | " : " ", at[i]);
            std::fprintf(stderr, "  (region base %p, alloc base %p)\n", mbi.BaseAddress, mbi.AllocationBase);
        }
        std::fflush(stderr);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// LEONIDA_NOP="rva[,rva...]" (hex): replaces the single int3 (0xCC) at each RVA with a NOP, so a debug break the
// title would take continues into the code after it. A byte that is not 0xCC is left alone and reported.
inline int nop_int3s(uint8_t* base) {
    char spec[1024];
    size_t length = 0;
    if (getenv_s(&length, spec, sizeof spec, "LEONIDA_NOP") != 0 || length <= 1) return 0;
    int done = 0;
    for (char* tok = std::strtok(spec, ", "); tok; tok = std::strtok(nullptr, ", ")) {
        const uint32_t rva = static_cast<uint32_t>(std::strtoull(tok, nullptr, 16));
        if (base[rva] != 0xCC) {
            std::fprintf(stderr, "[rt] nop: +0x%x is 0x%02x, not int3; left alone\n", rva, base[rva]);
            continue;
        }
        write_byte(base + rva, 0x90);
        ++done;
    }
    std::fprintf(stderr, "[rt] nop: %d int3(s) turned into NOPs\n", done);
    return done;
}

// Returns the number of probes placed.
inline int install(uint8_t* base) {
    char spec[1024];
    size_t length = 0;
    if (getenv_s(&length, spec, sizeof spec, "LEONIDA_PROBES") != 0 || length <= 1) return 0;
    g_base = base;
    for (char* tok = std::strtok(spec, ", "); tok && g_count < 64; tok = std::strtok(nullptr, ", ")) {
        const uint32_t rva = static_cast<uint32_t>(std::strtoull(tok, nullptr, 16));
        Probe& p = g_probes[g_count++];
        p.at = base + rva;
        p.original = *p.at;
        p.armed = true;
        write_byte(p.at, 0xCC);
    }
    AddVectoredExceptionHandler(1, handler);
    return g_count;
}

}  // namespace leonida::probes
