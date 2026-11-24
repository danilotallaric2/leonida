// Runtime compatibility patches for guest instructions unavailable on the host CPU.
//
// The Xbox Series X|S executable uses CLWB (66 0F AE /6) to flush write-combined cache lines. Intel Comet Lake and
// older CPUs do not implement it, so executing one raises STATUS_ILLEGAL_INSTRUCTION. The instruction is only a
// cache hint on pagefile-backed CPU mappings; replacing it with NOPs keeps the program's semantics.
#pragma once

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <intrin.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace leonida::cpu_compat {

struct PatchResult {
    bool ok = false;
    std::size_t patched = 0;
    const char* error = "";
};

// Rewrites every CLWB in the executable sections of a mapped PE64 image to NOPs. Called after mapping, before any
// image code runs.
inline PatchResult patch_clwb(uint8_t* base) {
    PatchResult r;
    if (!base) return r.error = "no image", r;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return r.error = "not a PE image", r;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return r.error = "not a PE64 image", r;

    auto patch_section = [&](const IMAGE_SECTION_HEADER& s) -> bool {
        if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)) return true;
        const std::size_t size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (size == 0) return true;
        uint8_t* begin = base + s.VirtualAddress;
        DWORD old = 0;
        if (!VirtualProtect(begin, size, PAGE_EXECUTE_READWRITE, &old)) return false;
        for (std::size_t i = 0; i + 5 <= size;) {
            const uint8_t* p = begin + i;
            std::size_t len = 0;
            if (p[0] == 0x66 && p[1] == 0x41 && p[2] == 0x0F && p[3] == 0xAE && (p[4] & 0x38) == 0x30) {
                len = 5;  // 66 41 0F AE /6, e.g. clwb [r9]
            } else if (p[0] == 0x66 && p[1] == 0x0F && p[2] == 0xAE && (p[3] & 0x38) == 0x30) {
                len = 4;  // 66 0F AE /6
            }
            if (len) {
                std::memset(const_cast<uint8_t*>(p), 0x90, len);
                r.patched++;
                i += len;
            } else {
                ++i;
            }
        }
        DWORD ignored = 0;
        VirtualProtect(begin, size, old, &ignored);
        FlushInstructionCache(GetCurrentProcess(), begin, size);
        return true;
    };

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!patch_section(sec[i])) return r.error = "VirtualProtect failed", r;
    }
    r.ok = true;
    return r;
}

// The title's watchdog thread deliberately faults itself (mov dword ptr [0],0; int3) when a worker has not checked
// in. Translated shades on a slow host can exceed its deadline even when the worker is making progress, so turn
// those self-faults into no-ops; the surrounding loop keeps running.
inline PatchResult patch_watchdog_abort(uint8_t* base) {
    PatchResult r;
    if (!base) return r.error = "no image", r;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return r.error = "not a PE image", r;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return r.error = "not a PE64 image", r;
    static constexpr uint8_t kSelfFault[] = {0xC7, 0x04, 0x25, 0, 0, 0, 0, 0, 0, 0, 0};
    for (const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
         sec < IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections; ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        const std::size_t size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        uint8_t* begin = base + sec->VirtualAddress;
        DWORD old = 0;
        if (!VirtualProtect(begin, size, PAGE_EXECUTE_READWRITE, &old)) return r.error = "VirtualProtect failed", r;
        for (std::size_t i = 0; i + sizeof(kSelfFault) <= size;) {
            uint8_t* p = begin + i;
            if (std::memcmp(p, kSelfFault, sizeof(kSelfFault)) == 0) {
                // Include the trailing int3 (with the optional xor eax,eax) so the loop resumes normally.
                std::size_t len = sizeof(kSelfFault);
                while (len < size && p[len] != 0xCC && len < sizeof(kSelfFault) + 4) ++len;
                if (len < size && p[len] == 0xCC) ++len;
                std::memset(p, 0x90, len);
                r.patched++;
                i += len;
            } else {
                ++i;
            }
        }
        DWORD ignored = 0;
        VirtualProtect(begin, size, old, &ignored);
        FlushInstructionCache(GetCurrentProcess(), begin, size);
    }
    r.ok = true;
    return r;
}

// Replace the bytes at a VA inside the main image's executable section. Used for one-off compatibility experiments.
inline PatchResult patch_rva(uint8_t* base, uint32_t rva, const uint8_t* bytes, std::size_t len) {
    PatchResult r;
    if (!base) return r.error = "no image", r;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return r.error = "not a PE image", r;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) || rva < sec->VirtualAddress ||
            rva + len > sec->VirtualAddress + (sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData))
            continue;
        uint8_t* p = base + rva;
        DWORD old = 0;
        if (!VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, &old)) return r.error = "VirtualProtect failed", r;
        std::memcpy(p, bytes, len);
        DWORD ignored = 0;
        VirtualProtect(p, len, old, &ignored);
        FlushInstructionCache(GetCurrentProcess(), p, len);
        r.ok = true;
        r.patched = 1;
        return r;
    }
    return r.error = "RVA not in executable section", r;
}

// CLZERO (0F 01 FC, AMD Zen only) zeroes the 64-byte line holding [rAX]. The retail title's memory-zeroing routine
// uses it in tight loops; on a CPU without it the instruction faults. The handler emulates it: one line per fault,
// or, for the loop "clzero; add rax,0x40; cmp rax,REG; jb back", the whole range in one go with rAX and RIP left as
// the loop would leave them.
inline std::uint64_t& gpr(CONTEXT* c, unsigned index) {
    std::uint64_t* regs[16] = {&c->Rax, &c->Rcx, &c->Rdx, &c->Rbx, &c->Rsp, &c->Rbp, &c->Rsi, &c->Rdi,
                               &c->R8,  &c->R9,  &c->R10, &c->R11, &c->R12, &c->R13, &c->R14, &c->R15};
    return *regs[index & 15];
}

inline std::atomic<std::uint64_t> g_clzero_faults{0};

inline LONG CALLBACK clzero_handler(EXCEPTION_POINTERS* info) {
    if (info->ExceptionRecord->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = info->ContextRecord;
    const auto* ip = reinterpret_cast<const std::uint8_t*>(c->Rip);
    // MONITORX (0F 01 FA) / MWAITX (0F 01 FB), AMD only: the title's fence wait arms a monitor on the fence value
    // and sleeps until it changes. The fault proves an instruction boundary, so the instruction is rewritten in
    // place (MONITORX -> 3-byte NOP, MWAITX -> PAUSE; NOP) and the loop becomes a plain spin that re-reads memory.
    if (ip[0] == 0x0F && ip[1] == 0x01 && (ip[2] == 0xFA || ip[2] == 0xFB)) {
        static constexpr std::uint8_t nop3[3] = {0x0F, 0x1F, 0x00};
        static constexpr std::uint8_t pause_nop[3] = {0xF3, 0x90, 0x90};
        auto* at = const_cast<std::uint8_t*>(ip);
        const char* name = ip[2] == 0xFA ? "MONITORX" : "MWAITX";  // read before the bytes change
        DWORD old = 0;
        if (VirtualProtect(at, 3, PAGE_EXECUTE_READWRITE, &old)) {
            std::memcpy(at, ip[2] == 0xFA ? nop3 : pause_nop, 3);
            DWORD ignored = 0;
            VirtualProtect(at, 3, old, &ignored);
            FlushInstructionCache(GetCurrentProcess(), at, 3);
            static std::atomic<int> logged{0};
            if (logged.fetch_add(1, std::memory_order_relaxed) < 4)
                std::fprintf(stderr, "[rt] cpu_compat: %s at %p rewritten\n", name, static_cast<const void*>(ip));
            return EXCEPTION_CONTINUE_EXECUTION;  // re-run the rewritten bytes
        }
        c->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (!(ip[0] == 0x0F && ip[1] == 0x01 && ip[2] == 0xFC)) return EXCEPTION_CONTINUE_SEARCH;
    if (g_clzero_faults.fetch_add(1, std::memory_order_relaxed) == 0)
        std::fprintf(stderr, "[rt] cpu_compat: emulating CLZERO (first at %p)\n", static_cast<const void*>(ip));
    // add rax,0x40 ; cmp rax,REG (REX.W 39 /r, mod 11, rm rax) ; jb rel8 back to the clzero
    const std::uint8_t* t = ip + 3;
    if (t[0] == 0x48 && t[1] == 0x83 && t[2] == 0xC0 && t[3] == 0x40 && (t[4] & 0xFB) == 0x48 && t[5] == 0x39 &&
        (t[6] & 0xC7) == 0xC0 && t[7] == 0x72 && static_cast<std::int8_t>(t[8]) == -12) {
        const unsigned reg = ((t[6] >> 3) & 7) | ((t[4] & 4) ? 8 : 0);
        const std::uint64_t end = gpr(c, reg);
        std::uint64_t rax = c->Rax;
        do {
            std::memset(reinterpret_cast<void*>(rax & ~std::uint64_t{63}), 0, 64);
            rax += 0x40;
        } while (rax < end);
        c->Rax = rax;
        c->EFlags &= ~static_cast<DWORD>(0x8D5);           // CF PF AF ZF SF OF from "cmp rax,end" with rax >= end
        if (rax == end) c->EFlags |= 0x44;                 // ZF, PF
        c->Rip = reinterpret_cast<DWORD64>(t + 9);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    std::memset(reinterpret_cast<void*>(c->Rax & ~std::uint64_t{63}), 0, 64);
    c->Rip += 3;
    return EXCEPTION_CONTINUE_EXECUTION;
}

inline void install_clzero_emulation() {
    int regs[4] = {};
    __cpuid(regs, 0x80000000);
    bool clzero = false, mwaitx = false;
    if (static_cast<unsigned>(regs[0]) >= 0x80000008u) {
        __cpuid(regs, 0x80000008);
        clzero = regs[1] & 1;
    }
    __cpuid(regs, 0x80000001);
    mwaitx = regs[2] & (1 << 29);
    if (clzero && mwaitx) return;  // the CPU has both
    AddVectoredExceptionHandler(1, clzero_handler);
    std::fprintf(stderr, "[rt] cpu_compat: CPU lacks CLZERO/MWAITX; emulation installed\n");
}

// The retail title's only CLZERO user (RVA 0x4e8aa10, game_scarlett_master.exe 1.0.2.1) clears an object's work area:
// the cache lines of [obj+0x40, obj+0x7440), two 32-byte blocks at +0xda40 and +0xdac0, then stores 0xffffffffff at
// +0x20. It is called often enough that the per-call CLZERO faults (emulated in clzero_handler) dominated the boot
// on a CPU without CLZERO. The function is replaced by this native one when its first bytes match.
inline void __fastcall native_clear_work_area(std::uint8_t* o) {
    const auto begin = reinterpret_cast<std::uintptr_t>(o + 0x40) & ~std::uintptr_t{63};
    const auto end = ((reinterpret_cast<std::uintptr_t>(o + 0x7440) - 1) | 63) + 1;
    std::memset(reinterpret_cast<void*>(begin), 0, end - begin);
    std::memset(o + 0xda40, 0, 32);
    std::memset(o + 0xdac0, 0, 32);
    const std::uint64_t marker = 0xffffffffffull;
    std::memcpy(o + 0x20, &marker, sizeof marker);
}

inline PatchResult patch_clzero_routine(uint8_t* base) {
    PatchResult r;
    constexpr std::uint32_t kRva = 0x4e8aa10;
    static constexpr std::uint8_t kExpected[] = {0x48, 0x8d, 0x41, 0x40, 0x4c, 0x8d, 0x91, 0xc0, 0x39, 0x00, 0x00,
                                                 0x4c, 0x8d, 0x89, 0x40, 0x55, 0x00, 0x00};
    if (!base) return r.error = "no image", r;
    if (std::memcmp(base + kRva, kExpected, sizeof kExpected) != 0) return r.error = "routine not found", r;
    std::uint8_t jump[12] = {0x48, 0xB8};  // mov rax, imm64 ; jmp rax
    const auto target = reinterpret_cast<std::uint64_t>(&native_clear_work_area);
    std::memcpy(jump + 2, &target, 8);
    jump[10] = 0xFF;
    jump[11] = 0xE0;
    return patch_rva(base, kRva, jump, sizeof jump);
}

}  // namespace leonida::cpu_compat
