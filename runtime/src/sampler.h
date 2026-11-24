// LEONIDA_SAMPLE="seconds[,rounds]": every `seconds`, each other thread of the process is suspended for a moment and
// its instruction pointer and the return-address candidates on its stack that fall inside the main image are read;
// threads that used more than a quarter of the interval in CPU time since the previous round are printed. For finding
// where a title spins or waits when a debugger cannot attach. While a thread is suspended nothing is printed or
// allocated (it may hold the CRT or loader lock); the output comes after it resumes.
#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>

namespace leonida::sampler {

// ntdll's THREAD_BASIC_INFORMATION (ThreadBasicInformation, class 0); not in the SDK's winternl.h.
struct ThreadBasicInfo {
    LONG ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

struct Config {
    std::uint8_t* image = nullptr;
    std::size_t image_size = 0;
    DWORD interval_ms = 0;
    int rounds = 0;
};

inline std::uint64_t thread_cpu_100ns(HANDLE t) {
    FILETIME c{}, e{}, k{}, u{};
    if (!GetThreadTimes(t, &c, &e, &k, &u)) return 0;
    return (std::uint64_t(k.dwHighDateTime) << 32 | k.dwLowDateTime) +
           (std::uint64_t(u.dwHighDateTime) << 32 | u.dwLowDateTime);
}

inline DWORD WINAPI sampler_thread(void* p) {
    const Config cfg = *static_cast<Config*>(p);
    using QueryFn = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<QueryFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    std::map<DWORD, std::uint64_t> last;
    const auto lo = reinterpret_cast<std::uint64_t>(cfg.image) + 0x1000;
    const auto hi = reinterpret_cast<std::uint64_t>(cfg.image) + cfg.image_size;
    for (int round = 0; round < cfg.rounds; ++round) {
        Sleep(cfg.interval_ms);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te{sizeof te};
        std::fprintf(stderr, "[sample] round %d\n", round);
        for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId()) continue;
            HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE,
                                  te.th32ThreadID);
            if (!t) continue;
            const std::uint64_t cpu = thread_cpu_100ns(t);
            const std::uint64_t before = last.count(te.th32ThreadID) ? last[te.th32ThreadID] : cpu;
            last[te.th32ThreadID] = cpu;
            const std::uint64_t used_ms = (cpu - before) / 10000;
            if (round == 0 || used_ms * 4 < cfg.interval_ms) {
                CloseHandle(t);
                continue;
            }
            // Stack bounds from the TEB, read before suspending.
            ThreadBasicInfo tbi{};
            std::uint64_t stack_base = 0;
            if (query && query(t, static_cast<THREADINFOCLASS>(0), &tbi, sizeof tbi, nullptr) == 0 && tbi.TebBaseAddress)
                stack_base = reinterpret_cast<const NT_TIB*>(tbi.TebBaseAddress)->StackBase
                                 ? reinterpret_cast<std::uint64_t>(reinterpret_cast<const NT_TIB*>(tbi.TebBaseAddress)->StackBase)
                                 : 0;
            CONTEXT c{};
            c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            std::uint64_t rets[16]{};
            int n = 0;
            bool got = false;
            if (SuspendThread(t) != static_cast<DWORD>(-1)) {
                if (GetThreadContext(t, &c)) {
                    got = true;
                    const auto* sp = reinterpret_cast<const std::uint64_t*>(c.Rsp);
                    for (int i = 0; i < 2048 && n < 16; ++i) {
                        if (stack_base && reinterpret_cast<std::uint64_t>(sp + i + 1) > stack_base) break;
                        const std::uint64_t v = sp[i];
                        if (v >= lo && v < hi) rets[n++] = v - reinterpret_cast<std::uint64_t>(cfg.image);
                    }
                }
                ResumeThread(t);
            }
            CloseHandle(t);
            if (!got) continue;
            std::fprintf(stderr, "[sample] tid %lu used %llu ms: rip=", te.th32ThreadID,
                         static_cast<unsigned long long>(used_ms));
            if (c.Rip >= lo && c.Rip < hi)
                std::fprintf(stderr, "+0x%llx", static_cast<unsigned long long>(c.Rip - reinterpret_cast<std::uint64_t>(cfg.image)));
            else
                std::fprintf(stderr, "%p(host)", reinterpret_cast<void*>(c.Rip));
            for (int i = 0; i < n; ++i) std::fprintf(stderr, " +0x%llx", static_cast<unsigned long long>(rets[i]));
            std::fprintf(stderr, "\n");
        }
        CloseHandle(snap);
        std::fflush(stderr);
    }
    return 0;
}

inline void install(std::uint8_t* image, std::size_t image_size) {
    char spec[64];
    size_t length = 0;
    if (getenv_s(&length, spec, sizeof spec, "LEONIDA_SAMPLE") != 0 || length <= 1) return;
    static Config cfg;
    cfg.image = image;
    cfg.image_size = image_size;
    char* rest = nullptr;
    const unsigned long seconds = std::strtoul(spec, &rest, 10);
    cfg.interval_ms = static_cast<DWORD>((seconds ? seconds : 60) * 1000);
    cfg.rounds = (rest && *rest == ',') ? std::atoi(rest + 1) : 1000;
    CloseHandle(CreateThread(nullptr, 0, sampler_thread, &cfg, 0, nullptr));
    std::fprintf(stderr, "[rt] sampler: every %lu s\n", cfg.interval_ms / 1000);
}

}  // namespace leonida::sampler
