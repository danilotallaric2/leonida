// Write watch for debugging memory corruption during the retail boot work.
//
// LEONIDA_WATCH="attr:size:offset:len" (hex): when XMemVirtualAlloc returns a reservation with exactly these
// attributes and size, the page holding [base+offset, base+offset+len) is made read-only. A write to that page faults;
// a write into the watched bytes is logged (instruction, thread, the stack's first return-address candidates inside
// the main image), then every write is let through with a single step and the page is protected again. Writes made
// by the kernel on the title's behalf (ReadFile into the page, for one) are not seen. Other threads write freely while
// one thread steps, so a racing write can be missed.
#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <intrin.h>
#include <unordered_map>

namespace leonida::watch {

struct State {
    std::uint64_t attr = 0, size = 0, offset = 0, len = 0;
    bool configured = false;
    std::uint8_t* lo = nullptr;    // watched bytes
    std::uint8_t* hi = nullptr;
    std::uint8_t* page = nullptr;  // their page
    DWORD protect = PAGE_READWRITE;
    std::atomic<int> hits{0};
    std::uint8_t* image = nullptr;
    std::size_t image_size = 0;
};

inline State& state() {
    static State s;
    return s;
}

inline thread_local bool t_stepping = false;

inline void reprotect() {
    DWORD old = 0;
    VirtualProtect(state().page, 4096, PAGE_READONLY, &old);
}

inline void print_address(const char* label, std::uint64_t a) {
    State& s = state();
    if (s.image && a >= reinterpret_cast<std::uint64_t>(s.image) &&
        a < reinterpret_cast<std::uint64_t>(s.image) + s.image_size)
        std::fprintf(stderr, " %s=+0x%llx", label, static_cast<unsigned long long>(a - reinterpret_cast<std::uint64_t>(s.image)));
}

// LEONIDA_WATCH_ALLOC_CALLER="rva" (hex): every block allocated from that return address is remembered, and its free
// is logged with the caller chain (first 40), whatever the address.
inline std::uint64_t g_track_caller = 0;
inline SRWLOCK g_track_lock = SRWLOCK_INIT;
inline void* g_tracked[4096];
inline int g_tracked_count = 0;
inline std::atomic<int> g_tracked_frees{0};
struct Freed {
    void* ptr = nullptr;
    std::uint64_t rets[16]{};
    int count = 0;
};
inline Freed g_freed[4096];
inline unsigned g_freed_next = 0;
inline std::unordered_map<void*, unsigned>* g_freed_index = new std::unordered_map<void*, unsigned>;

inline LONG CALLBACK handler(EXCEPTION_POINTERS* info) {
    State& s = state();
    if (!s.page) return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    CONTEXT* c = info->ContextRecord;
    if (code == EXCEPTION_SINGLE_STEP && t_stepping) {
        t_stepping = false;
        reprotect();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == EXCEPTION_ACCESS_VIOLATION && g_track_caller) {
        // A use after free: is one of the object registers a tracked block that was freed? Reported once.
        static std::atomic<bool> reported{false};
        const DWORD64 regs[] = {c->Rsi, c->Rcx, c->Rdi, c->Rbx, c->Rdx, c->R12, c->R13, c->R14, c->R15};
        for (const DWORD64 r : regs) {
            AcquireSRWLockShared(&g_track_lock);
            auto it = g_freed_index->find(reinterpret_cast<void*>(r));
            Freed f{};
            if (it != g_freed_index->end()) f = g_freed[it->second];
            ReleaseSRWLockShared(&g_track_lock);
            if (f.ptr && !reported.exchange(true)) {
                std::fprintf(stderr, "[watch] USE AFTER FREE of %p at", f.ptr);
                print_address("rip", c->Rip);
                std::fprintf(stderr, "; it was freed by:");
                for (int i = 0; i < f.count; ++i)
                    std::fprintf(stderr, " +0x%llx", static_cast<unsigned long long>(f.rets[i]));
                std::fprintf(stderr, "\n");
                std::fflush(stderr);
            }
        }
    }
    if (code != EXCEPTION_ACCESS_VIOLATION || info->ExceptionRecord->NumberParameters < 2 ||
        info->ExceptionRecord->ExceptionInformation[0] != 1)
        return EXCEPTION_CONTINUE_SEARCH;
    auto* target = reinterpret_cast<std::uint8_t*>(info->ExceptionRecord->ExceptionInformation[1]);
    if (target < s.page || target >= s.page + 4096) return EXCEPTION_CONTINUE_SEARCH;
    if (target + 16 > s.lo && target < s.hi) {  // a write of up to 16 bytes that touches the watched range
        const int n = s.hits.fetch_add(1, std::memory_order_relaxed);
        if (n < 64) {
            std::fprintf(stderr, "[watch] #%d write to %p (+%lld) tid=%lu rip=%p", n, static_cast<void*>(target),
                         static_cast<long long>(target - s.lo), GetCurrentThreadId(), reinterpret_cast<void*>(c->Rip));
            print_address("at", c->Rip);
            const auto* sp = reinterpret_cast<const std::uint64_t*>(c->Rsp);
            int shown = 0;
            for (int i = 0; i < 64 && shown < 8; ++i) {
                const std::uint64_t v = sp[i];
                if (s.image && v >= reinterpret_cast<std::uint64_t>(s.image) &&
                    v < reinterpret_cast<std::uint64_t>(s.image) + s.image_size) {
                    print_address("ret?", v);
                    ++shown;
                }
            }
            std::fprintf(stderr, " rcx=%llx rdx=%llx r8=%llx\n", c->Rcx, c->Rdx, c->R8);
            std::fflush(stderr);
        }
    }
    DWORD old = 0;
    VirtualProtect(s.page, 4096, s.protect, &old);
    t_stepping = true;
    c->EFlags |= 0x100;  // trap flag: re-protect after this one instruction
    return EXCEPTION_CONTINUE_EXECUTION;
}

// LEONIDA_WATCH_ALLOC="va" (hex): the address of a global holding the title's allocator object. Once that object
// exists (and the watch is armed), its vtable slots +0x60 (free: this, ptr) and +0x70 (allocate: this, ?, size, ...)
// are wrapped; every call whose block lies within 0x400 bytes of the watched range is logged with its caller.
using AllocFn = void*(__fastcall*)(void*, void*, std::uint64_t, void*, void*, void*);
using FreeFn = void(__fastcall*)(void*, void*, void*, void*);
inline AllocFn g_alloc = nullptr;
inline FreeFn g_free = nullptr;

inline bool near_watch(const void* p) {
    State& s = state();
    const auto* b = static_cast<const std::uint8_t*>(p);
    return s.lo && b + 0x400 >= s.lo && b <= s.hi + 0x400;
}

inline void log_call(const char* op, const void* p, std::uint64_t size, void* ret, void* const* frame) {
    std::fprintf(stderr, "[watch] %s %p size 0x%llx tid=%lu", op, p, static_cast<unsigned long long>(size),
                 GetCurrentThreadId());
    print_address("caller", reinterpret_cast<std::uint64_t>(ret));
    int shown = 0;
    for (int i = 1; i < 160 && shown < 14; ++i) {  // return-address candidates further up the stack
        const auto v = reinterpret_cast<std::uint64_t>(frame[i]);
        State& s = state();
        if (s.image && v >= reinterpret_cast<std::uint64_t>(s.image) + 0x1000 &&
            v < reinterpret_cast<std::uint64_t>(s.image) + 0x5f40000) {
            print_address("up", v);
            ++shown;
        }
    }
    std::fprintf(stderr, "\n");
    std::fflush(stderr);
}

inline void* __fastcall alloc_hook(void* self, void* a, std::uint64_t size, void* b, void* c, void* d) {
    void* p = g_alloc(self, a, size, b, c, d);
    if (p && g_track_caller &&
        reinterpret_cast<std::uint64_t>(_ReturnAddress()) == reinterpret_cast<std::uint64_t>(state().image) + g_track_caller) {
        AcquireSRWLockExclusive(&g_track_lock);
        if (g_tracked_count < 4096) g_tracked[g_tracked_count++] = p;
        ReleaseSRWLockExclusive(&g_track_lock);
    }
    if (p && g_track_caller) {  // any reuse of a freed block ends its "recently freed" record
        AcquireSRWLockShared(&g_track_lock);
        const bool known = g_freed_index->count(p) != 0;
        ReleaseSRWLockShared(&g_track_lock);
        if (known) {
            AcquireSRWLockExclusive(&g_track_lock);
            auto it = g_freed_index->find(p);
            if (it != g_freed_index->end()) {
                g_freed[it->second].ptr = nullptr;
                g_freed_index->erase(it);
            }
            ReleaseSRWLockExclusive(&g_track_lock);
        }
    }
    if (p && near_watch(p)) log_call("alloc", p, size, _ReturnAddress(), static_cast<void* const*>(_AddressOfReturnAddress()));
    return p;
}

inline void __fastcall free_hook(void* self, void* p, void* b, void* c) {
    if (p && g_track_caller) {
        bool tracked = false;
        AcquireSRWLockExclusive(&g_track_lock);
        for (int i = 0; i < g_tracked_count; ++i)
            if (g_tracked[i] == p) {
                g_tracked[i] = g_tracked[--g_tracked_count];
                tracked = true;
                break;
            }
        ReleaseSRWLockExclusive(&g_track_lock);
        auto* const* frame = static_cast<void* const*>(_AddressOfReturnAddress());
        if (tracked) {  // remember who freed it
            AcquireSRWLockExclusive(&g_track_lock);
            const unsigned slot = g_freed_next++ % 4096;
            Freed& f = g_freed[slot];
            if (f.ptr) g_freed_index->erase(f.ptr);
            f.ptr = p;
            (*g_freed_index)[p] = slot;
            int n = 0;
            for (int i = 0; i < 200 && n < 16; ++i) {
                const auto v = reinterpret_cast<std::uint64_t>(frame[i]);
                if (v >= reinterpret_cast<std::uint64_t>(state().image) + 0x1000 &&
                    v < reinterpret_cast<std::uint64_t>(state().image) + 0x5f40000)
                    f.rets[n++] = v - reinterpret_cast<std::uint64_t>(state().image);
            }
            f.count = n;
            ReleaseSRWLockExclusive(&g_track_lock);
        } else {
            Freed previous{};
            AcquireSRWLockExclusive(&g_track_lock);
            auto it = g_freed_index->find(p);
            if (it != g_freed_index->end()) {
                previous = g_freed[it->second];
                g_freed[it->second].ptr = nullptr;
                g_freed_index->erase(it);
            }
            ReleaseSRWLockExclusive(&g_track_lock);
            if (previous.ptr && g_tracked_frees.fetch_add(1) < 8) {
                std::fprintf(stderr, "[watch] DOUBLE FREE of %p; first free chain:", p);
                for (int i = 0; i < previous.count; ++i)
                    std::fprintf(stderr, " +0x%llx", static_cast<unsigned long long>(previous.rets[i]));
                std::fprintf(stderr, "\n");
                log_call("second free", p, 0, _ReturnAddress(), frame);
            }
        }
    }
    if (p && near_watch(p)) log_call("free ", p, 0, _ReturnAddress(), static_cast<void* const*>(_AddressOfReturnAddress()));
    g_free(self, p, b, c);
}

inline DWORD WINAPI hook_allocator_thread(void* global) {
    auto** slot = static_cast<void**>(global);
    for (int i = 0; i < 600000 && !*slot; ++i) Sleep(1);
    void* object = *slot;
    if (!object) return 0;
    void** vtbl = *static_cast<void***>(object);
    DWORD old = 0;
    if (!VirtualProtect(vtbl + 12, 3 * sizeof(void*), PAGE_READWRITE, &old)) return 0;
    g_free = reinterpret_cast<FreeFn>(vtbl[12]);
    g_alloc = reinterpret_cast<AllocFn>(vtbl[14]);
    vtbl[12] = reinterpret_cast<void*>(&free_hook);
    vtbl[14] = reinterpret_cast<void*>(&alloc_hook);
    DWORD ignored = 0;
    VirtualProtect(vtbl + 12, 3 * sizeof(void*), old, &ignored);
    std::fprintf(stderr, "[rt] watch: allocator %p hooked (vtable %p)\n", object, static_cast<void*>(vtbl));
    return 0;
}

inline void configure(std::uint8_t* image, std::size_t image_size) {
    char spec[128];
    size_t length = 0;
    if (getenv_s(&length, spec, sizeof spec, "LEONIDA_WATCH") != 0 || length <= 1) return;
    State& s = state();
    unsigned long long a = 0, z = 0, o = 0, l = 0;
    if (std::sscanf(spec, "%llx:%llx:%llx:%llx", &a, &z, &o, &l) != 4 || !l) return;
    s.attr = a, s.size = z, s.offset = o, s.len = l;
    s.image = image, s.image_size = image_size;
    s.configured = true;
    AddVectoredExceptionHandler(1, handler);
    char caller[32];
    if (getenv_s(&length, caller, sizeof caller, "LEONIDA_WATCH_ALLOC_CALLER") == 0 && length > 1)
        g_track_caller = std::strtoull(caller, nullptr, 16);
    char global[32];
    if (getenv_s(&length, global, sizeof global, "LEONIDA_WATCH_ALLOC") == 0 && length > 1) {
        void* va = reinterpret_cast<void*>(std::strtoull(global, nullptr, 16));
        CloseHandle(CreateThread(nullptr, 0, hook_allocator_thread, va, 0, nullptr));
    }
    std::fprintf(stderr, "[rt] watch: waiting for XMemVirtualAlloc attr 0x%llx size 0x%llx, bytes +0x%llx..+0x%llx\n", a, z,
                 o, o + l);
}

// Called by XMemVirtualAlloc with every reservation it returns.
inline void on_reservation(void* base, std::uint64_t size, std::uint64_t attributes) {
    State& s = state();
    if (!s.configured || s.page || !base || attributes != s.attr || size != s.size) return;
    s.lo = static_cast<std::uint8_t*>(base) + s.offset;
    s.hi = s.lo + s.len;
    s.page = reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(s.lo) & ~std::uintptr_t{4095});
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(s.page, &mbi, sizeof mbi);
    s.protect = mbi.Protect ? mbi.Protect : PAGE_READWRITE;
    DWORD old = 0;
    const BOOL ok = VirtualProtect(s.page, 4096, PAGE_READONLY, &old);
    std::fprintf(stderr, "[rt] watch: armed on %p..%p (page %p, protect 0x%lx -> read-only: %s)\n", static_cast<void*>(s.lo),
                 static_cast<void*>(s.hi), static_cast<void*>(s.page), s.protect, ok ? "ok" : "FAILED");
    if (!ok) s.page = nullptr;
}

}  // namespace leonida::watch
