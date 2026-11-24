// The console audio coprocessor (AcpHal.dll, xapu.dll, chad.dll) as a SILENT device: every call the retail title
// makes succeeds and leaves valid memory behind, but nothing is ever decoded or played. The title's audio init
// asserts (int3) when any of these fails, so "absent" is not an option (+0x43ad94e, then +0x43a657e).
//
// Shapes read statically from the retail executable (no console documentation exists; details and call sites in
// docs/audio_hal_exe_calls.md and the RT-5 audio map). In short:
//   - AcpHal: one APU heap (ApuCreateHeap) that ApuAlloc carves; ApuMap* translate between CPU pointers and opaque
//     32-bit "APU addresses" (a fixed offset here); shape contexts are zeroed arrays nobody updates, so the title
//     always sees "no output available" (silence) for its XMA voices; the HAL object answers every method S_OK.
//   - xapu: a decode queue. Each command is echoed as a result of the same type with an output size of 0, which the
//     title takes as a clean "no samples" completion, so its slot and buffer state machine keeps cycling. HYPOTHESIS:
//     the result type equals the command opcode (inferred from the title's state machine).
//   - chad (XDsp): streams complete each submission at once (status +4 = the sequence number, +0xc = 0).
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <new>
#include <set>

#include "shims.h"
#include "../src/feature_off.h"

namespace {

void note(const char* what) {
    static std::mutex m;
    static std::set<const char*>* seen = new std::set<const char*>;
    std::lock_guard<std::mutex> lock(m);
    if (seen->insert(what).second) std::fprintf(stderr, "[rt] apu_silent: %s\n", what);
}

void* zeroed_aligned(std::size_t size, std::size_t align) {
    void* p = _aligned_malloc(size ? size : 1, align < 16 ? 16 : align);
    if (p) std::memset(p, 0, size ? size : 1);
    return p;
}

// ---- APU heap -----------------------------------------------------------------------------------------------------

constexpr std::uint32_t kApuBase = 0x10000000;  // HYPOTHESIS: any non-zero 32-bit range; the title treats it as opaque

struct Heap {
    std::mutex lock;
    std::uint8_t* base = nullptr;
    std::size_t size = 0, used = 0;
    std::set<std::uint8_t*> fallback;  // blocks from the host allocator once the heap is full
} g_heap;

bool in_heap(const void* p, std::size_t n) {
    const auto* b = static_cast<const std::uint8_t*>(p);
    return g_heap.base && b >= g_heap.base && n <= g_heap.size && b - g_heap.base <= std::ptrdiff_t(g_heap.size - n);
}

HRESULT WINAPI apu_create_heap(std::uint32_t size, std::uint32_t size2) {
    std::lock_guard<std::mutex> guard(g_heap.lock);
    if (g_heap.base) return S_OK;
    const std::size_t total = std::size_t(size) + size2;
    // Reserved and committed at once: Windows and Wine hand out committed pages lazily, zero-filled.
    g_heap.base = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!g_heap.base) return E_OUTOFMEMORY;
    g_heap.size = total;
    std::fprintf(stderr, "[rt] apu_silent: APU heap of %zu bytes at %p (no audio is produced)\n", total,
                 static_cast<void*>(g_heap.base));
    return S_OK;
}

HRESULT WINAPI apu_alloc(void** va, std::uint32_t* apu, std::uint32_t size, std::uint32_t align, std::uint32_t) {
    note("ApuAlloc");
    if (!va) return E_POINTER;
    const std::size_t a = align && !(align & (align - 1)) ? align : 0x800;
    std::uint8_t* p = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_heap.lock);
        if (g_heap.base) {
            const std::size_t start = (g_heap.used + a - 1) & ~(a - 1);
            const std::size_t n = size ? size : 1;
            if (start <= g_heap.size && n <= g_heap.size - start) {
                p = g_heap.base + start;
                g_heap.used = start + n;
                std::memset(p, 0, n);
            }
        }
        if (!p) {  // the title does not check the result, so a host block stands in rather than a failure
            p = static_cast<std::uint8_t*>(zeroed_aligned(size, a));
            if (p) g_heap.fallback.insert(p);
        }
    }
    *va = p;
    if (apu) *apu = in_heap(p, 1) ? kApuBase + static_cast<std::uint32_t>(p - g_heap.base) : 0;
    return p ? S_OK : E_OUTOFMEMORY;
}

// The title frees 700 pieces it carved out of one block, so interior pointers are normal: only host fallback blocks
// are released, the bump heap keeps its memory until exit.
HRESULT WINAPI apu_free(void* p) {
    std::lock_guard<std::mutex> guard(g_heap.lock);
    auto it = g_heap.fallback.find(static_cast<std::uint8_t*>(p));
    if (it != g_heap.fallback.end()) {
        _aligned_free(*it);
        g_heap.fallback.erase(it);
    }
    return S_OK;
}

BOOLEAN WINAPI apu_is_virtual_address_valid(const void* p, std::uint32_t size) { return in_heap(p, size ? size : 1); }

std::uint32_t WINAPI apu_map_virtual_address(const void* p) {
    return in_heap(p, 1) ? kApuBase + static_cast<std::uint32_t>(static_cast<const std::uint8_t*>(p) - g_heap.base) : 0;
}

void* WINAPI apu_map_apu_address(std::uint32_t a) {
    if (!g_heap.base || a < kApuBase || a - kApuBase >= g_heap.size) return nullptr;
    return g_heap.base + (a - kApuBase);
}

// ---- Shape contexts and the HAL object ----------------------------------------------------------------------------

// The title's struct: six u32 counts at +0x00, six pointers at +0x18 (the 5th, +0x38, is its XMA context array of
// count x 64 bytes), then (HYPOTHESIS) six u32 APU addresses at +0x48. It ends at +0x60; nothing is written after.
void* g_shape_blocks[6] = {};

HRESULT WINAPI acp_hal_allocate_shape_contexts(std::uint8_t* s) {
    if (!s) return E_POINTER;
    for (int i = 0; i < 6; ++i) {
        std::uint32_t count = 0;
        std::memcpy(&count, s + 4 * i, 4);
        void* block = count ? zeroed_aligned(std::size_t(count) * 64, 64) : nullptr;
        if (count && !block) return E_OUTOFMEMORY;
        g_shape_blocks[i] = block;
        std::memcpy(s + 0x18 + 8 * i, &block, 8);
    }
    note("AcpHalAllocateShapeContexts: zeroed contexts, never updated (silence)");
    return S_OK;
}

HRESULT WINAPI acp_hal_release_shape_contexts() {
    for (void*& b : g_shape_blocks) {
        _aligned_free(b);
        b = nullptr;
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE hal_ok(void*, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t) {
    return S_OK;
}

struct Hal {
    void* const* vtbl;
};
void* const g_hal_vtbl[8] = {reinterpret_cast<void*>(&hal_ok), reinterpret_cast<void*>(&hal_ok),
                             reinterpret_cast<void*>(&hal_ok), reinterpret_cast<void*>(&hal_ok),
                             reinterpret_cast<void*>(&hal_ok), reinterpret_cast<void*>(&hal_ok),
                             reinterpret_cast<void*>(&hal_ok), reinterpret_cast<void*>(&hal_ok)};
Hal g_hal{g_hal_vtbl};

// Writes only the 8-byte pointer: the title keeps an event and a status word right after it.
HRESULT WINAPI acp_hal_create(void** out) {
    if (!out) return E_POINTER;
    *out = &g_hal;
    note("AcpHalCreate: silent HAL object");
    return S_OK;
}

// ---- xapu ---------------------------------------------------------------------------------------------------------

struct ApuResult {
    std::uint8_t bytes[80];
};

struct XApu {
    std::mutex lock;
    std::deque<ApuResult> results;
    void* shared = nullptr;
} g_xapu;

// (config, 16-byte out block, handle out). config +0xc is the shared buffer size (0x104000 in the retail title).
HRESULT WINAPI xapu_connect(const std::uint32_t* config, void** out16, void** handle) {
    if (!config || !out16 || !handle) return E_POINTER;
    const std::size_t size = config[3] ? config[3] : 0x104000;
    if (!g_xapu.shared) g_xapu.shared = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g_xapu.shared) return E_OUTOFMEMORY;
    out16[0] = g_xapu.shared;  // the second 8 bytes are left as the title zeroed them
    *handle = &g_xapu;
    note("XApuConnect: decode queue echoes every command with no samples");
    return S_OK;
}

HRESULT WINAPI xapu_enqueue_command(void*, const std::uint8_t* cmd, std::uint64_t) {
    if (!cmd) return E_POINTER;
    static const bool echo = !leonida::feature_off("xapu_echo");
    if (!echo) return S_OK;
    ApuResult r{};
    std::memcpy(r.bytes, cmd, 8);  // +0 type (= the opcode), +4 slot; +0x34 output size stays 0
    std::lock_guard<std::mutex> guard(g_xapu.lock);
    if (g_xapu.results.size() < 4096) g_xapu.results.push_back(r);
    return S_OK;
}

std::uint32_t WINAPI xapu_get_result_count(void*, std::uint64_t) {
    std::lock_guard<std::mutex> guard(g_xapu.lock);
    return static_cast<std::uint32_t>(g_xapu.results.size());
}

HRESULT WINAPI xapu_dequeue_result(void*, std::uint8_t* out) {
    if (!out) return E_POINTER;
    std::lock_guard<std::mutex> guard(g_xapu.lock);
    if (g_xapu.results.empty()) return E_FAIL;  // the caller skips this iteration
    std::memcpy(out, g_xapu.results.front().bytes, sizeof(ApuResult));
    g_xapu.results.pop_front();
    return S_OK;
}

HRESULT WINAPI xapu_disconnect(void*) {
    std::lock_guard<std::mutex> guard(g_xapu.lock);
    g_xapu.results.clear();
    return S_OK;  // the shared buffer stays: a late reader must not fault
}

// ---- chad (XDsp) --------------------------------------------------------------------------------------------------

struct DspStream {
    alignas(64) std::uint8_t status[256];  // HYPOTHESIS on the size; the title reads +4 (sequence) and +0xc (0 = ok)
    std::atomic<std::uint32_t> sequence{0};
};

std::uint8_t g_dsp_connection;  // a non-null token

// (buffer, size, max streams, 0x80, 1, u64* out); the title requires exactly 0.
std::uint32_t WINAPI xdsp_connect(void*, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, void** out) {
    if (out) *out = &g_dsp_connection;
    note("XDspConnectWithMaximumStreamLimit: submissions complete at once");
    return 0;
}

std::uint32_t WINAPI xdsp_activate(void*, const void*, void** out_status, void** out_stream) {
    auto* s = new (std::nothrow) DspStream{};
    if (!s) return 1;
    if (out_status) *out_status = s->status;
    if (out_stream) *out_stream = s;
    return 0;
}

std::uint32_t WINAPI xdsp_submit_command(DspStream* s, const void*, std::uint32_t* seq) {
    if (!s) return 1;
    const std::uint32_t n = s->sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    if (seq) *seq = n;
    std::memcpy(s->status + 4, &n, 4);
    std::memset(s->status + 0xc, 0, 4);
    return 0;
}

std::uint32_t WINAPI xdsp_deactivate(DspStream*) { return 0; }  // kept: the title may still read the status block
std::uint32_t WINAPI xdsp_disconnect(void*) { return 0; }

}  // namespace

SHIM_TABLE(apu_silent,
    {"acphal.dll", "ApuCreateHeap", reinterpret_cast<void*>(&apu_create_heap)},
    {"acphal.dll", "ApuAlloc", reinterpret_cast<void*>(&apu_alloc)},
    {"acphal.dll", "ApuFree", reinterpret_cast<void*>(&apu_free)},
    {"acphal.dll", "ApuIsVirtualAddressValid", reinterpret_cast<void*>(&apu_is_virtual_address_valid)},
    {"acphal.dll", "ApuMapVirtualAddress", reinterpret_cast<void*>(&apu_map_virtual_address)},
    {"acphal.dll", "ApuMapApuAddress", reinterpret_cast<void*>(&apu_map_apu_address)},
    {"acphal.dll", "AcpHalAllocateShapeContexts", reinterpret_cast<void*>(&acp_hal_allocate_shape_contexts)},
    {"acphal.dll", "AcpHalReleaseShapeContexts", reinterpret_cast<void*>(&acp_hal_release_shape_contexts)},
    {"acphal.dll", "AcpHalCreate", reinterpret_cast<void*>(&acp_hal_create)},
    {"xapu.dll", "XApuConnect", reinterpret_cast<void*>(&xapu_connect)},
    {"xapu.dll", "XApuEnqueueCommand", reinterpret_cast<void*>(&xapu_enqueue_command)},
    {"xapu.dll", "XApuGetResultCount", reinterpret_cast<void*>(&xapu_get_result_count)},
    {"xapu.dll", "XApuDequeueResult", reinterpret_cast<void*>(&xapu_dequeue_result)},
    {"xapu.dll", "XApuDisconnect", reinterpret_cast<void*>(&xapu_disconnect)},
    {"chad.dll", "XDspConnectWithMaximumStreamLimit", reinterpret_cast<void*>(&xdsp_connect)},
    {"chad.dll", "XDspActivate", reinterpret_cast<void*>(&xdsp_activate)},
    {"chad.dll", "XDspSubmitCommand", reinterpret_cast<void*>(&xdsp_submit_command)},
    {"chad.dll", "XDspDeactivate", reinterpret_cast<void*>(&xdsp_deactivate)},
    {"chad.dll", "XDspDisconnect", reinterpret_cast<void*>(&xdsp_disconnect)},
);
