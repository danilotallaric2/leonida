// xg_xs.dll: the console texture layout library. XGCreateTextureComputer is answered with a computer object whose
// layout is LINEAR (padded rows and mips, see compute()), not the console's swizzled one. It exists so the boot can go on; texture data
// written through CopyIntoSubresource lands in linear order and will look wrong wherever the GPU side expects the
// console swizzle.
//
// Read from the retail executable's four call sites (shapes only, no console headers):
//   XGCreateTextureComputer(const desc*, computer** out) -> HRESULT. The desc is the 0x38-byte D3D12_RESOURCE_DESC
//     shape, with the console swizzle mode in Layout (0x100 | mode). One site ignores the HRESULT and uses *out.
//   vtable +0x08 (slot 1)  called last on every path: Release.
//   vtable +0x10 (slot 2)  (layout* out): a resource layout. Header {u64 size, u64 alignment, u32 mip levels,
//                          u32 planes}, then planes of 0x6c8 bytes; one plane is a 0x38-byte header and 15 mips of
//                          0x70 bytes. Of a mip the title reads +0x00 (size), +0x10 (one 2D slice) and +0x1c (pitch
//                          in bytes). HYPOTHESIS for the other fields filled below.
//   vtable +0x40 (slot 8)  (dst base, plane, subresource, src, row pitch, slice pitch): CopyIntoSubresource.
//   vtable +0x50 (slot 10) (u32* tiles, D3D12_PACKED_MIP_INFO*, D3D12_TILE_SHAPE*, u32* count in/out, u32 first,
//                          D3D12_SUBRESOURCE_TILING*): the GetResourceTiling shape, 64 KB tiles.
// Every other slot logs its first call and returns 0.
#include <windows.h>
#include <d3d12.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <utility>

#include "shims.h"
#include "../src/feature_off.h"

namespace {

struct FormatInfo {
    std::uint32_t block_bytes = 0;  // bytes of one element (one texel, or one compressed block)
    std::uint32_t block_dim = 1;    // 4 for BC formats
};

FormatInfo format_info(std::uint32_t f) {
    switch (f) {
    case DXGI_FORMAT_R32G32B32A32_TYPELESS: case DXGI_FORMAT_R32G32B32A32_FLOAT:
    case DXGI_FORMAT_R32G32B32A32_UINT: case DXGI_FORMAT_R32G32B32A32_SINT: return {16, 1};
    case DXGI_FORMAT_R32G32B32_TYPELESS: case DXGI_FORMAT_R32G32B32_FLOAT:
    case DXGI_FORMAT_R32G32B32_UINT: case DXGI_FORMAT_R32G32B32_SINT: return {12, 1};
    case DXGI_FORMAT_R16G16B16A16_TYPELESS: case DXGI_FORMAT_R16G16B16A16_FLOAT: case DXGI_FORMAT_R16G16B16A16_UNORM:
    case DXGI_FORMAT_R16G16B16A16_UINT: case DXGI_FORMAT_R16G16B16A16_SNORM: case DXGI_FORMAT_R16G16B16A16_SINT:
    case DXGI_FORMAT_R32G32_TYPELESS: case DXGI_FORMAT_R32G32_FLOAT: case DXGI_FORMAT_R32G32_UINT:
    case DXGI_FORMAT_R32G32_SINT: case DXGI_FORMAT_R32G8X24_TYPELESS: case DXGI_FORMAT_D32_FLOAT_S8X24_UINT:
    case DXGI_FORMAT_R32_FLOAT_X8X24_TYPELESS: case DXGI_FORMAT_X32_TYPELESS_G8X24_UINT: return {8, 1};
    case DXGI_FORMAT_R8G8_TYPELESS: case DXGI_FORMAT_R8G8_UNORM: case DXGI_FORMAT_R8G8_UINT:
    case DXGI_FORMAT_R8G8_SNORM: case DXGI_FORMAT_R8G8_SINT: case DXGI_FORMAT_R16_TYPELESS:
    case DXGI_FORMAT_R16_FLOAT: case DXGI_FORMAT_D16_UNORM: case DXGI_FORMAT_R16_UNORM: case DXGI_FORMAT_R16_UINT:
    case DXGI_FORMAT_R16_SNORM: case DXGI_FORMAT_R16_SINT: case DXGI_FORMAT_B5G6R5_UNORM:
    case DXGI_FORMAT_B5G5R5A1_UNORM: case DXGI_FORMAT_B4G4R4A4_UNORM: return {2, 1};
    case DXGI_FORMAT_R8_TYPELESS: case DXGI_FORMAT_R8_UNORM: case DXGI_FORMAT_R8_UINT: case DXGI_FORMAT_R8_SNORM:
    case DXGI_FORMAT_R8_SINT: case DXGI_FORMAT_A8_UNORM: return {1, 1};
    case DXGI_FORMAT_BC1_TYPELESS: case DXGI_FORMAT_BC1_UNORM: case DXGI_FORMAT_BC1_UNORM_SRGB:
    case DXGI_FORMAT_BC4_TYPELESS: case DXGI_FORMAT_BC4_UNORM: case DXGI_FORMAT_BC4_SNORM: return {8, 4};
    case DXGI_FORMAT_BC2_TYPELESS: case DXGI_FORMAT_BC2_UNORM: case DXGI_FORMAT_BC2_UNORM_SRGB:
    case DXGI_FORMAT_BC3_TYPELESS: case DXGI_FORMAT_BC3_UNORM: case DXGI_FORMAT_BC3_UNORM_SRGB:
    case DXGI_FORMAT_BC5_TYPELESS: case DXGI_FORMAT_BC5_UNORM: case DXGI_FORMAT_BC5_SNORM:
    case DXGI_FORMAT_BC6H_TYPELESS: case DXGI_FORMAT_BC6H_UF16: case DXGI_FORMAT_BC6H_SF16:
    case DXGI_FORMAT_BC7_TYPELESS: case DXGI_FORMAT_BC7_UNORM: case DXGI_FORMAT_BC7_UNORM_SRGB: return {16, 4};
    default: break;
    }
    // The 32-bit families (RGBA8, BGRA8, R10G10B10A2, R11G11B10, R32, R16G16, D24S8, D32, R9G9B9E5...).
    if (f != DXGI_FORMAT_UNKNOWN && f < 130) return {4, 1};
    return {};
}

constexpr int kMaxMips = 15;
constexpr std::size_t kPlaneBytes = 0x6c8;
constexpr std::size_t kPlaneHeader = 0x38;
constexpr std::size_t kMipBytes = 0x70;
constexpr std::size_t kLayoutHeader = 0x18;
constexpr std::uint64_t kTile = 64 * 1024;

struct Mip {
    std::uint32_t width = 1, height = 1, depth = 1;  // texels
    std::uint32_t cols = 1, rows = 1;                // elements (blocks for BC)
    std::uint32_t pitch = 0;                         // bytes of one row of elements
    std::uint64_t slice = 0;                         // bytes of one 2D slice (depth slices included for 3D)
    std::uint64_t offset = 0;                        // from the resource start; array slices follow each other
};

struct Computer;

struct Vtbl {
    void* slots[24];
};

struct Computer {
    const Vtbl* vtbl;
    std::atomic<long> refs{1};
    D3D12_RESOURCE_DESC desc{};
    FormatInfo fmt{};
    std::uint32_t mips = 1, array = 1;
    Mip mip[kMaxMips]{};
    std::uint64_t size = 0;

    void compute() {
        fmt = format_info(static_cast<std::uint32_t>(desc.Format));
        if (!fmt.block_bytes) fmt = {4, 1};
        mips = std::clamp<std::uint32_t>(desc.MipLevels ? desc.MipLevels : 1, 1, kMaxMips);
        const bool volume = desc.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE3D;
        array = volume ? 1 : std::max<std::uint32_t>(desc.DepthOrArraySize, 1);
        std::uint64_t at = 0;
        for (std::uint32_t m = 0; m < mips; ++m) {
            Mip& p = mip[m];
            p.width = std::max<std::uint32_t>(static_cast<std::uint32_t>(desc.Width >> m), 1);
            p.height = std::max<std::uint32_t>(desc.Height >> m, 1);
            p.depth = volume ? std::max<std::uint32_t>(desc.DepthOrArraySize >> m, 1) : 1;
            p.cols = (p.width + fmt.block_dim - 1) / fmt.block_dim;
            p.rows = (p.height + fmt.block_dim - 1) / fmt.block_dim;
            // Padded, not tight: a console layout is never smaller than this (tile-aligned rows, at least one 4 KB
            // tile per mip, 64 KB total), and a title that sizes a buffer from this layout but fills it by its own
            // rules must not run past the end. Rows 256-byte aligned, slices 4 KB aligned.
            p.pitch = (p.cols * fmt.block_bytes + 255u) & ~255u;
            p.slice = (std::uint64_t(p.pitch) * p.rows * p.depth + 4095u) & ~std::uint64_t{4095};
            p.offset = at;
            at += p.slice * array;
        }
        size = (at + kTile - 1) & ~(kTile - 1);
    }
};

std::atomic<std::uint32_t> g_logged_slots{0};

void note_first(int slot, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3) {
    if (slot >= 32) return;
    const std::uint32_t bit = 1u << slot;
    if (g_logged_slots.fetch_or(bit, std::memory_order_relaxed) & bit) return;
    std::fprintf(stderr, "[rt] xg_xs: texture computer slot %d first call (args 0x%llx 0x%llx 0x%llx)\n", slot,
                 static_cast<unsigned long long>(a1), static_cast<unsigned long long>(a2),
                 static_cast<unsigned long long>(a3));
}

HRESULT STDMETHODCALLTYPE qi(Computer* self, const IID*, void** out) {
    note_first(0, reinterpret_cast<std::uint64_t>(self), 0, 0);
    if (out) *out = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE release(Computer* self) {
    note_first(1, reinterpret_cast<std::uint64_t>(self), 0, 0);
    const long left = --self->refs;
    if (left == 0) delete self;
    return static_cast<ULONG>(left < 0 ? 0 : left);
}

HRESULT STDMETHODCALLTYPE get_layout(Computer* self, std::uint8_t* out) {
    note_first(2, reinterpret_cast<std::uint64_t>(out), 0, 0);
    if (!out) return E_POINTER;
    std::memset(out, 0, kLayoutHeader + kPlaneBytes);
    auto put64 = [](std::uint8_t* p, std::uint64_t v) { std::memcpy(p, &v, 8); };
    auto put32 = [](std::uint8_t* p, std::uint32_t v) { std::memcpy(p, &v, 4); };
    put64(out + 0x00, self->size);
    put64(out + 0x08, kTile);
    put32(out + 0x10, self->mips);
    put32(out + 0x14, 1);
    std::uint8_t* plane = out + kLayoutHeader;
    put64(plane + 0x08, self->size);  // HYPOTHESIS: plane size, base offset, alignment, bytes per element
    put64(plane + 0x10, 0);
    put64(plane + 0x18, kTile);
    put32(plane + 0x20, self->fmt.block_bytes);
    for (std::uint32_t m = 0; m < self->mips; ++m) {
        const Mip& p = self->mip[m];
        std::uint8_t* e = plane + kPlaneHeader + m * kMipBytes;
        put64(e + 0x00, p.slice * self->array);  // read by the title
        put64(e + 0x08, p.offset);
        put64(e + 0x10, p.slice);                // read by the title
        put32(e + 0x18, p.cols * self->fmt.block_dim);
        put32(e + 0x1c, p.pitch);                // read by the title
        put32(e + 0x20, self->fmt.block_bytes);
        put32(e + 0x24, p.cols * self->fmt.block_dim);
        put32(e + 0x28, p.rows * self->fmt.block_dim);
        put32(e + 0x2c, p.depth);
        put32(e + 0x30, p.width);
        put32(e + 0x34, p.height);
        put32(e + 0x38, p.depth);
    }
    return S_OK;
}

// dst base, plane, subresource (mip + slice * mips), linear source with its pitches.
HRESULT STDMETHODCALLTYPE copy_into(Computer* self, std::uint8_t* dst, std::uint32_t plane, std::uint32_t sub,
                                    const std::uint8_t* src, std::uint32_t row_pitch, std::uint32_t slice_pitch) {
    note_first(8, reinterpret_cast<std::uint64_t>(dst), sub, reinterpret_cast<std::uint64_t>(src));
    if (!dst || !src || plane != 0) return E_INVALIDARG;
    static const bool off = leonida::feature_off("xgcopy");
    if (off) return S_OK;
    const std::uint32_t m = sub % self->mips, slice = sub / self->mips;
    if (slice >= self->array) return E_INVALIDARG;
    const Mip& p = self->mip[m];
    std::uint8_t* out = dst + p.offset + p.slice * slice;
    const std::uint32_t row = std::min(p.pitch, row_pitch ? row_pitch : p.pitch);
    for (std::uint32_t z = 0; z < p.depth; ++z)
        for (std::uint32_t y = 0; y < p.rows; ++y)
            std::memcpy(out + (std::uint64_t(z) * p.rows + y) * p.pitch,
                        src + std::uint64_t(z) * slice_pitch + std::uint64_t(y) * (row_pitch ? row_pitch : p.pitch),
                        row);
    return S_OK;
}

// D3D12 standard 64 KB tile shape, in texels.
D3D12_TILE_SHAPE tile_shape(const Computer* c) {
    const std::uint32_t bpe = c->fmt.block_bytes, dim = c->fmt.block_dim;
    std::uint32_t w = 128, h = 128;
    switch (bpe) {
    case 1: w = 256; h = 256; break;
    case 2: w = 256; h = 128; break;
    case 4: w = 128; h = 128; break;
    case 8: w = 128; h = 64; break;
    case 16: w = 64; h = 64; break;
    default: break;
    }
    return {w * dim, h * dim, 1};
}

void STDMETHODCALLTYPE get_tiling(Computer* self, std::uint32_t* total, D3D12_PACKED_MIP_INFO* packed,
                                  D3D12_TILE_SHAPE* shape, std::uint32_t* count, std::uint32_t first,
                                  D3D12_SUBRESOURCE_TILING* tilings) {
    note_first(10, reinterpret_cast<std::uint64_t>(total), count ? *count : 0, first);
    const D3D12_TILE_SHAPE t = tile_shape(self);
    std::uint32_t standard = 0;
    while (standard < self->mips && self->mip[standard].width >= t.WidthInTexels &&
           self->mip[standard].height >= t.HeightInTexels)
        ++standard;
    std::uint32_t tiles = 0;
    std::uint32_t start[kMaxMips]{};
    for (std::uint32_t m = 0; m < standard; ++m) {
        start[m] = tiles;
        const Mip& p = self->mip[m];
        tiles += ((p.width + t.WidthInTexels - 1) / t.WidthInTexels) *
                 ((p.height + t.HeightInTexels - 1) / t.HeightInTexels) * p.depth;
    }
    std::uint64_t tail = 0;
    for (std::uint32_t m = standard; m < self->mips; ++m) tail += self->mip[m].slice;
    const std::uint32_t tail_tiles = static_cast<std::uint32_t>((tail + kTile - 1) / kTile);
    const std::uint32_t per_slice = tiles + tail_tiles;
    if (total) *total = per_slice * self->array;
    if (packed) *packed = {static_cast<UINT8>(standard), static_cast<UINT8>(self->mips - standard), tail_tiles, tiles};
    if (shape) *shape = t;
    if (count && tilings) {
        const std::uint32_t subresources = self->mips * self->array;
        std::uint32_t n = 0;
        for (; n < *count && first + n < subresources; ++n) {
            const std::uint32_t s = first + n, m = s % self->mips, slice = s / self->mips;
            D3D12_SUBRESOURCE_TILING& o = tilings[n];
            if (m >= standard) {
                o = {0, 0, 0, D3D12_PACKED_TILE};
                continue;
            }
            const Mip& p = self->mip[m];
            o.WidthInTiles = (p.width + t.WidthInTexels - 1) / t.WidthInTexels;
            o.HeightInTiles = static_cast<UINT16>((p.height + t.HeightInTexels - 1) / t.HeightInTexels);
            o.DepthInTiles = static_cast<UINT16>(p.depth);
            o.StartTileIndexInOverallResource = slice * per_slice + start[m];
        }
        *count = n;
    }
}

template <int Slot>
std::uint64_t STDMETHODCALLTYPE other(Computer*, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3) {
    note_first(Slot, a1, a2, a3);
    return 0;
}

template <int... I>
constexpr Vtbl make_vtbl(std::integer_sequence<int, I...>) {
    return Vtbl{{reinterpret_cast<void*>(&other<I>)...}};
}

const Vtbl& vtbl() {
    static const Vtbl table = [] {
        Vtbl v = make_vtbl(std::make_integer_sequence<int, 24>{});
        v.slots[0] = reinterpret_cast<void*>(&qi);
        v.slots[1] = reinterpret_cast<void*>(&release);
        v.slots[2] = reinterpret_cast<void*>(&get_layout);
        v.slots[8] = reinterpret_cast<void*>(&copy_into);
        v.slots[10] = reinterpret_cast<void*>(&get_tiling);
        return v;
    }();
    return table;
}

HRESULT WINAPI xg_create_texture_computer(const D3D12_RESOURCE_DESC* desc, Computer** out) {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (!desc) return E_INVALIDARG;
    auto* c = new (std::nothrow) Computer{};
    if (!c) return E_OUTOFMEMORY;
    c->vtbl = &vtbl();
    c->desc = *desc;
    c->compute();
    static std::atomic<bool> logged{false};
    if (!logged.exchange(true, std::memory_order_relaxed))
        std::fprintf(stderr,
                     "[rt] xg_xs: XGCreateTextureComputer answered with a LINEAR layout (first: dim %u %llux%u "
                     "array %u mips %u format %u layout 0x%x)\n",
                     static_cast<unsigned>(desc->Dimension), static_cast<unsigned long long>(desc->Width),
                     desc->Height, desc->DepthOrArraySize, desc->MipLevels, static_cast<unsigned>(desc->Format),
                     static_cast<unsigned>(desc->Layout));
    *out = c;
    return S_OK;
}

}  // namespace

SHIM_TABLE(xg_xs,
    {"xg_xs.dll", "XGCreateTextureComputer", reinterpret_cast<void*>(&xg_create_texture_computer)},
);
