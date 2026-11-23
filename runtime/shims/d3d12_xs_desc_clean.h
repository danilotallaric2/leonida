// The PC form of a resource description the retail title builds for the console, for the Xbox-ABI device proxy.
//
// The title's D3D12_RESOURCE_DESC carries console values the PC device cannot take: the layout word is 0x101 (tiled)
// or 0x1 (row-major buffer), and the flags have bits above the PC ones set (docs/retail_boot_chain.md, #6982). Slot 76
// replaces the layout word the same way before it forwards to CreateCommittedResource; slot 25 and the slot 127
// stand-in need the same cleaning. The title's own description is never written: a caller gets a copy.
#pragma once

#include <windows.h>
#include <d3d12.h>

#include <cstdint>

namespace rt::d3d12_xs {

// The D3D12_RESOURCE_FLAGS bits the PC runtime defines; every other bit is a console one.
constexpr std::uint32_t kPcResourceFlagsMask =
    D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET | D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL |
    D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS | D3D12_RESOURCE_FLAG_DENY_SHADER_RESOURCE |
    D3D12_RESOURCE_FLAG_ALLOW_CROSS_ADAPTER | D3D12_RESOURCE_FLAG_ALLOW_SIMULTANEOUS_ACCESS |
    D3D12_RESOURCE_FLAG_VIDEO_DECODE_REFERENCE_ONLY | D3D12_RESOURCE_FLAG_VIDEO_ENCODE_REFERENCE_ONLY |
    D3D12_RESOURCE_FLAG_RAYTRACING_ACCELERATION_STRUCTURE;

// A copy of the title's description with the PC flags only and a PC layout: ROW_MAJOR for a buffer, UNKNOWN for a
// texture (the layout the PC device picks itself).
// Console-only DXGI values (116..129 are unassigned on the PC). The retail title makes a depth-stencil texture in
// 118 and views it as 119/120; by their places next to each other and the console SDK's numbering they are the
// 16-bit depth + 8-bit stencil family. HYPOTHESIS on the names; they are given the PC D24S8 family, which keeps a
// stencil plane and has the same view shapes (depth as plane 0, stencil as plane 1).
inline DXGI_FORMAT pc_format(DXGI_FORMAT f) {
    switch (static_cast<unsigned>(f)) {
    case 118: return DXGI_FORMAT_D24_UNORM_S8_UINT;      // D16_UNORM_S8_UINT
    case 119: return DXGI_FORMAT_R24_UNORM_X8_TYPELESS;  // R16_UNORM_X8_TYPELESS
    case 120: return DXGI_FORMAT_X24_TYPELESS_G8_UINT;   // X16_TYPELESS_G8_UINT
    default: return f;
    }
}

// A clear value with its format mapped by pc_format; `storage` holds the copy when one is needed.
inline const D3D12_CLEAR_VALUE* pc_clear_value(const D3D12_CLEAR_VALUE* v, D3D12_CLEAR_VALUE& storage) {
    if (!v || pc_format(v->Format) == v->Format) return v;
    storage = *v;
    storage.Format = pc_format(v->Format);
    return &storage;
}

inline D3D12_RESOURCE_DESC pc_resource_desc(const D3D12_RESOURCE_DESC& xbox) {
    D3D12_RESOURCE_DESC pc = xbox;
    pc.Format = pc_format(xbox.Format);
    pc.Layout = xbox.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER ? D3D12_TEXTURE_LAYOUT_ROW_MAJOR
                                                                 : D3D12_TEXTURE_LAYOUT_UNKNOWN;
    pc.Flags = static_cast<D3D12_RESOURCE_FLAGS>(static_cast<std::uint32_t>(xbox.Flags) & kPcResourceFlagsMask);
    // The console allows a depth-stencil texture with unordered access (the retail title makes a 2560x1440
    // R32G8X24_TYPELESS one at startup); D3D12 on the PC refuses that pair. The UAV flag is dropped so the resource
    // can be made; a UAV of it is then refused at view creation.
    if ((pc.Flags & D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL) && (pc.Flags & D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS))
        pc.Flags = static_cast<D3D12_RESOURCE_FLAGS>(pc.Flags & ~D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS);
    return pc;
}

}  // namespace rt::d3d12_xs
