#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download DirectX SDK Headers

Скачивает необходимые заголовочные файлы DirectX для генерации заглушек
"""

from pathlib import Path
from typing import List


# DirectX заголовки по версиям
DIRECTX_HEADERS = {
    'd3d9.dll': [
        'd3d9.h',           # Direct3D 9
        'd3d9types.h',      # D3D9 types
        'd3d9caps.h',       # D3D9 capabilities
    ],
    'd3d11.dll': [
        'd3d11.h',          # Direct3D 11
        'd3d11_1.h',        # D3D11.1
        'd3d11_2.h',        # D3D11.2
        'd3d11_3.h',        # D3D11.3
        'd3d11_4.h',        # D3D11.4
        'd3dcommon.h',      # Common D3D definitions
    ],
    'd3d12.dll': [
        'd3d12.h',          # Direct3D 12
        'd3d12sdklayers.h', # D3D12 SDK layers
    ],
    'dxgi.dll': [
        'dxgi.h',           # DirectX Graphics Infrastructure
        'dxgi1_2.h',        # DXGI 1.2
        'dxgi1_3.h',        # DXGI 1.3
        'dxgi1_4.h',        # DXGI 1.4
        'dxgi1_5.h',        # DXGI 1.5
        'dxgi1_6.h',        # DXGI 1.6
    ],
    'dxguid.lib': [
        'dxguid.h',         # DirectX GUIDs
    ],
}


def download_from_local_sdk() -> Path:
    """Пытается найти локально установленный DirectX SDK"""
    possible_paths = [
        # Windows SDK (содержит DirectX headers)
        Path('C:/Program Files (x86)/Windows Kits/10/Include'),
        Path('C:/Program Files/Windows Kits/10/Include'),
        # Legacy DirectX SDK
        Path('C:/Program Files (x86)/Microsoft DirectX SDK (June 2010)/Include'),
        Path('C:/Program Files/Microsoft DirectX SDK (June 2010)/Include'),
    ]
    
    for base_path in possible_paths:
        if base_path.exists():
            # Для Windows SDK ищем последнюю версию
            if 'Windows Kits' in str(base_path):
                versions = sorted([d for d in base_path.iterdir() if d.is_dir()], reverse=True)
                if versions:
                    shared_path = versions[0] / 'shared'
                    um_path = versions[0] / 'um'
                    if shared_path.exists() or um_path.exists():
                        print(f"[+] Found Windows SDK with DirectX: {versions[0]}")
                        return versions[0]
            else:
                # Legacy DirectX SDK
                if base_path.exists():
                    print(f"[+] Found DirectX SDK: {base_path}")
                    return base_path
    
    return None


def copy_from_local_sdk(sdk_path: Path, output_dir: Path) -> int:
    """Копирует DirectX заголовки из локального SDK"""
    copied = 0
    
    # Определяем пути для поиска
    search_paths = []
    if 'Windows Kits' in str(sdk_path):
        search_paths = [
            sdk_path / 'shared',  # Общие заголовки
            sdk_path / 'um',      # User-mode заголовки
        ]
    else:
        search_paths = [sdk_path]
    
    for dll_name, headers in DIRECTX_HEADERS.items():
        print(f"\n[*] {dll_name}:")
        
        for header_name in headers:
            found = False
            
            for search_path in search_paths:
                source = search_path / header_name
                
                if source.exists():
                    dest = output_dir / header_name
                    print(f"  Copying {header_name}...", end=' ')
                    dest.write_bytes(source.read_bytes())
                    print(f"✓")
                    copied += 1
                    found = True
                    break
            
            if not found:
                print(f"  {header_name} not found ✗")
    
    return copied


def create_minimal_directx_headers(output_dir: Path):
    """Создаёт минимальные DirectX заголовки для базовых функций"""
    print("\n[*] Creating minimal DirectX headers...")
    
    # Минимальный d3d9.h
    d3d9_content = """
// Minimal d3d9.h for emulator
// Based on DirectX SDK

#ifndef _D3D9_H_
#define _D3D9_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef interface IDirect3D9 IDirect3D9;
typedef interface IDirect3DDevice9 IDirect3DDevice9;

// D3D9 creation function
IDirect3D9* WINAPI Direct3DCreate9(UINT SDKVersion);

// COM interface methods (simplified)
typedef struct IDirect3D9Vtbl {
    // IUnknown
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDirect3D9* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDirect3D9* This);
    ULONG (STDMETHODCALLTYPE *Release)(IDirect3D9* This);
    
    // IDirect3D9
    HRESULT (STDMETHODCALLTYPE *RegisterSoftwareDevice)(IDirect3D9* This, void* pInitializeFunction);
    UINT (STDMETHODCALLTYPE *GetAdapterCount)(IDirect3D9* This);
    HRESULT (STDMETHODCALLTYPE *GetAdapterIdentifier)(IDirect3D9* This, UINT Adapter, DWORD Flags, void* pIdentifier);
    UINT (STDMETHODCALLTYPE *GetAdapterModeCount)(IDirect3D9* This, UINT Adapter, DWORD Format);
    HRESULT (STDMETHODCALLTYPE *EnumAdapterModes)(IDirect3D9* This, UINT Adapter, DWORD Format, UINT Mode, void* pMode);
    HRESULT (STDMETHODCALLTYPE *GetAdapterDisplayMode)(IDirect3D9* This, UINT Adapter, void* pMode);
    HRESULT (STDMETHODCALLTYPE *CheckDeviceType)(IDirect3D9* This, UINT Adapter, DWORD DevType, DWORD AdapterFormat, DWORD BackBufferFormat, BOOL bWindowed);
    HRESULT (STDMETHODCALLTYPE *CheckDeviceFormat)(IDirect3D9* This, UINT Adapter, DWORD DeviceType, DWORD AdapterFormat, DWORD Usage, DWORD RType, DWORD CheckFormat);
    HRESULT (STDMETHODCALLTYPE *CheckDeviceMultiSampleType)(IDirect3D9* This, UINT Adapter, DWORD DeviceType, DWORD SurfaceFormat, BOOL Windowed, DWORD MultiSampleType, DWORD* pQualityLevels);
    HRESULT (STDMETHODCALLTYPE *CheckDepthStencilMatch)(IDirect3D9* This, UINT Adapter, DWORD DeviceType, DWORD AdapterFormat, DWORD RenderTargetFormat, DWORD DepthStencilFormat);
    HRESULT (STDMETHODCALLTYPE *CheckDeviceFormatConversion)(IDirect3D9* This, UINT Adapter, DWORD DeviceType, DWORD SourceFormat, DWORD TargetFormat);
    HRESULT (STDMETHODCALLTYPE *GetDeviceCaps)(IDirect3D9* This, UINT Adapter, DWORD DeviceType, void* pCaps);
    HMONITOR (STDMETHODCALLTYPE *GetAdapterMonitor)(IDirect3D9* This, UINT Adapter);
    HRESULT (STDMETHODCALLTYPE *CreateDevice)(IDirect3D9* This, UINT Adapter, DWORD DeviceType, HWND hFocusWindow, DWORD BehaviorFlags, void* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface);
} IDirect3D9Vtbl;

struct IDirect3D9 {
    const IDirect3D9Vtbl* lpVtbl;
};

#ifdef __cplusplus
}
#endif

#endif // _D3D9_H_
"""
    
    (output_dir / 'd3d9.h').write_text(d3d9_content, encoding='utf-8')
    print("  Created d3d9.h ✓")
    
    # Минимальный d3d11.h
    d3d11_content = """
// Minimal d3d11.h for emulator
// Based on DirectX SDK

#ifndef _D3D11_H_
#define _D3D11_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef interface ID3D11Device ID3D11Device;
typedef interface ID3D11DeviceContext ID3D11DeviceContext;

// D3D11 creation function
HRESULT WINAPI D3D11CreateDevice(
    void* pAdapter,
    UINT DriverType,
    HMODULE Software,
    UINT Flags,
    const UINT* pFeatureLevels,
    UINT FeatureLevels,
    UINT SDKVersion,
    ID3D11Device** ppDevice,
    UINT* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext
);

HRESULT WINAPI D3D11CreateDeviceAndSwapChain(
    void* pAdapter,
    UINT DriverType,
    HMODULE Software,
    UINT Flags,
    const UINT* pFeatureLevels,
    UINT FeatureLevels,
    UINT SDKVersion,
    const void* pSwapChainDesc,
    void** ppSwapChain,
    ID3D11Device** ppDevice,
    UINT* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext
);

#ifdef __cplusplus
}
#endif

#endif // _D3D11_H_
"""
    
    (output_dir / 'd3d11.h').write_text(d3d11_content, encoding='utf-8')
    print("  Created d3d11.h ✓")
    
    # Минимальный dxgi.h
    dxgi_content = """
// Minimal dxgi.h for emulator
// Based on DirectX SDK

#ifndef _DXGI_H_
#define _DXGI_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef interface IDXGIFactory IDXGIFactory;
typedef interface IDXGIAdapter IDXGIAdapter;
typedef interface IDXGISwapChain IDXGISwapChain;

// DXGI creation function
HRESULT WINAPI CreateDXGIFactory(
    REFIID riid,
    void** ppFactory
);

HRESULT WINAPI CreateDXGIFactory1(
    REFIID riid,
    void** ppFactory
);

HRESULT WINAPI CreateDXGIFactory2(
    UINT Flags,
    REFIID riid,
    void** ppFactory
);

#ifdef __cplusplus
}
#endif

#endif // _DXGI_H_
"""
    
    (output_dir / 'dxgi.h').write_text(dxgi_content, encoding='utf-8')
    print("  Created dxgi.h ✓")


def main():
    """Основная функция"""
    print("=" * 70)
    print("DirectX SDK Headers Downloader")
    print("=" * 70)
    print()
    
    # Создаём директорию для заголовков
    headers_dir = Path('tools/directx_headers')
    headers_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Output directory: {headers_dir.absolute()}")
    print()
    
    # Пытаемся найти локальный SDK
    local_sdk = download_from_local_sdk()
    
    if local_sdk:
        # Копируем из локального SDK
        copied = copy_from_local_sdk(local_sdk, headers_dir)
        print(f"\n[+] Copied {copied} DirectX headers from local SDK")
    else:
        print("[!] Local DirectX SDK not found")
        print("[*] Creating minimal DirectX headers...")
        create_minimal_directx_headers(headers_dir)
        print("\n[+] Created minimal DirectX headers")
    
    print()
    print("=" * 70)
    print("Next steps:")
    print("  1. Review headers in tools/directx_headers/")
    print("  2. Run: python tools/directx_parser.py")
    print("  3. Generated stubs will be in tools/generated/")
    print("=" * 70)


if __name__ == '__main__':
    main()
