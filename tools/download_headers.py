#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download Windows SDK Headers

Скачивает необходимые заголовочные файлы из официальных источников
для генерации заглушек WinAPI
"""

import urllib.request
import urllib.error
from pathlib import Path
from typing import List


# Базовые заголовки, которые нужны для эмуляции
REQUIRED_HEADERS = {
    'kernel32.dll': [
        'fileapi.h',           # File I/O
        'processthreadsapi.h', # Process/Thread management
        'memoryapi.h',         # Memory management
        'synchapi.h',          # Synchronization
        'heapapi.h',           # Heap management
        'libloaderapi.h',      # Library loading
        'errhandlingapi.h',    # Error handling
        'profileapi.h',        # Performance counters
        'sysinfoapi.h',        # System information
        'winbase.h',           # Base definitions
    ],
    'user32.dll': [
        'winuser.h',           # User interface
    ],
    'advapi32.dll': [
        'winreg.h',            # Registry
    ],
    'ws2_32.dll': [
        'winsock2.h',          # Windows Sockets
        'ws2tcpip.h',          # TCP/IP specific
    ],
    'gdi32.dll': [
        'wingdi.h',            # Graphics Device Interface
    ],
}


# URL шаблоны для скачивания
# Используем официальный репозиторий Microsoft Docs
GITHUB_RAW_URL = 'https://raw.githubusercontent.com/MicrosoftDocs/sdk-api/docs/sdk-api-src/content'


def download_file(url: str, output_path: Path) -> bool:
    """Скачивает файл по URL"""
    try:
        print(f"  Downloading {output_path.name}...", end=' ')
        
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read()
            output_path.write_bytes(content)
        
        print(f"✓ ({len(content)} bytes)")
        return True
        
    except urllib.error.HTTPError as e:
        print(f"✗ HTTP {e.code}")
        return False
    except Exception as e:
        print(f"✗ {e}")
        return False


def download_from_local_sdk() -> Path:
    """Пытается найти локально установленный Windows SDK"""
    possible_paths = [
        Path('C:/Program Files (x86)/Windows Kits/10/Include'),
        Path('C:/Program Files/Windows Kits/10/Include'),
    ]
    
    for base_path in possible_paths:
        if base_path.exists():
            # Ищем последнюю версию SDK
            versions = sorted([d for d in base_path.iterdir() if d.is_dir()], reverse=True)
            if versions:
                um_path = versions[0] / 'um'
                if um_path.exists():
                    print(f"[+] Found local Windows SDK: {um_path}")
                    return um_path
    
    return None


def copy_from_local_sdk(headers_dir: Path, output_dir: Path) -> int:
    """Копирует заголовки из локального SDK"""
    copied = 0
    
    for dll_name, headers in REQUIRED_HEADERS.items():
        print(f"\n[*] {dll_name}:")
        
        for header_name in headers:
            source = headers_dir / header_name
            dest = output_dir / header_name
            
            if source.exists():
                print(f"  Copying {header_name}...", end=' ')
                dest.write_bytes(source.read_bytes())
                print(f"✓")
                copied += 1
            else:
                print(f"  {header_name} not found ✗")
    
    return copied


def create_minimal_headers(output_dir: Path):
    """Создаёт минимальные заголовки для базовых функций"""
    print("\n[*] Creating minimal headers for basic functions...")
    
    # Создаём минимальный fileapi.h с основными функциями
    fileapi_content = """
// Minimal fileapi.h for emulator
// Based on Windows SDK

#ifndef _FILEAPI_H_
#define _FILEAPI_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// File I/O functions
WINBASEAPI HANDLE WINAPI CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

WINBASEAPI HANDLE WINAPI CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

WINBASEAPI BOOL WINAPI ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

WINBASEAPI BOOL WINAPI WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

WINBASEAPI BOOL WINAPI CloseHandle(
    HANDLE hObject
);

WINBASEAPI DWORD WINAPI GetFileSize(
    HANDLE hFile,
    LPDWORD lpFileSizeHigh
);

WINBASEAPI BOOL WINAPI GetFileSizeEx(
    HANDLE hFile,
    PLARGE_INTEGER lpFileSize
);

#ifdef __cplusplus
}
#endif

#endif // _FILEAPI_H_
"""
    
    (output_dir / 'fileapi.h').write_text(fileapi_content, encoding='utf-8')
    print("  Created fileapi.h ✓")
    
    # Создаём минимальный processthreadsapi.h
    processthreadsapi_content = """
// Minimal processthreadsapi.h for emulator
// Based on Windows SDK

#ifndef _PROCESSTHREADSAPI_H_
#define _PROCESSTHREADSAPI_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Process/Thread functions
WINBASEAPI DWORD WINAPI GetCurrentProcessId(VOID);
WINBASEAPI DWORD WINAPI GetCurrentThreadId(VOID);
WINBASEAPI HANDLE WINAPI GetCurrentProcess(VOID);
WINBASEAPI HANDLE WINAPI GetCurrentThread(VOID);

WINBASEAPI VOID WINAPI ExitProcess(
    UINT uExitCode
);

WINBASEAPI VOID WINAPI Sleep(
    DWORD dwMilliseconds
);

WINBASEAPI DWORD WINAPI TlsAlloc(VOID);
WINBASEAPI BOOL WINAPI TlsFree(DWORD dwTlsIndex);
WINBASEAPI LPVOID WINAPI TlsGetValue(DWORD dwTlsIndex);
WINBASEAPI BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);

#ifdef __cplusplus
}
#endif

#endif // _PROCESSTHREADSAPI_H_
"""
    
    (output_dir / 'processthreadsapi.h').write_text(processthreadsapi_content, encoding='utf-8')
    print("  Created processthreadsapi.h ✓")


def main():
    """Основная функция"""
    print("=" * 70)
    print("Windows SDK Headers Downloader")
    print("=" * 70)
    print()
    
    # Создаём директорию для заголовков
    headers_dir = Path('tools/headers')
    headers_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Output directory: {headers_dir.absolute()}")
    print()
    
    # Пытаемся найти локальный SDK
    local_sdk = download_from_local_sdk()
    
    if local_sdk:
        # Копируем из локального SDK
        copied = copy_from_local_sdk(local_sdk, headers_dir)
        print(f"\n[+] Copied {copied} headers from local SDK")
    else:
        print("[!] Local Windows SDK not found")
        print("[*] Creating minimal headers...")
        create_minimal_headers(headers_dir)
        print("\n[+] Created minimal headers")
    
    print()
    print("=" * 70)
    print("Next steps:")
    print("  1. Review headers in tools/headers/")
    print("  2. Run: python tools/header_parser.py")
    print("  3. Generated stubs will be in tools/generated/")
    print("=" * 70)


if __name__ == '__main__':
    main()
