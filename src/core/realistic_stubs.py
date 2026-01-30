#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Realistic Stubs — правдоподобные заглушки для периферии

Принцип: Заглушки должны вести себя как реальные функции:
- DirectX: возвращать реальные данные о GPU, соблюдать тайминги рендеринга
- Файлы: предоставлять реальные файлы из виртуальной FS
- Сеть: имитировать задержки, возвращать правдоподобные данные
- GPU: возвращать реальные характеристики целевой системы

Цель: Полная иллюзия работы на реальной системе для анти-тампера
"""

import ctypes
import struct
import os
from ctypes import wintypes


class SystemInfo:
    """Реальная информация о целевой системе"""
    
    def __init__(self):
        # Получаем РЕАЛЬНЫЕ данные о системе
        self._gather_real_system_info()
    
    def _gather_real_system_info(self):
        """Собираем реальные данные о системе"""
        # CPU
        try:
            import platform
            self.cpu_name = platform.processor()
            self.cpu_cores = os.cpu_count() or 8
        except:
            self.cpu_name = "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"
            self.cpu_cores = 8
        
        # Memory
        try:
            kernel32 = ctypes.WinDLL('kernel32')
            
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            
            mem_status = MEMORYSTATUSEX()
            mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
            
            self.total_memory = mem_status.ullTotalPhys
            self.available_memory = mem_status.ullAvailPhys
        except:
            self.total_memory = 16 * 1024 * 1024 * 1024  # 16 GB
            self.available_memory = 8 * 1024 * 1024 * 1024  # 8 GB
        
        # GPU (попытка получить реальные данные)
        self.gpu_name = self._get_gpu_name()
        self.gpu_memory = self._get_gpu_memory()
        self.gpu_vendor_id = 0x10DE  # NVIDIA
        self.gpu_device_id = 0x1B80  # GTX 1080
    
    def _get_gpu_name(self):
        """Получить имя GPU из реестра или WMI"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000")
            gpu_name, _ = winreg.QueryValueEx(key, "DriverDesc")
            winreg.CloseKey(key)
            return gpu_name
        except:
            return "NVIDIA GeForce GTX 1080"
    
    def _get_gpu_memory(self):
        """Получить объём видеопамяти"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000")
            vram, _ = winreg.QueryValueEx(key, "HardwareInformation.qwMemorySize")
            winreg.CloseKey(key)
            return vram
        except:
            return 8 * 1024 * 1024 * 1024  # 8 GB


class VirtualFileSystem:
    """Виртуальная файловая система с реальными файлами"""
    
    def __init__(self, base_path="."):
        self.base_path = base_path
        self.open_files = {}  # handle -> (path, position, mode)
        self.next_handle = 0x1000
    
    def open(self, path, mode='rb'):
        """Открыть файл (реальный или виртуальный)"""
        # Нормализуем путь
        normalized_path = path.replace('\\', '/').lower()
        
        # Проверяем, существует ли реальный файл
        real_path = os.path.join(self.base_path, normalized_path.lstrip('/'))
        
        if os.path.exists(real_path):
            # Открываем реальный файл
            try:
                file_obj = open(real_path, mode)
                handle = self.next_handle
                self.next_handle += 1
                
                self.open_files[handle] = {
                    'path': real_path,
                    'file': file_obj,
                    'position': 0,
                    'size': os.path.getsize(real_path)
                }
                
                return handle
            except:
                return None
        else:
            # Создаём виртуальный файл (пустой)
            handle = self.next_handle
            self.next_handle += 1
            
            self.open_files[handle] = {
                'path': normalized_path,
                'file': None,  # Виртуальный
                'position': 0,
                'size': 0,
                'data': b''  # Пустые данные
            }
            
            return handle
    
    def read(self, handle, size):
        """Прочитать из файла"""
        if handle not in self.open_files:
            return None
        
        file_info = self.open_files[handle]
        
        if file_info['file']:
            # Реальный файл
            data = file_info['file'].read(size)
            file_info['position'] += len(data)
            return data
        else:
            # Виртуальный файл (возвращаем нули)
            data = b'\x00' * size
            file_info['position'] += size
            return data
    
    def close(self, handle):
        """Закрыть файл"""
        if handle in self.open_files:
            file_info = self.open_files[handle]
            if file_info['file']:
                file_info['file'].close()
            del self.open_files[handle]
            return True
        return False
    
    def get_size(self, handle):
        """Получить размер файла"""
        if handle in self.open_files:
            return self.open_files[handle]['size']
        return 0


class DirectXStubs:
    """Правдоподобные заглушки для DirectX"""
    
    def __init__(self, system_info, clock):
        self.system_info = system_info
        self.clock = clock
        
        # Состояние DirectX
        self.device_created = False
        self.swap_chain = None
        self.frame_count = 0
        self.last_present_time = 0
        
        # Тайминги рендеринга (60 FPS = 16.67 мс на кадр)
        self.target_frame_time_ms = 16.67
        self.target_frame_time_ticks = int(self.target_frame_time_ms * clock.cpu_freq_mhz * 1000)
    
    def D3D11CreateDevice(self, adapter, driver_type, software, flags, feature_levels, sdk_version):
        """Создание D3D11 устройства"""
        print(f"[D3D11] CreateDevice()")
        print(f"  GPU: {self.system_info.gpu_name}")
        print(f"  VRAM: {self.system_info.gpu_memory // (1024*1024)} MB")
        
        # Имитируем задержку инициализации GPU (~50 мс)
        init_ticks = int(50 * self.clock.cpu_freq_mhz * 1000)
        self.clock.advance(init_ticks)
        
        self.device_created = True
        
        # Возвращаем фейковые указатели на device и context
        device_ptr = 0x20000000
        context_ptr = 0x20000100
        
        return (0, device_ptr, context_ptr)  # S_OK, device, context
    
    def CreateSwapChain(self, device, desc):
        """Создание swap chain"""
        print(f"[D3D11] CreateSwapChain()")
        print(f"  Resolution: {desc.get('width', 1920)}x{desc.get('height', 1080)}")
        print(f"  Format: {desc.get('format', 'DXGI_FORMAT_R8G8B8A8_UNORM')}")
        
        # Имитируем задержку создания swap chain (~20 мс)
        init_ticks = int(20 * self.clock.cpu_freq_mhz * 1000)
        self.clock.advance(init_ticks)
        
        self.swap_chain = 0x20000200
        return (0, self.swap_chain)  # S_OK, swap_chain
    
    def Present(self, sync_interval=0):
        """Презентация кадра (vsync)"""
        self.frame_count += 1
        
        # Вычисляем время с последнего Present
        current_time = self.clock.ticks
        
        # Если это первый вызов, инициализируем last_present_time
        if self.last_present_time == 0:
            self.last_present_time = current_time
        
        delta = current_time - self.last_present_time
        
        # Если vsync включён (sync_interval > 0), имитируем ожидание
        if sync_interval > 0:
            # Ждём до следующего vsync (60 Hz = 16.67 мс)
            if delta < self.target_frame_time_ticks:
                wait_ticks = self.target_frame_time_ticks - delta
                self.clock.advance(wait_ticks)
            else:
                # Если прошло больше времени, просто продвигаем на минимум
                self.clock.advance(int(1 * self.clock.cpu_freq_mhz * 1000))
        else:
            # Без vsync — минимальная задержка (~1 мс)
            self.clock.advance(int(1 * self.clock.cpu_freq_mhz * 1000))
        
        self.last_present_time = self.clock.ticks
        
        if self.frame_count % 60 == 0:
            print(f"[D3D11] Present() - Frame {self.frame_count}, VirtualTime: {self.clock}")
        
        return 0  # S_OK
    
    def GetAdapterDesc(self):
        """Получить описание адаптера (GPU)"""
        print(f"[DXGI] GetAdapterDesc()")
        print(f"  -> {self.system_info.gpu_name}")
        
        # Возвращаем структуру DXGI_ADAPTER_DESC
        desc = {
            'Description': self.system_info.gpu_name,
            'VendorId': self.system_info.gpu_vendor_id,
            'DeviceId': self.system_info.gpu_device_id,
            'SubSysId': 0,
            'Revision': 0,
            'DedicatedVideoMemory': self.system_info.gpu_memory,
            'DedicatedSystemMemory': 0,
            'SharedSystemMemory': self.system_info.total_memory // 2,
        }
        
        return desc


class NetworkStubs:
    """Правдоподобные заглушки для сети"""
    
    def __init__(self, clock):
        self.clock = clock
        
        # Имитация сетевых задержек
        self.ping_ms = 30  # 30 мс пинг
        self.download_speed_mbps = 100  # 100 Мбит/с
    
    def connect(self, host, port):
        """Подключение к серверу"""
        print(f"[NET] connect({host}:{port})")
        
        # Имитируем задержку подключения (ping + handshake)
        connect_time_ms = self.ping_ms * 3  # ~90 мс
        connect_ticks = int(connect_time_ms * self.clock.cpu_freq_mhz * 1000)
        self.clock.advance(connect_ticks)
        
        print(f"  -> Connected (latency: {connect_time_ms} ms)")
        
        # Возвращаем фейковый socket
        return 0x30000000
    
    def send(self, socket, data):
        """Отправка данных"""
        size = len(data)
        
        # Имитируем задержку отправки
        send_time_ms = (size * 8) / (self.download_speed_mbps * 1000) + self.ping_ms
        send_ticks = int(send_time_ms * self.clock.cpu_freq_mhz * 1000)
        self.clock.advance(send_ticks)
        
        print(f"[NET] send({size} bytes) - {send_time_ms:.2f} ms")
        
        return size
    
    def recv(self, socket, size):
        """Получение данных"""
        # Имитируем задержку получения
        recv_time_ms = (size * 8) / (self.download_speed_mbps * 1000) + self.ping_ms
        recv_ticks = int(recv_time_ms * self.clock.cpu_freq_mhz * 1000)
        self.clock.advance(recv_ticks)
        
        print(f"[NET] recv({size} bytes) - {recv_time_ms:.2f} ms")
        
        # Возвращаем фейковые данные (нули)
        return b'\x00' * size


if __name__ == "__main__":
    print("Realistic Stubs — правдоподобные заглушки для периферии")
    print("\nПринцип: Заглушки ведут себя как реальные функции:")
    print("  • DirectX: реальные данные о GPU, корректные тайминги")
    print("  • Файлы: виртуальная FS с реальными файлами")
    print("  • Сеть: имитация задержек и пропускной способности")
    print("  • Система: реальные характеристики CPU/RAM/GPU")
    print("\nЦель: Полная иллюзия работы на реальной системе")
