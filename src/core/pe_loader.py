#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE Loader — загрузка PE-файлов в эмулятор

Минимальная реализация для загрузки учебного анти-тампера.
"""

import pefile
from unicorn.x86_const import *


class PELoader:
    """Загрузчик PE-файлов для эмулятора"""
    
    def __init__(self, emulator):
        self.emu = emulator
        self.pe = None
        self.image_base = 0
        self.entry_point = 0
    
    def load(self, filepath):
        """Загрузить PE-файл в память эмулятора"""
        print(f"[*] Загрузка PE: {filepath}")
        
        # Парсим PE
        self.pe = pefile.PE(filepath)
        
        # Получаем базовый адрес и точку входа
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        print(f"[*] ImageBase: 0x{self.image_base:x}")
        print(f"[*] EntryPoint: 0x{self.entry_point:x}")
        print(f"[*] Секций: {self.pe.FILE_HEADER.NumberOfSections}")
        
        # Выделяем память под образ (если ещё не выделена)
        image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        try:
            self.emu.uc.mem_map(self.image_base, image_size)
            print(f"[*] Выделено памяти: {image_size:,} байт")
        except:
            print(f"[*] Память уже выделена (используем существующую)")
        
        # Загружаем секции
        self._load_sections()
        
        # Обрабатываем импорты (патчим IAT)
        self._process_imports()
        
        # Настраиваем стек
        self._setup_stack()
        
        print(f"[OK] PE загружен успешно\n")
        return self.entry_point
    
    def _load_sections(self):
        """Загрузить все секции в память"""
        print(f"\n[*] Загрузка секций:")
        
        for section in self.pe.sections:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
            va = self.image_base + section.VirtualAddress
            size = section.Misc_VirtualSize
            data = section.get_data()
            
            if data:
                self.emu.uc.mem_write(va, data)
                print(f"    {name:<12} 0x{va:x}  {len(data):,} байт")
    
    def _process_imports(self):
        """Обработать импорты и патчить IAT"""
        print(f"\n[*] Обработка импортов:")
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("    [!] Нет импортов")
            return
        
        import_count = 0
        patched_count = 0
        
        # Сначала находим диапазон адресов IAT и выделяем память
        iat_addresses = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                iat_addresses.append(self.image_base + imp.address)
        
        if iat_addresses:
            min_iat = min(iat_addresses)
            max_iat = max(iat_addresses) + 8
            iat_size = ((max_iat - min_iat + 0xFFF) // 0x1000) * 0x1000  # Выравнивание
            
            # Выделяем память для IAT если нужно
            try:
                self.emu.uc.mem_map(min_iat, iat_size)
                print(f"    [*] Выделено для IAT: 0x{min_iat:x} - 0x{max_iat:x} ({iat_size:,} байт)")
            except:
                print(f"    [*] IAT уже в выделенной памяти")
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('ascii', errors='ignore')
            print(f"    DLL: {dll_name}")
            
            for imp in entry.imports:
                import_count += 1
                func_name = imp.name.decode('ascii', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                
                # Получаем адрес в IAT
                iat_address = self.image_base + imp.address
                
                # Проверяем, есть ли заглушка для этой функции
                stub_addr = self.emu.winapi.get_stub_address(func_name)
                
                if stub_addr:
                    # Патчим IAT — записываем адрес заглушки
                    try:
                        self.emu.uc.mem_write(iat_address, stub_addr.to_bytes(8, 'little'))
                        patched_count += 1
                        print(f"      [+] {func_name:<30} @ 0x{iat_address:x} -> 0x{stub_addr:x}")
                    except Exception as e:
                        print(f"      [-] {func_name:<30} @ 0x{iat_address:x} (ошибка патчинга: {e})")
                else:
                    # Заглушки нет — создаём dummy stub
                    dummy_stub = self._create_dummy_stub(func_name)
                    try:
                        self.emu.uc.mem_write(iat_address, dummy_stub.to_bytes(8, 'little'))
                        print(f"      [?] {func_name:<30} @ 0x{iat_address:x} -> dummy")
                    except Exception as e:
                        print(f"      [-] {func_name:<30} @ 0x{iat_address:x} (ошибка: {e})")
        
        print(f"\n    [*] Импортов: {import_count}, патчено: {patched_count}")
    
    def _create_dummy_stub(self, func_name):
        """Создать dummy заглушку для неизвестной функции"""
        # Выделяем адрес в области заглушек
        # Для простоты возвращаем адрес в конце области WinAPI stubs
        dummy_base = self.emu.winapi.STUB_BASE + 0xF000
        
        # Записываем простую заглушку: MOV RAX, 0; RET
        stub_code = bytes([
            0x48, 0x31, 0xC0,  # XOR RAX, RAX
            0xC3,              # RET
        ])
        
        try:
            self.emu.uc.mem_write(dummy_base, stub_code)
        except:
            pass  # Память уже выделена
        
        return dummy_base
    
    def _setup_stack(self):
        """Настроить стек"""
        # Стек уже выделен в SimpleEmulator
        # Просто устанавливаем указатели
        stack_top = self.emu.STACK_BASE + self.emu.STACK_SIZE - 0x1000
        
        self.emu.uc.reg_write(UC_X86_REG_RSP, stack_top)
        self.emu.uc.reg_write(UC_X86_REG_RBP, stack_top)
        
        print(f"\n[*] Стек: 0x{stack_top:x}")


if __name__ == "__main__":
    # Тест загрузчика
    import sys
    from simple_emulator import SimpleEmulator
    
    if len(sys.argv) < 2:
        print("Использование: python pe_loader.py <файл.exe>")
        sys.exit(1)
    
    emu = SimpleEmulator()
    loader = PELoader(emu)
    
    try:
        entry = loader.load(sys.argv[1])
        print(f"[OK] Готов к запуску с адреса 0x{entry:x}")
    except Exception as e:
        print(f"[!] Ошибка загрузки: {e}")
        import traceback
        traceback.print_exc()
