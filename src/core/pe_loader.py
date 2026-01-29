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
