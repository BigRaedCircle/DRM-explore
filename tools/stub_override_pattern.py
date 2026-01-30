#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Паттерн переопределения сгенерированных заглушек

Позволяет модифицировать поведение без изменения автогенерированного кода
"""

from typing import Dict, Callable, Optional


class StubRegistry:
    """
    Реестр заглушек с поддержкой переопределения
    
    Приоритеты (от высшего к низшему):
    1. Custom implementations (ручные реализации)
    2. Generated stubs (автогенерированные)
    3. Default fallback (базовая заглушка)
    """
    
    def __init__(self):
        # Слой 1: Автогенерированные заглушки (базовый)
        self._generated_stubs: Dict[str, Callable] = {}
        
        # Слой 2: Пользовательские переопределения (приоритетный)
        self._custom_stubs: Dict[str, Callable] = {}
        
        # Слой 3: Декораторы (модификаторы поведения)
        self._decorators: Dict[str, list] = {}
    
    def register_generated(self, name: str, func: Callable):
        """Регистрация автогенерированной заглушки"""
        self._generated_stubs[name] = func
    
    def register_custom(self, name: str, func: Callable):
        """Регистрация пользовательской реализации (переопределяет generated)"""
        self._custom_stubs[name] = func
    
    def add_decorator(self, name: str, decorator: Callable):
        """Добавление декоратора к заглушке"""
        if name not in self._decorators:
            self._decorators[name] = []
        self._decorators[name].append(decorator)
    
    def get_stub(self, name: str) -> Optional[Callable]:
        """Получить заглушку с учётом приоритетов"""
        # Приоритет 1: Пользовательская реализация
        if name in self._custom_stubs:
            func = self._custom_stubs[name]
        # Приоритет 2: Автогенерированная
        elif name in self._generated_stubs:
            func = self._generated_stubs[name]
        else:
            return None
        
        # Применяем декораторы (если есть)
        if name in self._decorators:
            for decorator in self._decorators[name]:
                func = decorator(func)
        
        return func
    
    def list_stubs(self):
        """Список всех заглушек с указанием типа"""
        all_stubs = set(self._generated_stubs.keys()) | set(self._custom_stubs.keys())
        
        result = []
        for name in sorted(all_stubs):
            stub_type = 'custom' if name in self._custom_stubs else 'generated'
            has_decorators = name in self._decorators
            result.append({
                'name': name,
                'type': stub_type,
                'decorated': has_decorators
            })
        
        return result


# ============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ
# ============================================================================

class WinAPIStubs:
    """Пример интеграции с эмулятором"""
    
    def __init__(self, emulator):
        self.emu = emulator
        self.uc = emulator.uc
        self.registry = StubRegistry()
        
        # Шаг 1: Загружаем автогенерированные заглушки
        self._load_generated_stubs()
        
        # Шаг 2: Регистрируем пользовательские реализации
        self._register_custom_implementations()
        
        # Шаг 3: Добавляем декораторы
        self._add_decorators()
    
    def _load_generated_stubs(self):
        """Загрузка автогенерированных заглушек"""
        # Импортируем сгенерированный модуль
        from tools.generated import winapi_stubs_generated
        
        # Регистрируем все функции из модуля
        for name in dir(winapi_stubs_generated):
            if name.startswith('_stub_'):
                func_name = name[6:]  # Убираем префикс _stub_
                func = getattr(winapi_stubs_generated, name)
                
                # Биндим self к функции
                bound_func = lambda *args, f=func, **kwargs: f(self, *args, **kwargs)
                self.registry.register_generated(func_name, bound_func)
    
    def _register_custom_implementations(self):
        """Регистрация пользовательских реализаций (переопределения)"""
        
        # Пример: CreateFileA с реальной логикой
        def createfilea_custom(self):
            """CreateFileA() - с реальной файловой системой"""
            lpFileName = self.uc.reg_read(UC_X86_REG_RCX)
            dwDesiredAccess = self.uc.reg_read(UC_X86_REG_RDX)
            
            filename = self._read_string(lpFileName)
            print(f"[API] CreateFileA('{filename}') [CUSTOM]")
            
            # Используем VirtualFileSystem
            handle = self.emu.vfs.open(filename, dwDesiredAccess)
            self.uc.reg_write(UC_X86_REG_RAX, handle)
            return handle
        
        self.registry.register_custom('createfilea', createfilea_custom)
        
        # Пример: ReadFile с реальной логикой
        def readfile_custom(self):
            """ReadFile() - с реальным чтением"""
            hFile = self.uc.reg_read(UC_X86_REG_RCX)
            lpBuffer = self.uc.reg_read(UC_X86_REG_RDX)
            nNumberOfBytesToRead = self.uc.reg_read(UC_X86_REG_R8)
            
            print(f"[API] ReadFile(handle=0x{hFile:x}, size={nNumberOfBytesToRead}) [CUSTOM]")
            
            # Читаем из VFS
            data = self.emu.vfs.read(hFile, nNumberOfBytesToRead)
            if data:
                self.uc.mem_write(lpBuffer, data)
                self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
            else:
                self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
            
            return len(data) if data else 0
        
        self.registry.register_custom('readfile', readfile_custom)
    
    def _add_decorators(self):
        """Добавление декораторов для модификации поведения"""
        
        # Декоратор для логирования
        def logging_decorator(func):
            def wrapper(*args, **kwargs):
                print(f"[TRACE] Calling {func.__name__}")
                result = func(*args, **kwargs)
                print(f"[TRACE] {func.__name__} returned {result}")
                return result
            return wrapper
        
        # Декоратор для подсчёта вызовов
        def counting_decorator(func):
            func.call_count = 0
            def wrapper(*args, **kwargs):
                func.call_count += 1
                return func(*args, **kwargs)
            wrapper.call_count = func.call_count
            return wrapper
        
        # Применяем декораторы к конкретным функциям
        self.registry.add_decorator('createfilea', logging_decorator)
        self.registry.add_decorator('createfilea', counting_decorator)
    
    def call_stub(self, name: str):
        """Вызов заглушки по имени"""
        stub = self.registry.get_stub(name.lower())
        if stub:
            return stub()
        else:
            print(f"[!] Stub not found: {name}")
            return 0


# ============================================================================
# АЛЬТЕРНАТИВНЫЙ ПОДХОД: Наследование с переопределением
# ============================================================================

class GeneratedStubs:
    """Базовый класс с автогенерированными заглушками"""
    
    def _stub_createfilea(self):
        """CreateFileA() - автогенерированная заглушка"""
        print("[API] CreateFileA() [GENERATED]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _stub_readfile(self):
        """ReadFile() - автогенерированная заглушка"""
        print("[API] ReadFile() [GENERATED]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0


class CustomStubs(GeneratedStubs):
    """Пользовательские переопределения (наследуем от Generated)"""
    
    def _stub_createfilea(self):
        """CreateFileA() - переопределённая версия"""
        lpFileName = self.uc.reg_read(UC_X86_REG_RCX)
        filename = self._read_string(lpFileName)
        print(f"[API] CreateFileA('{filename}') [CUSTOM]")
        
        # Реальная логика
        handle = self.emu.vfs.open(filename, ...)
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    # readfile не переопределяем - используется автогенерированная версия


# ============================================================================
# РЕКОМЕНДУЕМАЯ СТРУКТУРА ФАЙЛОВ
# ============================================================================

"""
src/core/
├── winapi_stubs.py              # Основной класс WinAPIStubs
├── winapi_custom.py             # Пользовательские реализации
└── winapi_decorators.py         # Декораторы

tools/generated/
├── winapi_stubs_generated.py    # Автогенерированные (НЕ ТРОГАТЬ!)
└── directx_stubs_generated.py   # Автогенерированные (НЕ ТРОГАТЬ!)

Использование:
--------------
1. Парсер генерирует tools/generated/*.py
2. src/core/winapi_stubs.py импортирует generated
3. src/core/winapi_custom.py содержит переопределения
4. StubRegistry выбирает нужную версию по приоритету
"""


# ============================================================================
# ПРИМЕР КОНФИГУРАЦИИ
# ============================================================================

STUB_OVERRIDES = {
    # Критичные функции - полная реализация
    'createfilea': 'custom',
    'createfilew': 'custom',
    'readfile': 'custom',
    'writefile': 'custom',
    'closefile': 'custom',
    
    # Важные функции - частичная реализация
    'heapalloc': 'custom',
    'heapfree': 'custom',
    'virtualalloc': 'custom',
    
    # Остальные - автогенерированные заглушки (fake but valid)
    # ... (436 функций)
}


if __name__ == '__main__':
    print("=" * 70)
    print("Stub Override Pattern - Demo")
    print("=" * 70)
    print()
    
    # Демонстрация работы реестра
    registry = StubRegistry()
    
    # Регистрируем автогенерированную заглушку
    def generated_createfile():
        return "GENERATED: fake handle"
    
    registry.register_generated('createfilea', generated_createfile)
    
    # Регистрируем пользовательскую реализацию
    def custom_createfile():
        return "CUSTOM: real VFS handle"
    
    registry.register_custom('createfilea', custom_createfile)
    
    # Получаем заглушку (будет custom, т.к. приоритет выше)
    stub = registry.get_stub('createfilea')
    print(f"Result: {stub()}")
    print()
    
    # Список всех заглушек
    print("Registered stubs:")
    for info in registry.list_stubs():
        print(f"  - {info['name']}: {info['type']}")
