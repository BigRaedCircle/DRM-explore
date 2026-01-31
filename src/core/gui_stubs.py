#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Stubs - заглушки для user32.dll и gdi32.dll

Стратегия: CPU-Z в CLI режиме (-txt=report) не должен использовать GUI,
но инициализирует GUI компоненты. Возвращаем "успех" для всех GUI вызовов.
"""

from unicorn.x86_const import *


class GUIStubs:
    """Заглушки для GUI функций (user32.dll, gdi32.dll)"""
    
    def __init__(self, emulator):
        self.emu = emulator
        self.uc = emulator.uc
        
        # Фейковые handles
        self.fake_hwnd = 0x10001000  # Фейковое окно
        self.fake_hdc = 0x20002000   # Фейковый device context
        self.fake_hfont = 0x30003000 # Фейковый шрифт
        self.fake_hbrush = 0x40004000 # Фейковая кисть
        
        # Счётчики для уникальных handles
        self.hwnd_counter = 0
        self.hdc_counter = 0
    
    # ========================================================================
    # USER32.DLL - Window Management
    # ========================================================================
    
    def RegisterClassW(self):
        """RegisterClassW() - регистрация класса окна"""
        lpWndClass = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[GUI] RegisterClassW(0x{lpWndClass:x}) -> 0x1234 [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 0x1234)  # Фейковый atom
        return 0x1234
    
    def CreateWindowExW(self):
        """CreateWindowExW() - создание окна"""
        print(f"[GUI] CreateWindowExW() -> 0x{self.fake_hwnd:x} [FAKE]")
        self.hwnd_counter += 1
        hwnd = self.fake_hwnd + self.hwnd_counter
        self.uc.reg_write(UC_X86_REG_RAX, hwnd)
        return hwnd
    
    def ShowWindow(self):
        """ShowWindow() - показать окно"""
        hWnd = self.uc.reg_read(UC_X86_REG_RCX)
        nCmdShow = self.uc.reg_read(UC_X86_REG_RDX)
        print(f"[GUI] ShowWindow(0x{hWnd:x}, {nCmdShow}) -> TRUE [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def UpdateWindow(self):
        """UpdateWindow() - обновить окно"""
        hWnd = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[GUI] UpdateWindow(0x{hWnd:x}) -> TRUE [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def DestroyWindow(self):
        """DestroyWindow() - уничтожить окно"""
        hWnd = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[GUI] DestroyWindow(0x{hWnd:x}) -> TRUE [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def GetDC(self):
        """GetDC() - получить device context"""
        hWnd = self.uc.reg_read(UC_X86_REG_RCX)
        self.hdc_counter += 1
        hdc = self.fake_hdc + self.hdc_counter
        print(f"[GUI] GetDC(0x{hWnd:x}) -> 0x{hdc:x} [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, hdc)
        return hdc
    
    def ReleaseDC(self):
        """ReleaseDC() - освободить device context"""
        hWnd = self.uc.reg_read(UC_X86_REG_RCX)
        hDC = self.uc.reg_read(UC_X86_REG_RDX)
        print(f"[GUI] ReleaseDC(0x{hWnd:x}, 0x{hDC:x}) -> 1 [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def GetSystemMetrics(self):
        """GetSystemMetrics() - получить системные метрики"""
        nIndex = self.uc.reg_read(UC_X86_REG_RCX)
        
        # Возвращаем разумные значения
        metrics = {
            0: 1920,   # SM_CXSCREEN - ширина экрана
            1: 1080,   # SM_CYSCREEN - высота экрана
            11: 16,    # SM_CXICON - ширина иконки
            12: 16,    # SM_CYICON - высота иконки
        }
        
        value = metrics.get(nIndex, 0)
        print(f"[GUI] GetSystemMetrics({nIndex}) -> {value} [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, value)
        return value
    
    def MessageBoxW(self):
        """MessageBoxW() - показать message box"""
        hWnd = self.uc.reg_read(UC_X86_REG_RCX)
        lpText = self.uc.reg_read(UC_X86_REG_RDX)
        lpCaption = self.uc.reg_read(UC_X86_REG_R8)
        uType = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[GUI] MessageBoxW(0x{hWnd:x}) -> IDOK [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # IDOK
        return 1
    
    def DefWindowProcW(self):
        """DefWindowProcW() - default window procedure"""
        print(f"[GUI] DefWindowProcW() -> 0 [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def PostQuitMessage(self):
        """PostQuitMessage() - послать WM_QUIT"""
        nExitCode = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[GUI] PostQuitMessage({nExitCode}) [FAKE]")
        return 0
    
    def GetMessageW(self):
        """GetMessageW() - получить сообщение"""
        print(f"[GUI] GetMessageW() -> 0 (WM_QUIT) [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)  # WM_QUIT
        return 0
    
    def DispatchMessageW(self):
        """DispatchMessageW() - отправить сообщение"""
        print(f"[GUI] DispatchMessageW() -> 0 [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def TranslateMessage(self):
        """TranslateMessage() - транслировать сообщение"""
        print(f"[GUI] TranslateMessage() -> FALSE [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    # ========================================================================
    # GDI32.DLL - Graphics Device Interface
    # ========================================================================
    
    def CreateFontW(self):
        """CreateFontW() - создать шрифт"""
        print(f"[GDI] CreateFontW() -> 0x{self.fake_hfont:x} [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, self.fake_hfont)
        return self.fake_hfont
    
    def SelectObject(self):
        """SelectObject() - выбрать объект в DC"""
        hDC = self.uc.reg_read(UC_X86_REG_RCX)
        hObject = self.uc.reg_read(UC_X86_REG_RDX)
        print(f"[GDI] SelectObject(0x{hDC:x}, 0x{hObject:x}) -> 0x{hObject:x} [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, hObject)
        return hObject
    
    def DeleteObject(self):
        """DeleteObject() - удалить объект"""
        hObject = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[GDI] DeleteObject(0x{hObject:x}) -> TRUE [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def TextOutW(self):
        """TextOutW() - вывести текст"""
        hDC = self.uc.reg_read(UC_X86_REG_RCX)
        x = self.uc.reg_read(UC_X86_REG_RDX)
        y = self.uc.reg_read(UC_X86_REG_R8)
        print(f"[GDI] TextOutW(0x{hDC:x}, {x}, {y}) -> TRUE [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def SetTextColor(self):
        """SetTextColor() - установить цвет текста"""
        hDC = self.uc.reg_read(UC_X86_REG_RCX)
        color = self.uc.reg_read(UC_X86_REG_RDX)
        print(f"[GDI] SetTextColor(0x{hDC:x}, 0x{color:x}) -> 0x{color:x} [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, color)
        return color
    
    def SetBkMode(self):
        """SetBkMode() - установить режим фона"""
        hDC = self.uc.reg_read(UC_X86_REG_RCX)
        mode = self.uc.reg_read(UC_X86_REG_RDX)
        print(f"[GDI] SetBkMode(0x{hDC:x}, {mode}) -> {mode} [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, mode)
        return mode
    
    def GetStockObject(self):
        """GetStockObject() - получить стандартный объект"""
        i = self.uc.reg_read(UC_X86_REG_RCX)
        obj = 0x50005000 + i
        print(f"[GDI] GetStockObject({i}) -> 0x{obj:x} [FAKE]")
        self.uc.reg_write(UC_X86_REG_RAX, obj)
        return obj
    
    # ========================================================================
    # Универсальная заглушка для неизвестных GUI функций
    # ========================================================================
    
    def generic_gui_stub(self, func_name):
        """Универсальная заглушка для GUI функций"""
        print(f"[GUI] {func_name}() -> SUCCESS [GENERIC STUB]")
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # Возвращаем "успех"
        return 1
    
    def get_stub(self, func_name):
        """Получить заглушку по имени функции"""
        # Пробуем найти конкретную реализацию
        method_name = func_name.replace('A', '').replace('W', '')  # Убираем A/W суффиксы
        
        if hasattr(self, method_name):
            return getattr(self, method_name)
        
        # Возвращаем универсальную заглушку
        return lambda: self.generic_gui_stub(func_name)


if __name__ == '__main__':
    print("=" * 70)
    print("GUI Stubs - заглушки для user32.dll и gdi32.dll")
    print("=" * 70)
    print()
    print("Этот модуль предоставляет заглушки для GUI функций.")
    print("CPU-Z в CLI режиме не должен использовать GUI, но инициализирует компоненты.")
    print()
    print("Стратегия: Возвращаем 'успех' для всех GUI вызовов.")
    print()
