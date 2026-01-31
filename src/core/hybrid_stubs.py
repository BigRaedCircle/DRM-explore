"""
Гибридная система заглушек: эмуляция + passthrough + stubs
"""

import ctypes
from ctypes import wintypes
from unicorn.x86_const import *

# Загружаем системные DLL для passthrough
try:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    PASSTHROUGH_AVAILABLE = True
except:
    PASSTHROUGH_AVAILABLE = False
    print("[!] WARNING: Passthrough not available (not on Windows?)")


class HybridStubs:
    """
    Гибридная система заглушек с 3 режимами:
    1. EMULATED - полная эмуляция (для критичных функций)
    2. PASSTHROUGH - проброс в систему (для безопасных read-only функций)
    3. STUB - простая заглушка (для некритичных функций)
    """
    
    # Категории функций
    CRITICAL_EMULATED = {
        # Память и heap - ДОЛЖНЫ быть эмулированы
        'heapalloc', 'heapfree', 'heaprealloc', 'getprocessheap',
        'virtualalloc', 'virtualfree', 'virtualprotect',
        
        # Потоки - эмулируем single-threaded
        'getcurrentthreadid', 'getcurrentprocessid', 'getcurrentthread', 'getcurrentprocess',
        'entercriticalsection', 'leavecriticalsection', 'initializecriticalsection',
        'initializecriticalsectionex', 'initializecriticalsectionandspincount',
        'deletecriticalsection',
        
        # Модули - работают с адресным пространством эмулятора
        'getmodulehandlew', 'getmodulehandleexw', 'getmodulefilenamew',
        'getprocaddress', 'loadlibraryw', 'loadlibraryexw', 'freelibrary',
        
        # Время - виртуальное
        'getsystemtimeasfiletime', 'queryperformancecounter', 'gettickcount',
        'gettickcount64',
        
        # Отладка
        'isdebuggerpresent', 'outputdebugstringw',
        
        # Exit
        'exitprocess', 'terminateprocess',
    }
    
    PASSTHROUGH_SAFE = {
        # Информация о системе (read-only, безопасно)
        'getsysteminfo', 'getnativesysteminfo', 'getversionexw',
        'isprocessorfeaturepresent', 'getlogicalprocessorinformation',
        'getlogicalprocessorinformationex',
        
        # Директории (read-only)
        'getsystemdirectoryw', 'getwindowsdirectoryw',
        
        # Консольный вывод (безопасно)
        'getstdhandle', 'writeconsolew', 'writeconsolea', 'writefile',
        'getconsolemode', 'setconsolemode', 'getconsoleoutputcp', 'getconsolecp',
        'readconsolew', 'readconsolea',
        
        # Ошибки (thread-local, но можно пробросить)
        'getlasterror', 'setlasterror', 'formatmessagea', 'formatmessagew',
        
        # Локализация (read-only)
        'getacp', 'getoemcp', 'getuserdefaultlcid', 'getlocaleinfoW',
        'multibytetowidechar', 'widechartomultibyte',
        'comparestringw', 'lcmapstringw', 'lcmapstringex',
        'getstringtypew', 'getcpinfo', 'isvalidcodepage', 'isvalidlocale',
        
        # Командная строка (read-only)
        'getcommandlinew', 'getcommandlinea',
        
        # Startup info (read-only)
        'getstartupinfow',
        
        # Environment (можно пробросить)
        'getenvironmentstringsw', 'freeenvironmentstringsw',
        'setenvironmentvariablew', 'getenvironmentvariablew',
    }
    
    STUB_NONCRITICAL = {
        # GUI - не нужны для консольного режима
        'sendmessagew', 'dialogboxindirectparamw', 'enddialog',
        'loadcursorw', 'setcursor', 'getdlgitem', 'getsyscolorbrush',
        'setwindowtextw', 'inflaterect',
        
        # Печать - не нужна
        'printdlgw', 'startdocw', 'enddoc', 'startpage', 'endpage',
        'getdevicecaps', 'setmapmode',
        
        # COM - можно заглушить
        'cocreateinstance', 'coinitializesecurity', 'cosetproxyblanket',
        'couninitialize',
        
        # OLEAUT32 - можно заглушить
        'variantinit', 'variantclear', 'sysfreestring', 'sysallocstring',
        'sysstringlen',
        
        # Registry - можно заглушить или эмулировать
        'regopenkeyw', 'regopenkeyexw', 'regqueryvalueexw', 'regclosekey',
        'regcreatekeyw', 'regsetvalueexw', 'regdeletekeyw',
        
        # Privileges - можно заглушить
        'lookupprivilegevaluew', 'adjusttokenprivileges', 'openprocesstoken',
        
        # Exception handling - можно заглушить
        'rtlcapturecontext', 'rtllookupfunctionentry', 'rtlvirtualunwind',
        'rtlunwind', 'rtlunwindex', 'rtlpctofileheader',
        'unhandledexceptionfilter', 'setunhandledexceptionfilter',
        'raiseexception',
        
        # TLS/FLS - можно заглушить
        'tlsalloc', 'tlsgetvalue', 'tlssetvalue', 'tlsfree',
        'flsalloc', 'flsgetvalue', 'flssetvalue', 'flsfree',
        
        # SRW Locks - можно заглушить
        'acquiresrwlockexclusive', 'releasesrwlockexclusive',
        'sleepconditionvariablesrw', 'wakeallconditionvariable',
        
        # Misc
        'initializeslisthead', 'encodepointer', 'decodepointer',
        'setthreadpriority', 'setthreadaffinitymask',
        'getprocessworkingsetsize', 'setprocessworkingsetsize',
        'virtuallock', 'deviceiocontrol',
        'getnumanodeprocessormask', 'getnumahighestnodenumber',
        'findresourcew', 'loadresource', 'lockresource', 'sizeofresource',
        'createfilew', 'readfile', 'closefile', 'deletefile',
        'findfirstfileexw', 'findnextfilew', 'findclose',
        'getfiletype', 'getfilesizeex', 'setfilepointerex',
        'setendoffile', 'flushfilebuffers',
        'localalloc', 'localfree',
        'setconsolemode', 'readconsoleinputw',
    }
    
    def __init__(self, uc, emu):
        self.uc = uc
        self.emu = emu
        self.passthrough_enabled = PASSTHROUGH_AVAILABLE
        
    def get_mode(self, func_name):
        """Определяет режим для функции"""
        func_lower = func_name.lower()
        
        if func_lower in self.CRITICAL_EMULATED:
            return 'EMULATED'
        elif func_lower in self.PASSTHROUGH_SAFE and self.passthrough_enabled:
            return 'PASSTHROUGH'
        else:
            return 'STUB'
    
    def call_passthrough(self, func_name, *args):
        """Вызывает реальную системную функцию"""
        if not self.passthrough_enabled:
            return None
        
        try:
            # Определяем DLL
            if func_name.lower().startswith(('reg', 'lookup', 'adjust', 'open')):
                dll = advapi32
            elif func_name.lower().startswith(('send', 'dialog', 'load', 'set', 'get')) and 'console' not in func_name.lower():
                dll = user32
            else:
                dll = kernel32
            
            # Получаем функцию
            func = getattr(dll, func_name, None)
            if func is None:
                return None
            
            # Вызываем
            result = func(*args)
            return result
            
        except Exception as e:
            print(f"[!] Passthrough failed for {func_name}: {e}")
            return None
    
    def read_string_from_memory(self, address, unicode=True):
        """Читает строку из памяти эмулятора"""
        if address == 0:
            return ""
        
        try:
            if unicode:
                # Unicode (UTF-16LE)
                chars = []
                offset = 0
                while True:
                    char_bytes = self.uc.mem_read(address + offset, 2)
                    char_val = int.from_bytes(char_bytes, 'little')
                    if char_val == 0:
                        break
                    chars.append(chr(char_val))
                    offset += 2
                    if offset > 1000:  # Safety limit
                        break
                return ''.join(chars)
            else:
                # ANSI
                chars = []
                offset = 0
                while True:
                    char_byte = self.uc.mem_read(address + offset, 1)[0]
                    if char_byte == 0:
                        break
                    chars.append(chr(char_byte))
                    offset += 1
                    if offset > 1000:  # Safety limit
                        break
                return ''.join(chars)
        except:
            return "<invalid>"


# Пример использования passthrough для WriteConsoleW
def passthrough_writeconsolew(hybrid, uc):
    """Пример: WriteConsoleW с passthrough"""
    hConsoleOutput = uc.reg_read(UC_X86_REG_RCX)
    lpBuffer = uc.reg_read(UC_X86_REG_RDX)
    nNumberOfCharsToWrite = uc.reg_read(UC_X86_REG_R8)
    lpNumberOfCharsWritten = uc.reg_read(UC_X86_REG_R9)
    
    # Читаем строку из памяти эмулятора
    text = hybrid.read_string_from_memory(lpBuffer, unicode=True)
    
    if hybrid.passthrough_enabled:
        # Вызываем реальную WriteConsoleW
        written = wintypes.DWORD()
        result = kernel32.WriteConsoleW(
            hConsoleOutput,
            text,
            nNumberOfCharsToWrite,
            ctypes.byref(written),
            None
        )
        
        # Записываем результат обратно в память эмулятора
        if lpNumberOfCharsWritten:
            uc.mem_write(lpNumberOfCharsWritten, written.value.to_bytes(4, 'little'))
        
        uc.reg_write(UC_X86_REG_RAX, result)
        return result
    else:
        # Fallback: просто печатаем
        print(f"[CONSOLE] {text}", end='')
        if lpNumberOfCharsWritten:
            uc.mem_write(lpNumberOfCharsWritten, nNumberOfCharsToWrite.to_bytes(4, 'little'))
        uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
