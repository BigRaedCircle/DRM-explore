#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Denuvo Advanced Detector - расширенная эвристика и детекция
"""

import pefile
import sys
import hashlib
from collections import Counter

class DenuvoDetector:
    """Продвинутый детектор Denuvo с множественными эвристиками"""
    
    # Известные сигнатуры
    SIGNATURES = [
        b'denuvo', b'Denuvo', b'DENUVO',
        b'anti_tamper', b'antitamper', b'anti-tamper',
        b'denuvo_atd', b'denuvo_init',
        b'vmprotect', b'VMProtect',
        b'secureregion', b'secure_region'
    ]
    
    # Подозрительные секции
    SUSPICIOUS_SECTIONS = ['.vm', '.denuvo', 'vmcode', '.ecode', 'denuvo']
    
    # Подозрительные API
    SUSPICIOUS_APIS = {
        'kernel32.dll': [
            'VirtualProtect', 'VirtualAlloc', 'VirtualQuery',
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'OutputDebugStringA', 'GetTickCount', 'QueryPerformanceCounter'
        ],
        'ntdll.dll': [
            'NtQueryInformationProcess', 'NtSetInformationThread',
            'RtlAdjustPrivilege', 'NtQuerySystemInformation'
        ]
    }
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.score = 0
        self.evidence = []
        
    def load(self):
        """Загрузка PE-файла"""
        try:
            self.pe = pefile.PE(self.filepath, fast_load=False)
            return True
        except Exception as e:
            print(f"[!] Ошибка загрузки: {e}")
            return False
    
    def check_sections(self):
        """Проверка секций на признаки Denuvo"""
        for section in self.pe.sections:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
            size = section.Misc_VirtualSize or section.SizeOfRawData
            
            # Проверка имени секции
            for marker in self.SUSPICIOUS_SECTIONS:
                if marker in name.lower():
                    self.score += 50
                    self.evidence.append(f"Секция {name} (явный признак)")
                    return True
            
            # Огромная секция с исполняемым кодом
            if 'X' in self._section_rights(section):
                if size > 100 * 1024 * 1024:  # >100 МБ
                    self.score += 30
                    self.evidence.append(f"Огромная исполняемая секция {name} ({size/1024/1024:.1f} МБ)")
            
            # Подозрительные права WX
            if 'W' in self._section_rights(section) and 'X' in self._section_rights(section):
                self.score += 20
                self.evidence.append(f"Секция {name} с правами WX")
        
        return False
    
    def check_signatures(self):
        """Поиск строковых сигнатур"""
        found = 0
        for section in self.pe.sections:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
            data = section.get_data()
            
            if not data:
                continue
            
            for sig in self.SIGNATURES:
                if sig.lower() in data.lower():
                    found += 1
                    self.score += 40
                    self.evidence.append(f"Сигнатура '{sig.decode()}' в {name}")
                    break  # Одна сигнатура на секцию достаточно
        
        return found > 0
    
    def check_entropy(self):
        """Анализ энтропии секций"""
        high_entropy_sections = 0
        
        for section in self.pe.sections:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
            data = section.get_data()
            
            if not data or len(data) < 1024:
                continue
            
            # Проверяем первые 4KB для скорости
            sample = data[:4096]
            entropy = self._calculate_entropy(sample)
            
            # Высокая энтропия в больших секциях
            if entropy > 7.5 and len(data) > 10 * 1024 * 1024:
                high_entropy_sections += 1
                self.score += 15
                self.evidence.append(f"Высокая энтропия {entropy:.2f} в {name}")
        
        return high_entropy_sections > 0
    
    def check_imports(self):
        """Анализ импортов"""
        suspicious_count = 0
        
        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                return False
            
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('ascii', errors='ignore').lower()
                
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    
                    api_name = imp.name.decode('ascii', errors='ignore')
                    
                    for suspicious_dll, apis in self.SUSPICIOUS_APIS.items():
                        if suspicious_dll in dll_name:
                            if any(api in api_name for api in apis):
                                suspicious_count += 1
            
            if suspicious_count >= 4:
                self.score += 10
                self.evidence.append(f"Подозрительные API ({suspicious_count} шт.)")
                return True
                
        except:
            pass
        
        return False
    
    def check_timestamp(self):
        """Проверка временной метки (некоторые версии Denuvo обнуляют)"""
        ts = self.pe.FILE_HEADER.TimeDateStamp
        if ts == 0:
            self.score += 5
            self.evidence.append("Обнуленная временная метка")
            return True
        return False
    
    def check_entry_point(self):
        """Проверка точки входа"""
        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # Точка входа в необычной секции
        for section in self.pe.sections:
            if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                name = section.Name.decode('ascii', errors='ignore').strip('\x00')
                if name not in ['.text', 'CODE', '.code']:
                    self.score += 10
                    self.evidence.append(f"Точка входа в необычной секции {name}")
                    return True
        
        return False
    
    def analyze(self):
        """Полный анализ файла"""
        if not self.load():
            return None
        
        print(f"[+] Анализ: {self.filepath}\n")
        
        # Запуск всех проверок
        checks = [
            ("Секции", self.check_sections),
            ("Сигнатуры", self.check_signatures),
            ("Энтропия", self.check_entropy),
            ("Импорты", self.check_imports),
            ("Временная метка", self.check_timestamp),
            ("Точка входа", self.check_entry_point)
        ]
        
        for name, check_func in checks:
            try:
                result = check_func()
                status = "✓" if result else "○"
                print(f"  [{status}] {name}")
            except Exception as e:
                print(f"  [!] {name}: ошибка ({e})")
        
        return self._get_verdict()
    
    def _get_verdict(self):
        """Вынесение вердикта на основе накопленных баллов"""
        print(f"\n[ОЦЕНКА] Баллов: {self.score}/100")
        
        if self.evidence:
            print(f"\n[ДОКАЗАТЕЛЬСТВА]")
            for i, ev in enumerate(self.evidence, 1):
                print(f"  {i}. {ev}")
        
        if self.score >= 50:
            verdict = "DENUVO ОБНАРУЖЕН"
            confidence = "высокая"
        elif self.score >= 30:
            verdict = "ВЕРОЯТНО DENUVO"
            confidence = "средняя"
        elif self.score >= 15:
            verdict = "ВОЗМОЖНО DENUVO"
            confidence = "низкая"
        else:
            verdict = "НЕ ОБНАРУЖЕН"
            confidence = "N/A"
        
        print(f"\n[ВЕРДИКТ] {verdict} (уверенность: {confidence})")
        return self.score >= 30  # Порог для положительного результата
    
    def _section_rights(self, section):
        """Получение прав доступа секции"""
        rights = []
        if section.Characteristics & 0x20000000: rights.append('X')
        if section.Characteristics & 0x40000000: rights.append('R')
        if section.Characteristics & 0x80000000: rights.append('W')
        return ''.join(rights)
    
    def _calculate_entropy(self, data):
        """Быстрый расчет энтропии"""
        if not data:
            return 0.0
        import math
        counter = Counter(data)
        length = len(data)
        entropy = 0
        for count in counter.values():
            p_x = count / length
            entropy += -p_x * math.log2(p_x)
        return entropy


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python denuvo-advanced.py <файл.exe>")
        sys.exit(1)
    
    detector = DenuvoDetector(sys.argv[1])
    result = detector.analyze()
    
    sys.exit(0 if result else 1)
