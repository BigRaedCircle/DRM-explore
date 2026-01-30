#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Header Parser - парсинг Windows SDK заголовков для генерации заглушек

Извлекает сигнатуры функций из .h файлов и генерирует:
1. Python stubs для эмулятора
2. Документацию по API
3. Статистику покрытия
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class FunctionSignature:
    """Сигнатура функции из заголовочного файла"""
    name: str
    return_type: str
    parameters: List[Tuple[str, str]]  # [(type, name), ...]
    dll_name: str
    header_file: str
    calling_convention: str = "WINAPI"  # __stdcall, WINAPI, etc.
    is_implemented: bool = False
    
    def to_dict(self):
        return asdict(self)


class HeaderParser:
    """Парсер Windows SDK заголовочных файлов"""
    
    # Регулярные выражения для парсинга
    FUNCTION_PATTERN = re.compile(
        r'(?:WINBASEAPI|WINUSERAPI|WINADVAPI|WINSOCK_API_LINKAGE|__declspec\(dllimport\))\s+'  # API декларация
        r'(\w+(?:\s+\w+)*?)\s+'  # Возвращаемый тип
        r'(WINAPI|APIENTRY|CALLBACK|__stdcall|__cdecl)\s+'  # Calling convention
        r'(\w+)\s*'  # Имя функции
        r'\((.*?)\);',  # Параметры
        re.MULTILINE | re.DOTALL
    )
    
    # DLL mapping по заголовочным файлам
    HEADER_TO_DLL = {
        'fileapi.h': 'kernel32.dll',
        'processthreadsapi.h': 'kernel32.dll',
        'memoryapi.h': 'kernel32.dll',
        'synchapi.h': 'kernel32.dll',
        'winbase.h': 'kernel32.dll',
        'winuser.h': 'user32.dll',
        'winreg.h': 'advapi32.dll',
        'winsock2.h': 'ws2_32.dll',
        'wingdi.h': 'gdi32.dll',
    }
    
    def __init__(self):
        self.functions: Dict[str, FunctionSignature] = {}
        
    def parse_file(self, header_path: Path) -> List[FunctionSignature]:
        """Парсит один заголовочный файл"""
        print(f"[*] Parsing {header_path.name}...")
        
        try:
            content = header_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            print(f"[!] Error reading {header_path}: {e}")
            return []
        
        # Удаляем комментарии
        content = self._remove_comments(content)
        
        # Ищем функции
        functions = []
        dll_name = self.HEADER_TO_DLL.get(header_path.name, 'unknown.dll')
        
        for match in self.FUNCTION_PATTERN.finditer(content):
            return_type = match.group(1).strip()
            calling_conv = match.group(2).strip()
            func_name = match.group(3).strip()
            params_str = match.group(4).strip()
            
            # Парсим параметры
            parameters = self._parse_parameters(params_str)
            
            func = FunctionSignature(
                name=func_name,
                return_type=return_type,
                parameters=parameters,
                dll_name=dll_name,
                header_file=header_path.name,
                calling_convention=calling_conv
            )
            
            functions.append(func)
            self.functions[func_name] = func
        
        print(f"    Found {len(functions)} functions")
        return functions
    
    def _remove_comments(self, content: str) -> str:
        """Удаляет C/C++ комментарии"""
        # Удаляем /* */ комментарии
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # Удаляем // комментарии
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        return content
    
    def _parse_parameters(self, params_str: str) -> List[Tuple[str, str]]:
        """Парсит строку параметров"""
        if not params_str or params_str == 'void':
            return []
        
        parameters = []
        # Разбиваем по запятым (с учётом вложенных скобок)
        params = self._split_parameters(params_str)
        
        for param in params:
            param = param.strip()
            if not param:
                continue
            
            # Разделяем тип и имя
            # Примеры: "HANDLE hFile", "LPCWSTR lpFileName", "DWORD *lpNumberOfBytesRead"
            parts = param.rsplit(None, 1)
            if len(parts) == 2:
                param_type, param_name = parts
                # Убираем * из имени и добавляем к типу
                if param_name.startswith('*'):
                    param_type += '*'
                    param_name = param_name[1:]
                # Убираем [] из имени (массивы)
                param_name = param_name.replace('[', '').replace(']', '')
                parameters.append((param_type.strip(), param_name.strip()))
            elif len(parts) == 1:
                # Только тип (например, "void")
                parameters.append((parts[0].strip(), ''))
        
        return parameters
    
    def _split_parameters(self, params_str: str) -> List[str]:
        """Разбивает параметры по запятым с учётом вложенных скобок"""
        params = []
        current = []
        depth = 0
        
        for char in params_str:
            if char == ',' and depth == 0:
                params.append(''.join(current))
                current = []
            else:
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                current.append(char)
        
        if current:
            params.append(''.join(current))
        
        return params
    
    def parse_directory(self, headers_dir: Path, patterns: List[str] = None) -> Dict[str, List[FunctionSignature]]:
        """Парсит все заголовочные файлы в директории"""
        if patterns is None:
            patterns = ['*.h']
        
        results = {}
        
        for pattern in patterns:
            for header_file in headers_dir.glob(pattern):
                functions = self.parse_file(header_file)
                if functions:
                    results[header_file.name] = functions
        
        return results
    
    def generate_python_stubs(self, output_file: Path):
        """Генерирует Python заглушки для эмулятора"""
        print(f"\n[*] Generating Python stubs: {output_file}")
        
        # Группируем по DLL
        by_dll = {}
        for func in self.functions.values():
            if func.dll_name not in by_dll:
                by_dll[func.dll_name] = []
            by_dll[func.dll_name].append(func)
        
        # Генерируем код
        code = []
        code.append('#!/usr/bin/env python3')
        code.append('# -*- coding: utf-8 -*-')
        code.append('"""')
        code.append('Auto-generated WinAPI stubs from Windows SDK headers')
        code.append('DO NOT EDIT MANUALLY - regenerate using tools/header_parser.py')
        code.append('"""')
        code.append('')
        code.append('from unicorn.x86_const import *')
        code.append('')
        code.append('')
        
        for dll_name in sorted(by_dll.keys()):
            functions = by_dll[dll_name]
            code.append(f'# ===== {dll_name} ({len(functions)} functions) =====')
            code.append('')
            
            for func in sorted(functions, key=lambda f: f.name):
                code.append(f'def _stub_{func.name.lower()}(self):')
                code.append(f'    """{func.name}() - {func.return_type} {func.calling_convention}')
                
                if func.parameters:
                    code.append('    Parameters:')
                    for param_type, param_name in func.parameters:
                        code.append(f'        {param_type} {param_name}')
                
                code.append(f'    Source: {func.header_file}')
                code.append('    """')
                
                # Генерируем чтение параметров
                if func.parameters:
                    regs = ['UC_X86_REG_RCX', 'UC_X86_REG_RDX', 'UC_X86_REG_R8', 'UC_X86_REG_R9']
                    for i, (param_type, param_name) in enumerate(func.parameters[:4]):
                        if param_name:
                            code.append(f'    {param_name} = self.uc.reg_read({regs[i]})')
                
                code.append(f'    print(f"[API] {func.name}()")')
                code.append('    ')
                code.append('    # TODO: Implement stub logic')
                code.append('    ')
                
                # Возвращаемое значение
                if func.return_type != 'void':
                    code.append('    self.uc.reg_write(UC_X86_REG_RAX, 0)  # TODO: Return proper value')
                
                code.append('    return 0')
                code.append('')
        
        output_file.write_text('\n'.join(code), encoding='utf-8')
        print(f"[+] Generated {len(self.functions)} function stubs")
    
    def generate_documentation(self, output_file: Path):
        """Генерирует документацию по API"""
        print(f"\n[*] Generating documentation: {output_file}")
        
        # Группируем по DLL
        by_dll = {}
        for func in self.functions.values():
            if func.dll_name not in by_dll:
                by_dll[func.dll_name] = []
            by_dll[func.dll_name].append(func)
        
        doc = []
        doc.append('# Windows API Functions Reference')
        doc.append('')
        doc.append('Auto-generated from Windows SDK headers')
        doc.append('')
        doc.append('## Summary')
        doc.append('')
        doc.append(f'Total functions: **{len(self.functions)}**')
        doc.append('')
        
        for dll_name in sorted(by_dll.keys()):
            functions = by_dll[dll_name]
            doc.append(f'- **{dll_name}**: {len(functions)} functions')
        
        doc.append('')
        doc.append('## Functions by DLL')
        doc.append('')
        
        for dll_name in sorted(by_dll.keys()):
            functions = by_dll[dll_name]
            doc.append(f'### {dll_name} ({len(functions)} functions)')
            doc.append('')
            doc.append('| Function | Return Type | Parameters | Source |')
            doc.append('|----------|-------------|------------|--------|')
            
            for func in sorted(functions, key=lambda f: f.name):
                params = ', '.join([f'{t} {n}' for t, n in func.parameters]) if func.parameters else 'void'
                if len(params) > 50:
                    params = params[:47] + '...'
                doc.append(f'| `{func.name}` | {func.return_type} | {params} | {func.header_file} |')
            
            doc.append('')
        
        output_file.write_text('\n'.join(doc), encoding='utf-8')
        print(f"[+] Generated documentation")
    
    def save_json(self, output_file: Path):
        """Сохраняет результаты в JSON"""
        print(f"\n[*] Saving JSON: {output_file}")
        
        data = {
            'total_functions': len(self.functions),
            'functions': [func.to_dict() for func in self.functions.values()]
        }
        
        output_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
        print(f"[+] Saved {len(self.functions)} functions to JSON")


def main():
    """Основная функция"""
    print("=" * 70)
    print("Windows SDK Header Parser")
    print("=" * 70)
    print()
    
    # Создаём директории
    output_dir = Path('tools/generated')
    output_dir.mkdir(exist_ok=True, parents=True)
    
    headers_dir = Path('tools/headers')
    
    if not headers_dir.exists():
        print("[!] Headers directory not found!")
        print("    Run: python tools/download_headers.py")
        return
    
    # Парсим заголовки
    parser = HeaderParser()
    
    # Список заголовков для парсинга
    headers_to_parse = [
        'fileapi.h',
        'processthreadsapi.h',
        'memoryapi.h',
        'synchapi.h',
        'heapapi.h',
        'libloaderapi.h',
        'errhandlingapi.h',
        'profileapi.h',
        'sysinfoapi.h',
        # 'winbase.h',  # Слишком большой, пропускаем
        # 'winuser.h',  # Слишком большой, пропускаем
        'winreg.h',
        # 'winsock2.h', # Слишком большой, пропускаем
        'wingdi.h',
    ]
    
    print(f"[*] Parsing {len(headers_to_parse)} header files...")
    print()
    
    for header_name in headers_to_parse:
        header_path = headers_dir / header_name
        if header_path.exists():
            parser.parse_file(header_path)
        else:
            print(f"[!] {header_name} not found, skipping")
    
    print()
    print(f"[+] Total functions parsed: {len(parser.functions)}")
    print()
    
    # Генерируем выходные файлы
    parser.generate_python_stubs(output_dir / 'winapi_stubs_generated.py')
    parser.generate_documentation(output_dir / 'API_REFERENCE.md')
    parser.save_json(output_dir / 'functions.json')
    
    print()
    print("=" * 70)
    print("[+] Done! Generated files:")
    print(f"    - {output_dir / 'winapi_stubs_generated.py'}")
    print(f"    - {output_dir / 'API_REFERENCE.md'}")
    print(f"    - {output_dir / 'functions.json'}")
    print("=" * 70)


if __name__ == '__main__':
    main()
