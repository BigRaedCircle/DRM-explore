#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DirectX Header Parser - парсинг DirectX SDK заголовков

Извлекает COM интерфейсы и функции из DirectX заголовков
Генерирует Python заглушки для эмулятора
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class DirectXFunction:
    """Функция DirectX (не метод интерфейса)"""
    name: str
    return_type: str
    parameters: List[Tuple[str, str]]
    dll_name: str
    header_file: str
    
    def to_dict(self):
        return asdict(self)


@dataclass
class COMMethod:
    """Метод COM интерфейса"""
    name: str
    return_type: str
    parameters: List[Tuple[str, str]]
    calling_convention: str = "STDMETHODCALLTYPE"
    
    def to_dict(self):
        return asdict(self)


@dataclass
class COMInterface:
    """COM интерфейс DirectX"""
    name: str
    parent: str  # Родительский интерфейс (обычно IUnknown)
    methods: List[COMMethod]
    dll_name: str
    header_file: str
    
    def to_dict(self):
        return {
            'name': self.name,
            'parent': self.parent,
            'methods': [m.to_dict() for m in self.methods],
            'dll_name': self.dll_name,
            'header_file': self.header_file,
        }


class DirectXParser:
    """Парсер DirectX заголовочных файлов"""
    
    # Регулярные выражения
    
    # Функции создания (Direct3DCreate9, D3D11CreateDevice, etc.)
    CREATION_FUNCTION_PATTERN = re.compile(
        r'(?:WINAPI|__stdcall)\s+'
        r'(\w+)\s*\('  # Имя функции
        r'([^)]*)\);',  # Параметры
        re.MULTILINE
    )
    
    # COM интерфейсы
    INTERFACE_PATTERN = re.compile(
        r'(?:DECLARE_INTERFACE_|interface)\s*'
        r'(?:\((\w+)\))?\s*'  # Родительский интерфейс (опционально)
        r'(\w+)\s*'  # Имя интерфейса
        r'\{(.*?)\};',  # Тело интерфейса
        re.MULTILINE | re.DOTALL
    )
    
    # Методы в интерфейсе
    METHOD_PATTERN = re.compile(
        r'(STDMETHOD|STDMETHOD_)\s*'
        r'(?:\((\w+)\))?\s*'  # Возвращаемый тип (для STDMETHOD_)
        r'(\w+)\s*'  # Имя метода
        r'\((.*?)\)',  # Параметры
        re.MULTILINE | re.DOTALL
    )
    
    # Mapping заголовков к DLL
    HEADER_TO_DLL = {
        'd3d9.h': 'd3d9.dll',
        'd3d11.h': 'd3d11.dll',
        'd3d11_1.h': 'd3d11.dll',
        'd3d11_2.h': 'd3d11.dll',
        'd3d11_3.h': 'd3d11.dll',
        'd3d11_4.h': 'd3d11.dll',
        'd3d12.h': 'd3d12.dll',
        'dxgi.h': 'dxgi.dll',
        'dxgi1_2.h': 'dxgi.dll',
        'dxgi1_3.h': 'dxgi.dll',
        'dxgi1_4.h': 'dxgi.dll',
        'dxgi1_5.h': 'dxgi.dll',
        'dxgi1_6.h': 'dxgi.dll',
    }
    
    def __init__(self):
        self.functions: Dict[str, DirectXFunction] = {}
        self.interfaces: Dict[str, COMInterface] = {}
        
    def parse_file(self, header_path: Path) -> Tuple[List[DirectXFunction], List[COMInterface]]:
        """Парсит один заголовочный файл"""
        print(f"[*] Parsing {header_path.name}...")
        
        try:
            content = header_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            print(f"[!] Error reading {header_path}: {e}")
            return [], []
        
        # Удаляем комментарии
        content = self._remove_comments(content)
        
        dll_name = self.HEADER_TO_DLL.get(header_path.name, 'unknown.dll')
        
        # Парсим функции создания
        functions = self._parse_creation_functions(content, dll_name, header_path.name)
        
        # Парсим COM интерфейсы
        interfaces = self._parse_interfaces(content, dll_name, header_path.name)
        
        print(f"    Found {len(functions)} functions, {len(interfaces)} interfaces")
        
        return functions, interfaces
    
    def _remove_comments(self, content: str) -> str:
        """Удаляет C/C++ комментарии"""
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        return content
    
    def _parse_creation_functions(self, content: str, dll_name: str, header_file: str) -> List[DirectXFunction]:
        """Парсит функции создания DirectX объектов"""
        functions = []
        
        # Ищем известные функции создания
        creation_funcs = [
            'Direct3DCreate9',
            'D3D11CreateDevice',
            'D3D11CreateDeviceAndSwapChain',
            'D3D12CreateDevice',
            'CreateDXGIFactory',
            'CreateDXGIFactory1',
            'CreateDXGIFactory2',
        ]
        
        for func_name in creation_funcs:
            # Ищем объявление функции
            pattern = rf'{func_name}\s*\((.*?)\);'
            match = re.search(pattern, content, re.DOTALL)
            
            if match:
                params_str = match.group(1)
                parameters = self._parse_parameters(params_str)
                
                func = DirectXFunction(
                    name=func_name,
                    return_type='HRESULT' if 'Create' in func_name and func_name != 'Direct3DCreate9' else 'IDirect3D9*',
                    parameters=parameters,
                    dll_name=dll_name,
                    header_file=header_file
                )
                
                functions.append(func)
                self.functions[func_name] = func
        
        return functions
    
    def _parse_interfaces(self, content: str, dll_name: str, header_file: str) -> List[COMInterface]:
        """Парсит COM интерфейсы"""
        interfaces = []
        
        # Упрощённый парсинг - ищем typedef struct с Vtbl
        vtbl_pattern = re.compile(
            r'typedef\s+struct\s+(\w+)Vtbl\s*\{(.*?)\}\s*\1Vtbl;',
            re.MULTILINE | re.DOTALL
        )
        
        for match in vtbl_pattern.finditer(content):
            interface_name = match.group(1)
            vtbl_body = match.group(2)
            
            # Парсим методы из Vtbl
            methods = self._parse_vtbl_methods(vtbl_body)
            
            if methods:
                interface = COMInterface(
                    name=interface_name,
                    parent='IUnknown',  # По умолчанию
                    methods=methods,
                    dll_name=dll_name,
                    header_file=header_file
                )
                
                interfaces.append(interface)
                self.interfaces[interface_name] = interface
        
        return interfaces
    
    def _parse_vtbl_methods(self, vtbl_body: str) -> List[COMMethod]:
        """Парсит методы из Vtbl структуры"""
        methods = []
        
        # Ищем указатели на функции
        method_pattern = re.compile(
            r'(\w+)\s*'  # Возвращаемый тип
            r'\(STDMETHODCALLTYPE\s*\*(\w+)\)'  # Имя метода
            r'\s*\((.*?)\);',  # Параметры
            re.MULTILINE | re.DOTALL
        )
        
        for match in method_pattern.finditer(vtbl_body):
            return_type = match.group(1).strip()
            method_name = match.group(2).strip()
            params_str = match.group(3).strip()
            
            # Парсим параметры
            parameters = self._parse_parameters(params_str)
            
            method = COMMethod(
                name=method_name,
                return_type=return_type,
                parameters=parameters
            )
            
            methods.append(method)
        
        return methods
    
    def _parse_parameters(self, params_str: str) -> List[Tuple[str, str]]:
        """Парсит строку параметров"""
        if not params_str or params_str.strip() in ['void', 'VOID']:
            return []
        
        parameters = []
        
        # Разбиваем по запятым
        params = self._split_parameters(params_str)
        
        for param in params:
            param = param.strip()
            if not param:
                continue
            
            # Убираем аннотации (_In_, _Out_, etc.)
            param = re.sub(r'_(?:In|Out|Inout|Opt)_(?:opt_)?', '', param)
            param = param.strip()
            
            # Разделяем тип и имя
            parts = param.rsplit(None, 1)
            if len(parts) == 2:
                param_type, param_name = parts
                # Убираем * из имени и добавляем к типу
                while param_name.startswith('*'):
                    param_type += '*'
                    param_name = param_name[1:]
                # Убираем [] из имени (массивы)
                param_name = param_name.replace('[', '').replace(']', '')
                parameters.append((param_type.strip(), param_name.strip()))
            elif len(parts) == 1:
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
    
    def generate_python_stubs(self, output_file: Path):
        """Генерирует Python заглушки для DirectX"""
        print(f"\n[*] Generating DirectX Python stubs: {output_file}")
        
        code = []
        code.append('#!/usr/bin/env python3')
        code.append('# -*- coding: utf-8 -*-')
        code.append('"""')
        code.append('Auto-generated DirectX stubs from DirectX SDK headers')
        code.append('DO NOT EDIT MANUALLY - regenerate using tools/directx_parser.py')
        code.append('"""')
        code.append('')
        code.append('from unicorn.x86_const import *')
        code.append('')
        code.append('')
        
        # Генерируем функции создания
        if self.functions:
            code.append('# ===== DirectX Creation Functions =====')
            code.append('')
            
            for func in sorted(self.functions.values(), key=lambda f: f.name):
                code.append(f'def _stub_{func.name.lower()}(self):')
                code.append(f'    """{func.name}() - {func.return_type}')
                
                if func.parameters:
                    code.append('    Parameters:')
                    for param_type, param_name in func.parameters:
                        code.append(f'        {param_type} {param_name}')
                
                code.append(f'    Source: {func.header_file} ({func.dll_name})')
                code.append('    """')
                
                # Генерируем чтение параметров
                if func.parameters:
                    regs = ['UC_X86_REG_RCX', 'UC_X86_REG_RDX', 'UC_X86_REG_R8', 'UC_X86_REG_R9']
                    for i, (param_type, param_name) in enumerate(func.parameters[:4]):
                        if param_name:
                            code.append(f'    {param_name} = self.uc.reg_read({regs[i]})')
                
                code.append(f'    print(f"[DirectX] {func.name}()")')
                code.append('    ')
                code.append('    # TODO: Implement DirectX stub logic')
                code.append('    # Return fake device/factory handle')
                code.append('    ')
                
                if 'HRESULT' in func.return_type:
                    code.append('    self.uc.reg_write(UC_X86_REG_RAX, 0)  # S_OK')
                else:
                    code.append('    self.uc.reg_write(UC_X86_REG_RAX, 0x12340000)  # Fake handle')
                
                code.append('    return 0')
                code.append('')
        
        # Генерируем COM интерфейсы
        if self.interfaces:
            code.append('')
            code.append('# ===== DirectX COM Interfaces =====')
            code.append('')
            
            for interface in sorted(self.interfaces.values(), key=lambda i: i.name):
                code.append(f'# {interface.name} ({len(interface.methods)} methods)')
                code.append(f'# Source: {interface.header_file} ({interface.dll_name})')
                code.append('')
                
                for method in interface.methods:
                    code.append(f'def _stub_{interface.name.lower()}_{method.name.lower()}(self):')
                    code.append(f'    """{interface.name}::{method.name}() - {method.return_type}')
                    
                    if method.parameters:
                        code.append('    Parameters:')
                        for param_type, param_name in method.parameters:
                            code.append(f'        {param_type} {param_name}')
                    
                    code.append('    """')
                    code.append(f'    print(f"[DirectX] {interface.name}::{method.name}()")')
                    code.append('    ')
                    code.append('    # TODO: Implement COM method stub')
                    code.append('    ')
                    
                    if 'HRESULT' in method.return_type or 'STDMETHOD' in method.return_type:
                        code.append('    self.uc.reg_write(UC_X86_REG_RAX, 0)  # S_OK')
                    elif 'ULONG' in method.return_type:
                        code.append('    self.uc.reg_write(UC_X86_REG_RAX, 1)  # Ref count')
                    else:
                        code.append('    self.uc.reg_write(UC_X86_REG_RAX, 0)')
                    
                    code.append('    return 0')
                    code.append('')
                
                code.append('')
        
        output_file.write_text('\n'.join(code), encoding='utf-8')
        print(f"[+] Generated {len(self.functions)} functions and {len(self.interfaces)} interfaces")
    
    def generate_documentation(self, output_file: Path):
        """Генерирует документацию по DirectX API"""
        print(f"\n[*] Generating DirectX documentation: {output_file}")
        
        doc = []
        doc.append('# DirectX API Reference')
        doc.append('')
        doc.append('Auto-generated from DirectX SDK headers')
        doc.append('')
        doc.append('## Summary')
        doc.append('')
        doc.append(f'- **Creation Functions**: {len(self.functions)}')
        doc.append(f'- **COM Interfaces**: {len(self.interfaces)}')
        
        total_methods = sum(len(i.methods) for i in self.interfaces.values())
        doc.append(f'- **Total Methods**: {total_methods}')
        doc.append('')
        
        # Функции создания
        if self.functions:
            doc.append('## Creation Functions')
            doc.append('')
            doc.append('| Function | Return Type | DLL | Source |')
            doc.append('|----------|-------------|-----|--------|')
            
            for func in sorted(self.functions.values(), key=lambda f: f.name):
                doc.append(f'| `{func.name}` | {func.return_type} | {func.dll_name} | {func.header_file} |')
            
            doc.append('')
        
        # COM интерфейсы
        if self.interfaces:
            doc.append('## COM Interfaces')
            doc.append('')
            
            for interface in sorted(self.interfaces.values(), key=lambda i: i.name):
                doc.append(f'### {interface.name} ({len(interface.methods)} methods)')
                doc.append('')
                doc.append(f'**Source**: {interface.header_file} ({interface.dll_name})')
                doc.append('')
                doc.append('| Method | Return Type | Parameters |')
                doc.append('|--------|-------------|------------|')
                
                for method in interface.methods:
                    params = ', '.join([f'{t} {n}' for t, n in method.parameters]) if method.parameters else 'void'
                    if len(params) > 50:
                        params = params[:47] + '...'
                    doc.append(f'| `{method.name}` | {method.return_type} | {params} |')
                
                doc.append('')
        
        output_file.write_text('\n'.join(doc), encoding='utf-8')
        print(f"[+] Generated documentation")
    
    def save_json(self, output_file: Path):
        """Сохраняет результаты в JSON"""
        print(f"\n[*] Saving JSON: {output_file}")
        
        data = {
            'functions': [func.to_dict() for func in self.functions.values()],
            'interfaces': [iface.to_dict() for iface in self.interfaces.values()],
            'total_functions': len(self.functions),
            'total_interfaces': len(self.interfaces),
            'total_methods': sum(len(i.methods) for i in self.interfaces.values()),
        }
        
        output_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
        print(f"[+] Saved to JSON")


def main():
    """Основная функция"""
    print("=" * 70)
    print("DirectX SDK Header Parser")
    print("=" * 70)
    print()
    
    # Создаём директории
    output_dir = Path('tools/generated')
    output_dir.mkdir(exist_ok=True, parents=True)
    
    headers_dir = Path('tools/directx_headers')
    
    if not headers_dir.exists():
        print("[!] DirectX headers directory not found!")
        print("    Run: python tools/download_directx_headers.py")
        return
    
    # Парсим заголовки
    parser = DirectXParser()
    
    # Список заголовков для парсинга
    headers_to_parse = [
        'd3d9.h',
        'd3d11.h',
        'd3d12.h',
        'dxgi.h',
    ]
    
    print(f"[*] Parsing {len(headers_to_parse)} DirectX header files...")
    print()
    
    for header_name in headers_to_parse:
        header_path = headers_dir / header_name
        if header_path.exists():
            functions, interfaces = parser.parse_file(header_path)
        else:
            print(f"[!] {header_name} not found, skipping")
    
    print()
    print(f"[+] Total functions: {len(parser.functions)}")
    print(f"[+] Total interfaces: {len(parser.interfaces)}")
    total_methods = sum(len(i.methods) for i in parser.interfaces.values())
    print(f"[+] Total methods: {total_methods}")
    print()
    
    # Генерируем выходные файлы
    parser.generate_python_stubs(output_dir / 'directx_stubs_generated.py')
    parser.generate_documentation(output_dir / 'DIRECTX_API_REFERENCE.md')
    parser.save_json(output_dir / 'directx_functions.json')
    
    print()
    print("=" * 70)
    print("[+] Done! Generated files:")
    print(f"    - {output_dir / 'directx_stubs_generated.py'}")
    print(f"    - {output_dir / 'DIRECTX_API_REFERENCE.md'}")
    print(f"    - {output_dir / 'directx_functions.json'}")
    print("=" * 70)


if __name__ == '__main__':
    main()
