#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест DirectX заглушек

Проверяет, что DirectX заглушки генерируются без синтаксических ошибок
"""

import sys
sys.path.insert(0, 'tools')


def test_directx_import():
    """Тест импорта DirectX заглушек"""
    print("=" * 70)
    print("TEST: DirectX Stubs Import")
    print("=" * 70)
    
    try:
        from generated import directx_stubs_generated
        
        # Подсчитываем заглушки
        stub_count = sum(1 for name in dir(directx_stubs_generated) if name.startswith('_stub_'))
        print(f"✅ Found {stub_count} DirectX stubs")
        
        # Проверяем известные функции
        expected_stubs = [
            '_stub_direct3dcreate9',
            '_stub_d3d11createdevice',
            '_stub_d3d12createdevice',
            '_stub_createdxgifactory',
        ]
        
        for stub_name in expected_stubs:
            if hasattr(directx_stubs_generated, stub_name):
                print(f"✅ Found {stub_name}")
            else:
                print(f"⚠️  Missing {stub_name}")
        
        print()
        print(f"✅ DirectX stubs loaded successfully!")
        return True
        
    except SyntaxError as e:
        print(f"❌ Syntax error in DirectX stubs: {e}")
        return False
    except ImportError as e:
        print(f"❌ Failed to import DirectX stubs: {e}")
        print(f"   Run: python tools/directx_parser.py")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_directx_syntax():
    """Тест синтаксиса сгенерированного файла"""
    print("=" * 70)
    print("TEST: DirectX Stubs Syntax Check")
    print("=" * 70)
    
    import py_compile
    from pathlib import Path
    
    stub_file = Path('tools/generated/directx_stubs_generated.py')
    
    if not stub_file.exists():
        print(f"❌ File not found: {stub_file}")
        return False
    
    try:
        py_compile.compile(str(stub_file), doraise=True)
        print(f"✅ Syntax check passed: {stub_file.name}")
        return True
    except py_compile.PyCompileError as e:
        print(f"❌ Syntax error: {e}")
        return False


def main():
    """Запуск всех тестов"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 20 + "DIRECTX STUBS TESTS" + " " * 29 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    results = []
    
    # Тест 1: Синтаксис
    try:
        success = test_directx_syntax()
        results.append(("DirectX Syntax Check", success))
    except Exception as e:
        print(f"❌ Test failed: {e}")
        results.append(("DirectX Syntax Check", False))
    
    print()
    
    # Тест 2: Импорт
    try:
        success = test_directx_import()
        results.append(("DirectX Import", success))
    except Exception as e:
        print(f"❌ Test failed: {e}")
        results.append(("DirectX Import", False))
    
    # Итоговая статистика
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print()
    print(f"Total: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    print()
    
    if passed == total:
        print("🎉 All DirectX tests passed!")
    else:
        print("⚠️  Some tests failed. Check the output above.")
    
    print()


if __name__ == '__main__':
    main()
