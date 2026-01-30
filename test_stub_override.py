#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест системы переопределения заглушек

Проверяет работу StubRegistry и интеграцию с автогенерированными заглушками
"""

import sys
sys.path.insert(0, 'src/core')
sys.path.insert(0, 'tools')

from winapi_stubs_v2 import WinAPIStubsV2, StubRegistry


def test_stub_registry():
    """Тест базовой функциональности StubRegistry"""
    print("=" * 70)
    print("TEST 1: StubRegistry Basic Functionality")
    print("=" * 70)
    
    registry = StubRegistry()
    
    # Регистрируем автогенерированную заглушку
    def generated_func():
        return "GENERATED"
    
    registry.register_generated('testfunc', generated_func)
    
    # Регистрируем пользовательскую реализацию
    def custom_func():
        return "CUSTOM"
    
    registry.register_custom('testfunc', custom_func)
    
    # Проверяем приоритет (custom должен быть выше)
    result = registry.get('testfunc')()
    assert result == "CUSTOM", f"Expected CUSTOM, got {result}"
    print(f"✅ Priority test passed: {result}")
    
    # Проверяем has_custom
    assert registry.has_custom('testfunc'), "has_custom should return True"
    print(f"✅ has_custom test passed")
    
    # Проверяем функцию без custom
    registry.register_generated('anotherfunc', lambda: "ONLY_GENERATED")
    result2 = registry.get('anotherfunc')()
    assert result2 == "ONLY_GENERATED", f"Expected ONLY_GENERATED, got {result2}"
    print(f"✅ Generated-only test passed: {result2}")
    
    print()


def test_generated_stubs_loading():
    """Тест загрузки автогенерированных заглушек"""
    print("=" * 70)
    print("TEST 2: Loading Generated Stubs")
    print("=" * 70)
    
    try:
        from generated import winapi_stubs_generated
        
        # Подсчитываем количество заглушек
        stub_count = sum(1 for name in dir(winapi_stubs_generated) if name.startswith('_stub_'))
        print(f"✅ Found {stub_count} generated stubs")
        
        # Проверяем несколько известных функций
        expected_stubs = ['_stub_createfilea', '_stub_readfile', '_stub_writefile']
        for stub_name in expected_stubs:
            assert hasattr(winapi_stubs_generated, stub_name), f"Missing {stub_name}"
            print(f"✅ Found {stub_name}")
        
        print()
        return True
        
    except ImportError as e:
        print(f"❌ Failed to load generated stubs: {e}")
        print(f"   Run: python tools/header_parser.py")
        print()
        return False


def test_winapi_stubs_v2_mock():
    """Тест WinAPIStubsV2 с мок-эмулятором"""
    print("=" * 70)
    print("TEST 3: WinAPIStubsV2 Integration (Mock)")
    print("=" * 70)
    
    # Создаём минимальный мок-эмулятор
    class MockUnicorn:
        def reg_read(self, reg):
            return 0x1000
        
        def reg_write(self, reg, value):
            pass
        
        def mem_read(self, addr, size):
            return b'test.txt\x00' + b'\x00' * (size - 9)
        
        def mem_write(self, addr, data):
            pass
    
    class MockClock:
        def get_tick_count(self):
            return 12345
        
        def query_performance_counter(self):
            return 9876543210
        
        def query_performance_frequency(self):
            return 3000000000
    
    class MockEmulator:
        def __init__(self):
            self.uc = MockUnicorn()
            self.clock = MockClock()
    
    # Создаём WinAPIStubsV2
    try:
        mock_emu = MockEmulator()
        stubs = WinAPIStubsV2(mock_emu)
        
        # Проверяем статистику
        stats = stubs.get_stats()
        print(f"✅ Total stubs: {stats['total']}")
        print(f"✅ Custom implementations: {stats['custom']}")
        print(f"✅ Generated stubs: {stats['generated']}")
        print(f"✅ Custom percentage: {stats['custom_percentage']:.1f}%")
        
        # Проверяем, что custom функции зарегистрированы
        assert stats['custom'] > 0, "No custom implementations found"
        assert stats['generated'] > 0, "No generated stubs found"
        
        # Проверяем вызов custom функции
        print(f"\n--- Testing custom stub call ---")
        result = stubs.call_stub('gettickcount')
        print(f"✅ GetTickCount returned: {result}")
        
        print()
        return True
        
    except Exception as e:
        print(f"❌ Failed to initialize WinAPIStubsV2: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_override_pattern():
    """Тест паттерна переопределения"""
    print("=" * 70)
    print("TEST 4: Override Pattern")
    print("=" * 70)
    
    registry = StubRegistry()
    
    # Симулируем автогенерированную заглушку
    def generated_createfile():
        return 0  # Fake handle
    
    registry.register_generated('createfilea', generated_createfile)
    
    # Проверяем, что используется generated
    result1 = registry.get('createfilea')()
    print(f"✅ Before override: {result1} (generated)")
    
    # Переопределяем custom реализацией
    def custom_createfile():
        return 0x1234  # Real VFS handle
    
    registry.register_custom('createfilea', custom_createfile)
    
    # Проверяем, что теперь используется custom
    result2 = registry.get('createfilea')()
    print(f"✅ After override: {result2} (custom)")
    
    assert result1 != result2, "Override didn't work"
    assert result2 == 0x1234, f"Expected 0x1234, got {result2}"
    
    print()


def main():
    """Запуск всех тестов"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "STUB OVERRIDE SYSTEM TESTS" + " " * 27 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    results = []
    
    # Тест 1: Базовая функциональность StubRegistry
    try:
        test_stub_registry()
        results.append(("StubRegistry Basic", True))
    except Exception as e:
        print(f"❌ Test failed: {e}")
        results.append(("StubRegistry Basic", False))
    
    # Тест 2: Загрузка автогенерированных заглушек
    try:
        success = test_generated_stubs_loading()
        results.append(("Generated Stubs Loading", success))
    except Exception as e:
        print(f"❌ Test failed: {e}")
        results.append(("Generated Stubs Loading", False))
    
    # Тест 3: Интеграция WinAPIStubsV2
    try:
        success = test_winapi_stubs_v2_mock()
        results.append(("WinAPIStubsV2 Integration", success))
    except Exception as e:
        print(f"❌ Test failed: {e}")
        results.append(("WinAPIStubsV2 Integration", False))
    
    # Тест 4: Паттерн переопределения
    try:
        test_override_pattern()
        results.append(("Override Pattern", True))
    except Exception as e:
        print(f"❌ Test failed: {e}")
        results.append(("Override Pattern", False))
    
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
        print("🎉 All tests passed! System is ready to use.")
    else:
        print("⚠️  Some tests failed. Check the output above.")
    
    print()


if __name__ == '__main__':
    main()
