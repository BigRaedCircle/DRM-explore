import mmap
import sys

def detect_denuvo_fast(filepath, max_scan_mb=64):
    """Быстрый поиск сигнатуры Denuvo без полной загрузки файла"""
    try:
        with open(filepath, 'rb') as f:
            # Открываем файл как memory-mapped (не загружая в память)
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # Ищем только в первых N МБ (сигнатуры обычно в начале)
                search_limit = min(mm.size(), max_scan_mb * 1024 * 1024)
                chunk = mm[:search_limit]
                
                if b'denuvo' in chunk.lower():
                    pos = chunk.lower().find(b'denuvo')
                    context = chunk[max(0, pos-20):pos+30]
                    return True, f"Найдено на позиции {pos}: {context}"
                return False, "Сигнатура не найдена в первых {} МБ".format(max_scan_mb)
    except Exception as e:
        return None, f"Ошибка: {e}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python detect.py <путь_к_файлу>")
        sys.exit(1)
    
    result, msg = detect_denuvo_fast(sys.argv[1])
    print(msg)
    sys.exit(0 if result else 1)
