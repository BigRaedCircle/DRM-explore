import pefile

def detect_denuvo(filepath):
    try:
        pe = pefile.PE(filepath)
        # Проверка секций
        denuvo_signatures = ['.vm', '.denuvo', 'denuvo']
        for section in pe.sections:
            name = section.Name.decode().strip('\x00').lower()
            if any(sig in name for sig in denuvo_signatures):
                return True, f"Найдена секция: {name}"
        
        # Проверка строк в ресурсах/секциях
        for section in pe.sections:
            data = section.get_data()
            if b'denuvo' in data.lower():
                return True, "Найдена сигнатура в данных секции"
                
        return False, "Denuvo не обнаружен"
    except Exception as e:
        return None, f"Ошибка: {e}"

# Пример использования
result, msg = detect_denuvo("Outlaws.exe")
print(msg)
