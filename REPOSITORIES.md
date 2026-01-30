# Репозитории проекта

## Активный репозиторий (текущий)

**BigRaedCircle/DRM-explore**
- URL: https://github.com/BigRaedCircle/DRM-explore
- Статус: ✅ Активный, все коммиты идут сюда
- Remote: `origin`
- Доступ: Полный (push/pull)

```bash
# Текущий remote
git remote -v
# origin  https://github.com/BigRaedCircle/DRM-explore.git

# Push в активный репозиторий
git push origin master
```

## Альтернативный репозиторий (старый)

**iackov/layered-emulation**
- URL: https://github.com/iackov/layered-emulation
- Статус: ⚠️ Устаревший, не синхронизирован
- Remote: `layered` (добавлен, но нет прав)
- Доступ: Только чтение (403 на push)

```bash
# Добавлен как remote, но push не работает
git remote add layered https://github.com/iackov/layered-emulation.git
git push layered master  # ❌ Permission denied
```

## Рекомендация

**Используй BigRaedCircle/DRM-explore** для всех операций:
- ✅ Все последние изменения здесь
- ✅ Полный доступ
- ✅ Актуальная версия кода

Если нужна синхронизация с iackov/layered-emulation:
1. Дай права доступа для BigRaedCircle
2. Или синхронизируй вручную через веб-интерфейс GitHub

---

**Последнее обновление:** 2026-01-30  
**Текущий коммит:** 6d1fb9b (Auto-generation system for WinAPI/DirectX stubs)
