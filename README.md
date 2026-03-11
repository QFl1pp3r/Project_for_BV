# Интелектуальный Аналайзер логов

Минимальный веб‑анализатор access‑логов (Nginx/Apache) с простыми детекторами:
Brute Force, SQLi, XSS, DoS и ML‑аномалии. Результат — HTML‑отчет, CSV со списком инцидентов и история сохраненных анализов.

## Быстрый старт

1) Установка зависимостей:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


## Запуск приложение

1) Запуск локально на машине:
Нужно изменить строчуку в app.py
Затем прописать команду:
```bash
python3 app.py 
```
Откройте в браузере: http://127.0.0.1:5000/

2) Запуск с помощью докера:

```bash
docker compose up --build
```

Откройте в браузере: http://127.0.0.1:5001/

## Как сгенерировать тестовые логи

Генератор находится в `tools/generate_logs.py`. Он пишет в stdout, поэтому
удобно перенаправить вывод в файл.

Примеры:

```bash
# Смешанный сценарий (норма + атаки)
python tools/generate_logs.py --mode mixed > test_logs/demo_mixed.log

# Только brute force
python tools/generate_logs.py --mode bruteforce > test_logs/demo_bruteforce.log

# Только SQLi
python tools/generate_logs.py --mode sqli > test_logs/demo_sqli.log

# Только XSS
python tools/generate_logs.py --mode xss > test_logs/demo_xss.log

# Только DoS
python tools/generate_logs.py --mode dos > test_logs/demo_dos.log
```

После генерации загрузите файл через веб‑форму.

## Что поддерживается

- Форматы логов: combined и common.
- Расширения файлов: `.log`, `.txt` (лимит 15 MB).
- Графики: запросы в минуту, таймлайн атак и топ‑IP.
- История анализов: повторное открытие отчетов, скачивание CSV, удаление одного анализа или очистка всей истории.

## Структура проекта

- `app.py` — Flask‑приложение и маршруты.
- `parser.py` — парсер строк access‑лога.
- `detectors.py` — правила детекторов и ML‑аномалии.
- `report.py` — построение графиков и экспорт CSV.
- `history_store.py` — JSON‑хранилище истории анализов.
- `templates/` — HTML‑шаблоны.
- `tools/generate_logs.py` — генератор тестовых логов.
- `test_logs/` — примеры логов.

## Заметки

- Сгенерированные графики и CSV лежат в `static/generated/`.
- История анализов хранится в `data/analysis_history.json`.
