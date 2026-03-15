# Интеллектуальный анализатор access-логов

Flask-приложение для анализа HTTP access-логов Nginx/Apache. Основной детектор использует CatBoost-модель с 5 классами:

- `NORMAL`
- `SQLI`
- `XSS`
- `BRUTE_FORCE`
- `DOS`

Regex-детекторы сохранены как baseline для side-by-side сравнения с ML. Важно: это не ground truth и не замена полноценной ML-валидации на размеченном датасете.

## Статус проекта

Текущая реализация — `PoC / demo`, а не production-ready SOC/IR инструмент.

- Онлайн-отчет показывает объединенные инциденты `ML + Regex` и метрики последнего обучения модели.
- Настоящие ML-метрики качества нужно считать офлайн на отдельном размеченном validation-наборе.
- Если внешний validation-набор не предоставлен, все метрики обучения относятся только к внутреннему holdout-сплиту и не доказывают готовность модели к реальному трафику.

## Быстрый старт

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Подготовка модели

1. Сгенерировать датасет:

```bash
python3 tools/generate_dataset.py --output data/dataset.csv --total 120000
```

2. Обучить CatBoost:

```bash
python3 tools/train_model.py --dataset data/dataset.csv --output models/attack_detector.cbm --metrics models/metrics.json
```

3. При наличии отдельного размеченного validation-набора выполнить внешнюю офлайн-валидацию:

```bash
python3 tools/train_model.py \
  --dataset data/dataset.csv \
  --validation-dataset data/validation_dataset.csv \
  --output models/attack_detector.cbm \
  --metrics models/metrics.json
```

После этого Flask-приложение будет использовать `models/attack_detector.cbm` как основной детектор.

Важно: старые артефакты модели и метрик, обученные на 6-классовой схеме с `ANOMALY`, больше не совместимы. После изменения схемы классов нужно заново собрать датасет и переобучить модель.

## Запуск приложения

Локально:

```bash
python3 app.py
```

Открыть в браузере: `http://127.0.0.1:5000/`

Docker:

```bash
docker compose up --build
```

Открыть в браузере: `http://127.0.0.1:5001/`

## Генерация тестовых логов

```bash
python3 tools/generate_logs.py --mode mixed > test_logs/demo_mixed.log
python3 tools/generate_logs.py --mode bruteforce > test_logs/demo_bf.log
python3 tools/generate_logs.py --mode sqli > test_logs/demo_sqli.log
python3 tools/generate_logs.py --mode xss > test_logs/demo_xss.log
python3 tools/generate_logs.py --mode dos > test_logs/demo_dos.log
python3 tools/generate_logs.py --mode campaign > test_logs/demo_campaign.log
```

`mixed` использует только поддерживаемые типы атак `SQLI/XSS/BRUTE_FORCE/DOS`, а `campaign` фиксирован как demo-цепочка `BRUTE_FORCE -> SQLI -> XSS` без `DOS`.

При импорте внешних датасетов (`CSIC` / `CICIDS`) в итоговый CSV попадают только строки с метками `NORMAL/SQLI/XSS/BRUTE_FORCE/DOS`; все остальные классы отбрасываются.

## Лабораторный уязвимый веб-сервис

В репозитории добавлен отдельный сервис `vulnerable_service/` для реализации реалистичных access-логов.

Сервис намеренно содержит сценарии, которые соответствуют классам детектора:

- `SQLI` через поиск в `/cats?q=...`
- `XSS` через параметр `note` и посты `/community`
- `BRUTE_FORCE` через повторные неуспешные `POST /account/login` (`401`)
- `DOS` через burst-запросы на `/api/cat-feed`

Запуск сервиса:

```bash
cd vulnerable_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

По умолчанию сервис доступен на `http://127.0.0.1:8080`.

Все HTTP-запросы сохраняются в:

```text
vulnerable_service/logs/access.log
```

## Attack-скрипт для сервиса

Добавлен внешний скрипт `tools/attack_lab_service.py`, который:

- генерирует трафик по всем 4 сценариям (`SQLI/XSS/BRUTE_FORCE/DOS`)
- берёт только новые строки из `vulnerable_service/logs/access.log`
- сохраняет их в отдельный файл для загрузки в детектор

Пример:

```bash
python3 tools/attack_lab_service.py \
  --base-url http://127.0.0.1:8080 \
  --service-log vulnerable_service/logs/access.log \
  --output test_logs/lab_attack.log
```

Полезные параметры:

- `--bf-attempts` (по умолчанию `14`)
- `--dos-requests` (по умолчанию `220`)
- `--dos-units` (по умолчанию `5000`)
- `--dos-workers` (по умолчанию `20`)

## Что строится в отчете

- KPI по логу и найденным инцидентам
- таймлайн инцидентов
- график нагрузки по минутам
- топ IP
- распределение confidence модели
- таблица метрик последнего обучения CatBoost
- таблица объединенных инцидентов с источником `ML`, `Regex` или `ML + Regex`

Важно: метрики CatBoost в веб-интерфейсе относятся к последнему офлайн-обучению на holdout/validation, а не к текущему загруженному логу.

## Структура

- `app.py` — Flask и orchestration анализа
- `parser.py` — парсер access-логов
- `feature_engineering.py` — извлечение признаков
- `ml_detector.py` — CatBoost inference
- `accuracy.py` — сравнение ML и regex
- `detectors.py` — regex baseline
- `report.py` — генерация графиков и CSV
- `tools/generate_dataset.py` — сборка обучающего датасета
- `tools/train_model.py` — обучение CatBoost
- `tools/generate_logs.py` — генератор демо-логов
- `models/` — модель и метрики обучения
- `data/` — датасеты
