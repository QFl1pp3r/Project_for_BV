# Интеллектуальный анализатор access-логов

Flask-приложение для анализа HTTP access-логов Nginx/Apache с двумя контурами работы:

1. офлайн-анализ загруженного лог-файла через веб-интерфейс;
2. потоковый мониторинг логов через Redis с отдельным live dashboard.

Основной ML-детектор использует CatBoost-модель с 5 классами:

- `NORMAL`
- `SQLI`
- `XSS`
- `BRUTE_FORCE`
- `DOS`

Regex-детекторы сохранены как baseline и fallback, а итоговый отчет объединяет события из `ML`, `Regex` или `ML + Regex`.

## Что умеет проект

- Загружать `access.log`/`txt` в формате `combined` или `common`.
- Парсить URL даже в сложных случаях, включая payload'ы с кавычками и пробелами.
- Классифицировать запросы CatBoost-моделью и агрегировать их в инциденты по временному окну.
- Дополнять ML-результат сигнатурными regex-детекторами для `SQLI`, `XSS`, `BRUTE_FORCE`, `DOS`.
- Переходить в режим `regex_fallback`, если модель недоступна или несовместима.
- Объединять дублирующиеся инциденты из разных источников в одну серию атак.
- Строить HTML-отчет с KPI, таймлайном атак, графиком нагрузки, топом IP и распределением confidence.
- Экспортировать инциденты в CSV.
- Сохранять историю анализов с возможностью повторного открытия и удаления артефактов.
- Показывать метрики последнего обучения модели из `models/metrics.json`.
- Принимать поток логов через Redis, считать активность по IP и отображать live dashboard на `/streaming`.
- Маршрутизировать подозрительный поток в отдельные файлы `logs/all_logs.log`, `logs/anomaly_logs.log`, `logs/ml_incidents.json`.
- Генерировать синтетические датасеты и demo-логи для обучения и ручной проверки.
- Поднимать лабораторный уязвимый веб-сервис для realistic traffic replay.
- Содержать unit-тесты на парсер, feature engineering, merge/reporting, историю анализов, генерацию данных и training split logic.

## Статус проекта

Текущая реализация — `PoC / demo`, а не production-ready SOC/IR инструмент.

- Метрики модели в интерфейсе относятся к последнему офлайн-обучению, а не к текущему загруженному логу.
- Без отдельного размеченного validation-набора качество подтверждается только внутренним holdout.
- Redis streaming здесь реализован как демонстрационный pipeline для локального мониторинга и лабораторных сценариев.

## Быстрый старт

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск веб-интерфейса

Локально:

```bash
python3 app.py
```

Приложение будет доступно на `http://127.0.0.1:5000/`.

Основные страницы:

- `/` — загрузка файла и история анализов
- `/report/<analysis_id>` — сохраненный отчет
- `/streaming` — live dashboard для Redis streaming
- `/api/streaming/status` — JSON-статус потокового контура

Docker:

```bash
docker compose up --build
```

Docker-стек поднимает:

- `bv_app` — основное Flask-приложение
- `redis` — очередь/хранилище потоковых событий
- `eviction_worker` — очистка sliding window в Redis
- `anomaly_router` — маршрутизация и ML-анализ потоковых логов

После запуска:

- UI: `http://127.0.0.1:5001/`
- Streaming dashboard: `http://127.0.0.1:5001/streaming`
- Redis: `127.0.0.1:6379`

## Что строится в офлайн-отчете

- KPI по загруженному логу
- число уникальных IP
- число серий атак и число подозрительных запросов
- таймлайн инцидентов по типам атак
- график запросов по минутам
- топ IP по числу запросов
- распределение confidence модели
- таблица метрик последнего обучения CatBoost
- таблица объединенных инцидентов с источником `ML`, `Regex` или `ML + Regex`
- CSV-экспорт инцидентов

Каждый успешный анализ сохраняется в `data/analysis_history.json`, а графики/CSV складываются в `static/generated/`.

## Потоковый мониторинг через Redis

В проекте есть отдельный streaming pipeline для живого мониторинга запросов.

Как он устроен:

1. `streaming/flask_middleware.py` пишет каждый HTTP-запрос в Redis:
   - список `logs:<ip>`
   - счетчик `ip:counter`
   - sorted set `ip:queue`
2. `streaming/eviction_worker.py` удаляет события старше 5 минут и уменьшает счетчики.
3. `streaming/anomaly_router.py` читает новые логи по IP, определяет threat level по порогам и:
   - пишет все события в `logs/all_logs.log`
   - пишет подозрительные события в `logs/anomaly_logs.log`
   - при уровнях `warning/attack` прогоняет данные через ML и пишет инциденты в `logs/ml_incidents.json`
4. Flask endpoint `/api/streaming/status` собирает live-снимок состояния для страницы `/streaming`.

Пороговые уровни активности:

- `normal` — до `100` запросов на IP за окно
- `suspicious` — до `250`
- `warning` — до `1000`
- `attack` — больше `1000`

Streaming dashboard показывает:

- число активных IP
- размер очереди
- распределение threat levels
- top IP по request count
- timeline по уровням активности
- live log feed
- последние ML-инциденты

### Быстрый demo-сценарий для streaming

1. Поднять Redis и воркеры:

```bash
docker compose up --build
```

2. В отдельном терминале запустить лабораторный сервис:

```bash
cd vulnerable_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

3. Открыть streaming dashboard:

```text
http://127.0.0.1:5001/streaming
```

4. Сгенерировать трафик в лабораторный сервис:

```bash
python3 tools/attack_lab_service.py \
  --base-url http://127.0.0.1:8999 \
  --service-log vulnerable_service/logs/access.log \
  --output test_logs/lab_attack.log
```

Важно: Redis-мидлварь подключается именно в `vulnerable_service/app.py`, поэтому live streaming имеет смысл либо с этим сервисом, либо при интеграции `register_redis_logging(app)` в другой источник трафика.

## Лабораторный уязвимый веб-сервис

В репозитории есть отдельный сервис `vulnerable_service/`, который генерирует реалистичные access-логи и может отправлять их в Redis.

Сценарии:

- `SQLI` через `/cats?q=...`
- `XSS` через `note` и `POST /community`
- `BRUTE_FORCE` через повторные неуспешные `POST /account/login`
- `DOS` через burst-запросы на `/api/cat-feed`

Запуск:

```bash
cd vulnerable_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

По умолчанию сервис доступен на `http://127.0.0.1:8999/`.

Логи сервиса пишутся в:

```text
vulnerable_service/logs/access.log
```

Если Redis доступен, этот же сервис автоматически включает Redis logging middleware.

## Генерация тестовых логов

Скрипт `tools/generate_logs.py` умеет генерировать:

- `normal`
- `bruteforce`
- `sqli`
- `xss`
- `dos`
- `mixed`
- `campaign`

Примеры:

```bash
python3 tools/generate_logs.py --mode normal --output test_logs/demo_normal.log
python3 tools/generate_logs.py --mode mixed --output test_logs/demo_mixed.log
python3 tools/generate_logs.py --mode bruteforce --output test_logs/demo_bf.log
python3 tools/generate_logs.py --mode sqli --output test_logs/demo_sqli.log
python3 tools/generate_logs.py --mode xss --output test_logs/demo_xss.log
python3 tools/generate_logs.py --mode dos --output test_logs/demo_dos.log
python3 tools/generate_logs.py --mode campaign --output test_logs/demo_campaign.log
```

Полезные параметры:

- `--intensity low|medium|high`
- `--attackers N`
- `--attacks sqli,xss`
- `--warmup-min`
- `--tail-min`
- `--bf-seconds`
- `--sqli-count`
- `--xss-count`
- `--dos-seconds`
- `--dos-rps`

`mixed` использует только поддерживаемые типы атак `SQLI/XSS/BRUTE_FORCE/DOS`, а `campaign` фиксирован как demo-цепочка `BRUTE_FORCE -> SQLI -> XSS`.

## Подготовка датасета и обучение модели

1. Сгенерировать датасет:

```bash
python3 tools/generate_dataset.py --output data/dataset.csv --total 120000
```

2. Обучить CatBoost:

```bash
python3 tools/train_model.py \
  --dataset data/dataset.csv \
  --output models/attack_detector.cbm \
  --metrics models/metrics.json
```

3. При наличии отдельного размеченного validation-набора выполнить внешнюю офлайн-валидацию:

```bash
python3 tools/train_model.py \
  --dataset data/dataset.csv \
  --validation-dataset data/validation_dataset.csv \
  --output models/attack_detector.cbm \
  --metrics models/metrics.json
```

Особенности training pipeline:

- жестко проверяется текущая 5-классовая схема
- поддерживаются режимы split: `auto`, `time`, `group`, `row`
- `auto` предпочитает `time -> group -> row`
- сохраняются train/test размеры, confusion matrix и per-class metrics
- можно добавлять внешний validation dataset только для офлайн-оценки

Важно: старые артефакты модели и метрик, обученные на другой схеме классов, несовместимы. После изменения label schema нужно пересобрать датасет и переобучить модель.

## Импорт внешних данных

`tools/generate_dataset.py` может добавлять записи из локально доступных публичных наборов данных.

При импорте внешних датасетов (`CSIC` / `CICIDS`) в итоговый CSV попадают только строки с метками:

- `NORMAL`
- `SQLI`
- `XSS`
- `BRUTE_FORCE`
- `DOS`

Все остальные классы отбрасываются как неподдерживаемые текущей схемой.

## Тесты

Проект содержит набор unit-тестов в `tests/`.

Запуск unit-тестов:

```bash
python3 -m unittest discover -s tests
```

Что покрыто тестами:

- парсинг access-log строк
- feature engineering
- сигнатуры `SQLI/XSS`
- merge логики `ML + Regex`
- summary и breakdown для отчета
- сохранение истории анализов и удаление артефактов
- генерация synthetic dataset
- split logic `group/time/auto`
- валидация label schema при обучении
- CLI генератора логов

Отдельно есть streaming smoke test, который требует доступный Redis на `localhost:6379`:

```bash
docker compose up -d redis
python3 tests/test_streaming.py
```

Этот smoke test проверяет:

- ingest логов в Redis
- рост счетчиков `ip:counter`
- пороги threat levels
- eviction старых событий из sliding window

На локальной `.venv` unit-тесты проходят: `24 tests OK`.

## Структура проекта

- `app.py` — Flask UI, офлайн-анализ, история и streaming API
- `core/parser.py` — парсинг access-логов
- `core/feature_engineering.py` — извлечение признаков
- `core/ml_detector.py` — CatBoost inference и агрегация ML-инцидентов
- `core/detectors.py` — regex baseline/fallback
- `core/analysis.py` — orchestration `ML + Regex`
- `core/report.py` — генерация графиков и CSV
- `core/model_metrics.py` — загрузка и нормализация метрик обучения
- `history_store.py` — хранение истории анализов
- `streaming/flask_middleware.py` — отправка HTTP-логов в Redis
- `streaming/eviction_worker.py` — очистка окна активности
- `streaming/anomaly_router.py` — маршрутизация и ML-анализ потоковых логов
- `tools/generate_dataset.py` — сборка обучающего датасета
- `tools/train_model.py` — обучение CatBoost
- `tools/generate_logs.py` — генератор demo-логов
- `tools/attack_lab_service.py` — генератор атак на лабораторный сервис
- `vulnerable_service/` — намеренно уязвимое Flask-приложение для realistic traffic
- `models/` — модель и метрики обучения
- `data/` — датасеты и история анализов
- `logs/` — файлы потокового мониторинга
- `test_logs/` — готовые demo-логи
