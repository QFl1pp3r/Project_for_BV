# Интеллектуальный анализатор access-логов

Flask-приложение для анализа HTTP access-логов Nginx/Apache. Основной детектор теперь использует предобученную CatBoost-модель с 6 классами:

- `NORMAL`
- `SQLI`
- `XSS`
- `BRUTE_FORCE`
- `DOS`
- `ANOMALY`

Regex-детекторы сохранены как baseline для side-by-side сравнения с ML. Важно: это не ground truth и не замена полноценной ML-валидации на размеченном датасете.

## Статус проекта

Текущая реализация — `PoC / demo`, а не production-ready SOC/IR инструмент.

- Онлайн-отчет показывает только степень совпадения `ML vs Regex baseline`.
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
```

## Что строится в отчете

- KPI по логу и найденным инцидентам
- таймлайн инцидентов
- график нагрузки по минутам
- топ IP
- распределение confidence модели
- сравнение `ML vs Regex baseline`
- таблица инцидентов с confidence и признаком совпадения с regex

Важно: блок `ML vs Regex baseline` в веб-интерфейсе не является оценкой точности модели по разметке.

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
