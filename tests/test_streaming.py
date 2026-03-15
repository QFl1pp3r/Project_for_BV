"""
Тест стриминговой системы.
Запускать при работающем Redis: docker compose up redis -d
Затем: python -m streaming.test_streaming
"""
import time
import uuid
import redis

r = redis.Redis(host="localhost", port=6379, decode_responses=True)


def cleanup():
    """Очистить все ключи перед тестом"""
    for key in r.scan_iter("logs:*"):
        r.delete(key)
    for key in r.scan_iter("flushed:*"):
        r.delete(key)
    r.delete("ip:counter")
    r.delete("ip:queue")
    print("[CLEANUP] Redis очищен")


def test_ingest(ip, count):
    """Имитация ingest — как flask_middleware"""
    print(f"\n[INGEST] Отправляем {count} запросов от {ip}")
    for i in range(count):
        ts = time.time()
        log_id = str(uuid.uuid4())
        raw = f'{log_id} {ip} - - [{ts}] "GET /test/{i} HTTP/1.1" 200 -'

        pipe = r.pipeline()
        pipe.rpush(f"logs:{ip}", raw)
        pipe.hincrby("ip:counter", ip, 1)
        pipe.zadd("ip:queue", {f"{ts}:{ip}:{log_id}": ts})
        pipe.execute()

    counter = r.hget("ip:counter", ip)
    queue_size = r.zcard("ip:queue")
    logs_size = r.llen(f"logs:{ip}")
    print(f"[CHECK] counter={counter}, queue_size={queue_size}, logs={logs_size}")


def test_threat_levels():
    """Проверяем что пороги работают"""
    levels = {
        "10.0.0.1": 50,     # normal
        "10.0.0.2": 150,    # suspicious
        "10.0.0.3": 500,    # warning
        "10.0.0.4": 1500,   # attack
    }

    expected = {
        "10.0.0.1": "NORMAL (50 req)",
        "10.0.0.2": "SUSPICIOUS (150 req)",
        "10.0.0.3": "WARNING (500 req)",
        "10.0.0.4": "ATTACK (1500 req)",
    }

    for ip, count in levels.items():
        test_ingest(ip, count)

    print("\n[THRESHOLDS] Ожидаемые уровни:")
    for ip, level in expected.items():
        actual_count = r.hget("ip:counter", ip)
        print(f"  {ip}: {level} (actual counter={actual_count})")


def test_eviction():
    """Проверяем что eviction работает"""
    ip = "192.168.99.99"
    ts_old = time.time() - 400  # 400 сек назад — старше окна в 300 сек
    log_id = str(uuid.uuid4())

    r.rpush(f"logs:{ip}", f"{log_id} {ip} old_log_entry")
    r.hincrby("ip:counter", ip, 1)
    r.zadd("ip:queue", {f"{ts_old}:{ip}:{log_id}": ts_old})

    print(f"\n[EVICTION] Добавлен старый лог для {ip} (ts={ts_old})")
    print(f"[EVICTION] counter={r.hget('ip:counter', ip)}")

    # Имитируем eviction
    from streaming.eviction_worker import evict_expired
    evict_expired()

    counter_after = r.hget("ip:counter", ip)
    logs_after = r.llen(f"logs:{ip}")
    print(f"[EVICTION] После eviction: counter={counter_after}, logs={logs_after}")

    if counter_after is None and logs_after == 0:
        print("[EVICTION] ✅ PASSED — старые данные удалены")
    else:
        print("[EVICTION] ❌ FAILED — данные остались")


def test_redis_connection():
    """Проверяем подключение"""
    try:
        r.ping()
        print("[CONNECTION] ✅ Redis доступен")
        return True
    except redis.ConnectionError:
        print("[CONNECTION] ❌ Redis недоступен. Запусти: docker compose up redis -d")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("  ТЕСТ СТРИМИНГОВОЙ СИСТЕМЫ")
    print("=" * 60)

    if not test_redis_connection():
        exit(1)

    cleanup()
    test_threat_levels()
    test_eviction()

    print("\n" + "=" * 60)
    print("  ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ")
    print("=" * 60)
