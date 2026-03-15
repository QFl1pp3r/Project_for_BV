import time
from streaming.redis_client import r

WINDOW_SECONDS = 300


def evict_expired():
    ts_dt = time.time() - WINDOW_SECONDS

    expired = r.zrangebyscore("ip:queue", 0, ts_dt)

    if not expired:
        return

    for member in expired:
        # member формат: "ts:ip:log_id"
        parts = member.split(":")
        ip = parts[1]

        new_count = r.hincrby("ip:counter", ip, -1)

        if new_count <= 0:
            r.hdel("ip:counter", ip)
            r.delete(f"logs:{ip}")
            r.delete(f"flushed:{ip}")

    r.zremrangebyscore("ip:queue", 0, ts_dt)


def run_loop():
    print("Eviction Worker started")
    while True:
        try:
            evict_expired()
        except Exception as e:
            print(f"Eviction error: {e}")
        time.sleep(1)


if __name__ == "__main__":
    run_loop()
