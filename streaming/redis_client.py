import redis
import time
import os


def create_redis_client():
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=6379,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True,
        health_check_interval=30
    )


def get_redis_with_retry(max_retries=5, delay=2):
    for attempt in range(max_retries):
        try:
            client = create_redis_client()
            client.ping()
            print("Redis connected")
            return client
        except (redis.ConnectionError, redis.TimeoutError) as e:
            print(f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
    raise RuntimeError("Cannot connect to Redis after max retries")


r = get_redis_with_retry()
