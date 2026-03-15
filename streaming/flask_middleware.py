import time
import uuid
from flask import request
from streaming.redis_client import r


def register_redis_logging(app):

    @app.after_request
    def push_to_redis(response):
        try:
            ip = request.remote_addr
            ts = time.time()
            log_id = str(uuid.uuid4())
            raw = f'{log_id} {ip} - - [{ts}] "{request.method} {request.full_path} HTTP/1.1" {response.status_code} -'

            pipe = r.pipeline()
            pipe.rpush(f"logs:{ip}", raw)
            pipe.hincrby("ip:counter", ip, 1)
            pipe.zadd("ip:queue", {f"{ts}:{ip}:{log_id}": ts})
            pipe.execute()
        except Exception:
            pass

        return response
