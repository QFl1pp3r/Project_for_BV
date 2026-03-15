import time
import uuid
from datetime import datetime, timezone
from flask import request
from streaming.redis_client import r


def register_redis_logging(app):

    @app.after_request
    def push_to_redis(response):
        try:
            ip = request.remote_addr or "0.0.0.0"
            ts = time.time()
            log_id = str(uuid.uuid4())

            # Format timestamp in Apache combined-log style so core.parser can parse it
            ts_fmt = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")

            ref = (request.headers.get("Referer") or "-").replace('"', "'")
            ua = (request.headers.get("User-Agent") or "-").replace('"', "'")

            if request.query_string:
                url = request.full_path
            else:
                url = request.path

            size = response.calculate_content_length() or 0

            raw = (
                f'{ip} - - [{ts_fmt}] '
                f'"{request.method} {url} HTTP/1.1" '
                f'{response.status_code} {size} '
                f'"{ref}" "{ua}"'
            )

            pipe = r.pipeline()
            pipe.rpush(f"logs:{ip}", raw)
            pipe.hincrby("ip:counter", ip, 1)
            pipe.zadd("ip:queue", {f"{ts}:{ip}:{log_id}": ts})
            pipe.execute()
        except Exception:
            pass

        return response
