import os
import sqlite3
import time
from datetime import datetime

from flask import Flask, g, jsonify, redirect, render_template, request, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "lab.db")
LOG_PATH = os.path.join(BASE_DIR, "logs", "access.log")

app = Flask(__name__)
app.config["SECRET_KEY"] = "kittyhub-demo-secret"

DEMO_USER = "admin"
DEMO_PASSWORD = "admin123"


# ------------------------------
# Database bootstrap
# ------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_error):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS cats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            breed TEXT NOT NULL,
            age_months INTEGER NOT NULL,
            fee REAL NOT NULL,
            bio TEXT NOT NULL
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    existing = db.execute("SELECT COUNT(*) FROM cats").fetchone()[0]
    if existing == 0:
        db.executemany(
            "INSERT INTO cats(name, breed, age_months, fee, bio) VALUES(?, ?, ?, ?, ?)",
            [
                ("Milo", "Maine Coon", 14, 120.0, "Friendly giant, likes kids and window naps."),
                ("Nori", "British Shorthair", 10, 150.0, "Calm indoor cat with soft blue coat."),
                ("Pixel", "Domestic Shorthair", 8, 95.0, "Playful and curious, loves toy mice."),
                ("Sasha", "Siberian", 20, 110.0, "Fluffy explorer with gentle temperament."),
                ("Luna", "Scottish Fold", 16, 180.0, "Very social, follows humans everywhere."),
            ],
        )

    db.commit()
    db.close()


# ------------------------------
# Access logging (combined format)
# ------------------------------
def _clean(value: str) -> str:
    return (value or "-").replace('"', "'")


def _request_url() -> str:
    if request.query_string:
        return request.full_path
    return request.path


@app.after_request
def write_access_log(response):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    ts = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    method = request.method
    url = _request_url()
    proto = request.environ.get("SERVER_PROTOCOL", "HTTP/1.1")
    status = response.status_code
    size = response.calculate_content_length() or 0
    ref = _clean(request.headers.get("Referer", "-"))
    ua = _clean(request.headers.get("User-Agent", "-"))

    line = f'{ip} - - [{ts}] "{method} {url} {proto}" {status} {size} "{ref}" "{ua}"\n'
    with open(LOG_PATH, "a", encoding="utf-8") as file_obj:
        file_obj.write(line)

    return response


# ------------------------------
# Business routes (cat app)
# ------------------------------
@app.get("/")
def index():
    db = get_db()
    featured = db.execute(
        "SELECT id, name, breed, age_months, fee, bio FROM cats ORDER BY id LIMIT 3"
    ).fetchall()
    total_cats = db.execute("SELECT COUNT(*) FROM cats").fetchone()[0]
    total_posts = db.execute("SELECT COUNT(*) FROM community_posts").fetchone()[0]
    return render_template(
        "index.html",
        featured=featured,
        total_cats=total_cats,
        total_posts=total_posts,
    )


@app.get("/cats")
def cats_catalog():
    db = get_db()
    query = request.args.get("q", "")

    unsafe_sql = (
        "SELECT id, name, breed, age_months, fee, bio "
        "FROM cats "
        f"WHERE name LIKE '%{query}%' OR breed LIKE '%{query}%' OR bio LIKE '%{query}%' "
        "ORDER BY id LIMIT 50"
    )

    rows = []
    error = None
    try:
        rows = db.execute(unsafe_sql).fetchall()
    except Exception as exc:
        error = str(exc)

    return render_template(
        "cats.html",
        query=query,
        rows=rows,
        error=error,
    )


@app.route("/community", methods=["GET", "POST"])
def community():
    db = get_db()
    note = request.args.get("note", "")

    if request.method == "POST":
        author = (request.form.get("author") or "cat_friend").strip()[:40]
        message = request.form.get("message") or ""
        db.execute(
            "INSERT INTO community_posts(author, message, created_at) VALUES(?, ?, ?)",
            (author, message, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        db.commit()
        return redirect(url_for("community"))

    entries = db.execute(
        "SELECT author, message, created_at FROM community_posts ORDER BY id DESC LIMIT 30"
    ).fetchall()
    return render_template("community.html", entries=entries, note=note)


@app.route("/account/login", methods=["GET", "POST"])
def account_login():
    auth_error = None
    auth_success = False

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == DEMO_USER and password == DEMO_PASSWORD:
            auth_success = True
        else:
            auth_error = "Invalid credentials"
            return render_template(
                "login.html",
                auth_error=auth_error,
                auth_success=auth_success,
                demo_user=DEMO_USER,
                demo_password=DEMO_PASSWORD,
            ), 401

    return render_template(
        "login.html",
        auth_error=auth_error,
        auth_success=auth_success,
        demo_user=DEMO_USER,
        demo_password=DEMO_PASSWORD,
    )


@app.get("/performance")
def performance_page():
    return render_template("performance.html")


def heavy_task(units: int) -> int:
    total = 0
    for i in range(1, units):
        total += (i * i) % 97
    time.sleep(0.04)
    return total


@app.get("/api/cat-feed")
def cat_feed_api():
    units = request.args.get("units", "120000")
    try:
        requested_units = int(units)
    except ValueError:
        requested_units = 120000

    requested_units = max(5000, min(requested_units, 350000))
    result = heavy_task(requested_units)
    return jsonify(
        {
            "ok": True,
            "units": requested_units,
            "checksum": result,
            "message": "Feed recommendations generated",
        }
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)
