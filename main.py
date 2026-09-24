from flask import Flask, request, jsonify, redirect
from werkzeug.middleware.proxy_fix import ProxyFix

import sqlite3
import secrets
import time
import os
from urllib.parse import urlparse

# ============================================================
# ⚡ YOUTUBE SHORT URL RESOLVER
# ============================================================

app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)

# ============================================================
# ⚙️ CONFIG
# ============================================================

DATABASE = os.getenv(
    "DATABASE_PATH",
    "tokens.db"
)

CREATE_API_KEY = os.getenv(
    "CREATE_API_KEY",
    ""
)

PUBLIC_BASE_URL = os.getenv(
    "PUBLIC_BASE_URL",
    ""
).rstrip("/")


# Maximum lifetime of a generated short URL.
# Even if the original URL lives longer, our token won't.
MAX_TOKEN_TTL = 10 * 60


# ============================================================
# 🗄️ DATABASE
# ============================================================

def get_db():
    db = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    db.row_factory = sqlite3.Row

    return db


def init_db():

    db = get_db()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )

    db.commit()
    db.close()


# ============================================================
# 🧹 CLEAN EXPIRED TOKENS
# ============================================================

def cleanup_expired():

    now = int(time.time())

    db = get_db()

    db.execute(
        "DELETE FROM tokens WHERE expires_at <= ?",
        (now,)
    )

    db.commit()
    db.close()


# ============================================================
# 🔐 VALIDATE TARGET URL
# ============================================================

def is_allowed_target(url):

    try:

        parsed = urlparse(
            str(url).strip()
        )

        # Only HTTPS
        if parsed.scheme.lower() != "https":
            return False

        host = (
            parsed.hostname
            or ""
        ).lower()

        # Only Google video CDN URLs.
        #
        # Examples:
        # redirector.googlevideo.com
        # rr5---sn-xxx.googlevideo.com
        #
        if host == "googlevideo.com":
            return True

        if host.endswith(
            ".googlevideo.com"
        ):
            return True

        return False

    except Exception:

        return False


# ============================================================
# ⏳ DETERMINE TOKEN EXPIRY
# ============================================================

def get_expiry_from_url(url):

    now = int(
        time.time()
    )

    # Default expiry
    expiry = now + MAX_TOKEN_TTL

    try:

        parsed = urlparse(url)

        query = {}

        for part in parsed.query.split("&"):

            if "=" in part:

                key, value = part.split(
                    "=",
                    1
                )

                query[key] = value

        # YouTube signed URLs normally contain:
        # expire=UNIX_TIMESTAMP

        expire_value = query.get(
            "expire"
        )

        if expire_value:

            original_expiry = int(
                expire_value
            )

            # Never keep our token alive longer
            # than the original URL itself.
            expiry = min(
                expiry,
                original_expiry
            )

    except Exception:

        pass

    return expiry


# ============================================================
# 🩺 HEALTH CHECK
# ============================================================

@app.get("/")
def home():

    return jsonify(
        {
            "status": "ok",
            "service": "YouTube Short URL Resolver",
            "developer": "Mrr Unknown"
        }
    )


@app.get("/health")
def health():

    return jsonify(
        {
            "status": "healthy"
        }
    )


# ============================================================
# 🔑 CREATE SHORT URL
# ============================================================

@app.post("/create")
def create_short_url():

    # --------------------------------------------------------
    # API KEY CHECK
    # --------------------------------------------------------

    if CREATE_API_KEY:

        supplied_key = request.headers.get(
            "X-API-Key",
            ""
        )

        if supplied_key != CREATE_API_KEY:

            return jsonify(
                {
                    "ok": False,
                    "error": "Unauthorized"
                }
            ), 401


    # --------------------------------------------------------
    # JSON CHECK
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not isinstance(
        data,
        dict
    ):

        return jsonify(
            {
                "ok": False,
                "error": "JSON body required"
            }
        ), 400


    target_url = (
        data.get("url")
        or
        data.get("media_url")
        or
        ""
    )

    target_url = str(
        target_url
    ).strip()


    # --------------------------------------------------------
    # URL VALIDATION
    # --------------------------------------------------------

    if not target_url:

        return jsonify(
            {
                "ok": False,
                "error": "Missing url"
            }
        ), 400


    if not is_allowed_target(
        target_url
    ):

        return jsonify(
            {
                "ok": False,
                "error": (
                    "Only HTTPS googlevideo.com "
                    "URLs are allowed"
                )
            }
        ), 400


    # --------------------------------------------------------
    # CLEAN OLD TOKENS
    # --------------------------------------------------------

    cleanup_expired()


    # --------------------------------------------------------
    # TOKEN
    # --------------------------------------------------------

    token = None

    db = get_db()

    # Retry in the extremely unlikely event
    # of a token collision.

    for _ in range(5):

        candidate = secrets.token_urlsafe(
            9
        )

        try:

            db.execute(
                """
                INSERT INTO tokens
                (
                    token,
                    target_url,
                    created_at,
                    expires_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    candidate,
                    target_url,
                    int(time.time()),
                    get_expiry_from_url(
                        target_url
                    )
                )
            )

            token = candidate

            break

        except sqlite3.IntegrityError:

            continue


    if not token:

        db.close()

        return jsonify(
            {
                "ok": False,
                "error": "Unable to generate token"
            }
        ), 500


    db.commit()
    db.close()


    # --------------------------------------------------------
    # CREATE PUBLIC URL
    # --------------------------------------------------------

    if PUBLIC_BASE_URL:

        base_url = PUBLIC_BASE_URL

    else:

        base_url = (
            request.url_root
            .rstrip("/")
        )


    short_url = (
        base_url
        + "/ytgo/"
        + token
    )


    return jsonify(
        {
            "ok": True,
            "url": short_url,
            "token": token
        }
    )


# ============================================================
# 🚀 REDIRECT
# ============================================================

@app.get("/ytgo/<token>")
def resolve_token(token):

    token = str(
        token
    ).strip()


    cleanup_expired()


    db = get_db()

    row = db.execute(
        """
        SELECT
            target_url,
            expires_at
        FROM tokens
        WHERE token = ?
        """,
        (token,)
    ).fetchone()


    db.close()


    # --------------------------------------------------------
    # TOKEN NOT FOUND
    # --------------------------------------------------------

    if not row:

        return jsonify(
            {
                "ok": False,
                "error": (
                    "This download link is "
                    "invalid or expired."
                )
            }
        ), 404


    # --------------------------------------------------------
    # EXPIRY CHECK
    # --------------------------------------------------------

    now = int(
        time.time()
    )

    if now >= int(
        row["expires_at"]
    ):

        return jsonify(
            {
                "ok": False,
                "error": (
                    "This download link "
                    "has expired."
                )
            }
        ), 410


    # --------------------------------------------------------
    # REDIRECT
    # --------------------------------------------------------

    return redirect(
        row["target_url"],
        code=302
    )


# ============================================================
# 🧹 OPTIONAL TOKEN STATS
# ============================================================

@app.get("/stats")
def stats():

    if CREATE_API_KEY:

        supplied_key = request.headers.get(
            "X-API-Key",
            ""
        )

        if supplied_key != CREATE_API_KEY:

            return jsonify(
                {
                    "ok": False,
                    "error": "Unauthorized"
                }
            ), 401


    cleanup_expired()


    db = get_db()

    row = db.execute(
        "SELECT COUNT(*) AS total FROM tokens"
    ).fetchone()

    db.close()


    return jsonify(
        {
            "ok": True,
            "active_tokens": int(
                row["total"]
            )
        }
    )


# ============================================================
# ▶️ STARTUP
# ============================================================

init_db()


if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
