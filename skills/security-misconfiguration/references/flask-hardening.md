# Flask Hardening Reference

## Production Configuration Checklist

```python
# config/production.py
class ProductionConfig:
    # Core security
    SECRET_KEY = os.environ["SECRET_KEY"]
    DEBUG = False
    TESTING = False

    # Session cookies
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "__Host-session"
    PERMANENT_SESSION_LIFETIME = 3600

    # Remember-me cookies
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 86400  # 24h max

    # WTF CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # SQLAlchemy
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
```

## Essential Extensions

```bash
pip install flask-talisman flask-login flask-wtf flask-limiter
```

| Extension | Purpose |
|-----------|---------|
| `flask-talisman` | Security headers + HTTPS enforcement |
| `flask-login` | Session auth with secure defaults |
| `flask-wtf` | CSRF protection |
| `flask-limiter` | Rate limiting |

## flask-talisman Full Config

```python
from flask_talisman import Talisman

csp = {
    "default-src": "'self'",
    "script-src": ["'self'", "https://cdn.jsdelivr.net"],
    "style-src": ["'self'", "'unsafe-inline'"],  # tighten if possible
    "img-src": ["'self'", "data:", "https:"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "connect-src": "'self'",
    "frame-ancestors": "'none'",
}

Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    content_security_policy=csp,
    referrer_policy="strict-origin-when-cross-origin",
    feature_policy={
        "geolocation": "'none'",
        "camera": "'none'",
        "microphone": "'none'",
    },
)
```

## Flask-Limiter Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379",
)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    ...
```

## Custom Error Handlers (avoid info leakage)

```python
@app.errorhandler(404)
def not_found(e):
    return {"error": "Not found"}, 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"500 error: {e}")
    return {"error": "Internal server error"}, 500

# Catch-all — never expose stack traces
@app.errorhandler(Exception)
def unhandled_exception(e):
    app.logger.exception("Unhandled exception")
    return {"error": "An error occurred"}, 500
```