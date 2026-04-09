# Remediation Patterns — A09 Security Logging & Alerting Failures

## CWE-117: Log Injection

### Pattern 1 — f-string injection
```python
# BEFORE (vulnerable)
logger.info(f"User action: {request.args.get('action')}")

# AFTER (safe)
action = request.args.get('action', '')
safe_action = action.replace('\n', '\\n').replace('\r', '\\r').replace('\x1b', '')
logger.info("User action: %s", safe_action)
```

### Pattern 2 — Structured logging (best approach)
```python
# BEFORE (vulnerable to injection)
app.logger.warning("Failed login: " + username + " from " + ip)

# AFTER (JSON fields are injection-safe by design)
log.warning("auth.failed", username=username, ip=ip)
# structlog JSONRenderer serializes each field independently
```

### Pattern 3 — Centralized sanitizer
```python
import re

def sanitize_for_log(value: str, max_length: int = 200) -> str:
    """Strip injection characters and truncate for log safety."""
    if not isinstance(value, str):
        value = str(value)
    # Remove newlines (log forging), ANSI escapes (terminal injection)
    value = re.sub(r'[\r\n\x1b]', '_', value)
    return value[:max_length]

# Usage
logger.info("Request from user: %s", sanitize_for_log(username))
```

---

## CWE-532: Sensitive Information in Logs

### Pattern 1 — Filter sensitive fields before logging request body
```python
SENSITIVE_FIELDS = {"password", "passwd", "token", "api_key", "secret",
                    "credit_card", "card_number", "cvv", "ssn", "authorization"}

def redact_dict(data: dict) -> dict:
    """Return a copy of dict with sensitive values replaced."""
    return {
        k: "***REDACTED***" if k.lower() in SENSITIVE_FIELDS else v
        for k, v in data.items()
    }

# FastAPI middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.json()
        log.info("request.body", path=request.url.path, body=redact_dict(body))
    response = await call_next(request)
    return response
```

### Pattern 2 — Safe exception logging
```python
# BEFORE (may log sensitive context variables)
try:
    process_payment(card_number, amount)
except Exception as e:
    logger.error(f"Payment failed: {e}", exc_info=True)  # locals() may appear

# AFTER (explicit safe fields only)
try:
    process_payment(card_number, amount)
except PaymentError as e:
    logger.error(
        "payment.failed",
        user_id=current_user.id,
        amount=amount,
        error_code=e.code,   # structured error code, not raw message
        # NOTE: card_number intentionally excluded
    )
```

---

## CWE-778: Insufficient Logging

### Pattern 1 — Flask auth blueprint with complete audit logging
```python
from flask import Blueprint, request, current_app
import logging

auth_bp = Blueprint('auth', __name__)
audit_log = logging.getLogger('audit')

@auth_bp.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        audit_log.warning(
            "auth.login.failed",
            extra={
                "ip": request.remote_addr,
                "username": username,          # username OK to log
                "user_agent": request.user_agent.string[:200],
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        return {"error": "Invalid credentials"}, 401

    audit_log.info(
        "auth.login.success",
        extra={
            "user_id": user.id,
            "ip": request.remote_addr,
            "user_agent": request.user_agent.string[:200],
        }
    )
    session['user_id'] = user.id
    return {"status": "ok"}
```

### Pattern 2 — FastAPI dependency for audit logging
```python
from fastapi import Depends, Request
from functools import wraps
import structlog

log = structlog.get_logger("audit")

async def audit_dependency(request: Request):
    """Inject audit context into every protected route."""
    return {
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "")[:200],
        "path": str(request.url.path),
        "method": request.method,
    }

@router.get("/admin/users")
async def list_users(
    current_user: User = Depends(get_current_admin_user),
    audit: dict = Depends(audit_dependency),
):
    log.info("admin.users.list", user_id=current_user.id, **audit)
    return await get_all_users()
```

---

## CWE-223: Omission of Security-Relevant Info

### Pattern — Exception handler that logs full context
```python
# FastAPI global handler
from fastapi import Request
from fastapi.responses import JSONResponse
import structlog

log = structlog.get_logger()

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error(
        "unhandled.exception",
        path=str(request.url.path),
        method=request.method,
        ip=request.client.host,
        exc_type=type(exc).__name__,
        exc_message=str(exc),   # safe — not raw user input
    )
    # Return generic message — stack trace never reaches client
    return JSONResponse(
        status_code=500,
        content={"error": "An internal error occurred."}
    )

# Flask equivalent
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(
        "unhandled.exception path=%s method=%s ip=%s error=%s",
        request.path, request.method, request.remote_addr, str(e),
        exc_info=True,
    )
    return {"error": "An internal error occurred."}, 500
```

---

## CWE-390: Swallowed Exceptions

```python
# BEFORE — exception caught silently, security event lost
try:
    verify_jwt_token(token)
except Exception:
    pass  # attacker probing tokens gets no detection signal

# AFTER — log and re-raise or return safe default
try:
    verify_jwt_token(token)
except InvalidTokenError as e:
    log.warning("jwt.invalid", reason=str(e), ip=request.client.host)
    raise HTTPException(status_code=401, detail="Invalid token")
except Exception as e:
    log.error("jwt.unexpected_error", exc_type=type(e).__name__)
    raise HTTPException(status_code=500, detail="Authentication error")
```