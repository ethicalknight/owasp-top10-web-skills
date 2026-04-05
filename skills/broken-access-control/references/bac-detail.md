# Broken Access Control — Detailed Reference

## Table of Contents
1. [CWE Deep Dives](#cwe-deep-dives)
2. [Attack Scenarios](#attack-scenarios)
3. [Framework-Specific Patterns](#framework-specific-patterns)
4. [Compliance Mapping](#compliance-mapping)
5. [Testing with pytest](#testing-with-pytest)

---

## CWE Deep Dives

### CWE-284 — Improper Access Control
The product does not restrict or incorrectly restricts access to a resource. The broadest BAC category — a catch-all when a more specific CWE doesn't apply.

**Python indicator:** No auth dependency on route; logic grants access based on request parameters rather than server-side state.

### CWE-285 — Improper Authorization
The system does not perform or incorrectly performs an authorization check when an actor attempts to access a resource. More specific than CWE-284 — auth *is* checked but the check is wrong.

**Python indicator:** `current_user` exists but `current_user.role` or `current_user.id` comparison is missing or wrong.

### CWE-352 — Cross-Site Request Forgery (CSRF)
The web application does not sufficiently verify that a well-formed, valid, consistent request was intentionally sent by the user.

**When it applies:** Only affects cookie-based session auth. JWT Bearer tokens in `Authorization` header are inherently CSRF-safe. Flask apps using `flask_login` and session cookies need Flask-WTF.

### CWE-639 — Authorization Bypass via User-Controlled Key
The system's authorization functionality does not prevent one user from gaining access to another user's data by modifying a key value expected to be private.

**Classic IDOR pattern:**
```
GET /api/invoices/1042   → User A's invoice (OK)
GET /api/invoices/1043   → User B's invoice (IDOR — attacker just incremented ID)
```

### CWE-862 — Missing Authorization
The software does not perform an authorization check when an actor attempts to access a resource or perform an action.

**Distinct from CWE-285:** Here, *no check exists at all*, rather than a check that is incorrectly implemented.

### CWE-918 — Server-Side Request Forgery (SSRF)
The server fetches a remote resource based on user-supplied input without sufficient validation, allowing attackers to coerce the server to send requests to unintended destinations.

**Merged into A01 in 2025** (was A10:2021). High severity in cloud environments where instance metadata services expose credentials.

**Critical endpoints to check:**
- `http://169.254.169.254/` — AWS EC2 metadata (IAM credentials)
- `http://metadata.google.internal/` — GCP metadata
- `http://169.254.169.254/metadata/` — Azure IMDS
- `http://localhost:*` — Internal services (Redis, Elasticsearch, admin panels)

### CWE-200 — Exposure of Sensitive Information to Unauthorized Actor
Often a *consequence* of BAC failures rather than a root cause. When access control fails, sensitive data is exposed.

---

## Attack Scenarios

### Scenario 1: Horizontal Privilege Escalation via IDOR
```
POST /api/transfer
{"from_account": "12345", "to_account": "99999", "amount": 500}
```
Attacker changes `from_account` to another user's account ID. If the server doesn't verify `from_account` belongs to the authenticated user → funds stolen.

### Scenario 2: Vertical Privilege Escalation via Parameter Tampering
```
POST /api/users/update
{"user_id": "42", "role": "admin"}
```
If the server accepts `role` from the request body rather than from the server-side session, any user can grant themselves admin.

### Scenario 3: Forced Browsing
```
GET /admin/users          → Should return 403, returns 200
GET /internal/debug       → Should be protected, is public
GET /api/v1/export-all    → No auth guard, exports entire database
```

### Scenario 4: SSRF to Steal Cloud Credentials
```
POST /api/webhooks/test
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}
```
Server fetches the URL, attacker receives AWS access keys in the response.

### Scenario 5: JWT Algorithm Confusion
```python
# Attacker crafts token with alg: "none"
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": 1, "role": "admin"}
# No signature needed — if server accepts alg:none, attacker is admin
```
Fix: Always explicitly specify `algorithms=["HS256"]` in `jwt.decode()`.

---

## Framework-Specific Patterns

### FastAPI

**Global auth dependency (apply to entire router):**
```python
from fastapi import APIRouter, Depends

# Apply auth to all routes in this router
router = APIRouter(
    prefix="/api/v1",
    dependencies=[Depends(get_current_user)]
)
```

**Role-based access control:**
```python
def require_role(required_role: str):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker

@app.delete("/users/{user_id}")
async def delete_user(user_id: int, _: User = Depends(require_role("admin"))):
    ...
```

**Scoped permissions (OAuth2-style):**
```python
from fastapi.security import SecurityScopes

def get_current_user(security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)):
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=403,
                headers={"WWW-Authenticate": f'Bearer scope="{security_scopes.scope_str}"'},
            )
```

### Flask

**Role-based decorator:**
```python
from functools import wraps
from flask_login import current_user

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/admin/dashboard")
@login_required
@require_role("admin", "superadmin")
def admin_dashboard():
    ...
```

**Object-level permission check (Flask pattern):**
```python
@app.route("/documents/<int:doc_id>")
@login_required
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id and current_user.role != "admin":
        abort(404)  # 404 preferred: avoids confirming the resource exists
    return render_template("document.html", doc=doc)
```

---

## Compliance Mapping

| BAC Sub-category | OWASP CWE | PCI DSS | SOC 2 | ISO 27001 |
|---|---|---|---|---|
| Missing authorization | CWE-862 | Req 7.2 | CC6.1 | A.9.4.1 |
| IDOR | CWE-639 | Req 7.1 | CC6.3 | A.9.4.2 |
| CORS misconfiguration | CWE-284 | Req 6.4 | CC6.6 | A.14.1.2 |
| SSRF | CWE-918 | Req 6.3 | CC6.6 | A.14.2.8 |
| CSRF | CWE-352 | Req 6.3.2 | CC6.6 | A.14.2.5 |
| Privilege escalation | CWE-269 | Req 7.3 | CC6.3 | A.9.2.3 |

---

## Testing with pytest

### Integration test template for IDOR:
```python
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_idor_protection(client: AsyncClient, user_a_token, user_b_token):
    """User B should not be able to access User A's resource."""
    # User A creates a resource
    response = await client.post(
        "/api/documents",
        json={"title": "Private Doc"},
        headers={"Authorization": f"Bearer {user_a_token}"}
    )
    doc_id = response.json()["id"]

    # User B attempts to access User A's resource
    response = await client.get(
        f"/api/documents/{doc_id}",
        headers={"Authorization": f"Bearer {user_b_token}"}
    )
    assert response.status_code in (403, 404), f"IDOR vulnerability: got {response.status_code}"

@pytest.mark.asyncio
async def test_unauthenticated_access_denied(client: AsyncClient):
    """Protected routes must reject unauthenticated requests."""
    response = await client.get("/api/users/me")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_privilege_escalation_blocked(client: AsyncClient, user_token, admin_only_endpoint):
    """Regular user must not access admin endpoints."""
    response = await client.delete(
        f"/api/admin/users/1",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403
```

### SSRF test:
```python
@pytest.mark.asyncio
async def test_ssrf_private_ip_blocked(client: AsyncClient, user_token):
    """Server must not fetch private/internal URLs."""
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/admin",
        "http://localhost:6379",
        "http://192.168.1.1/",
    ]
    for url in ssrf_payloads:
        response = await client.post(
            "/api/webhooks/test",
            json={"url": url},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 400, f"SSRF not blocked for: {url}"
```