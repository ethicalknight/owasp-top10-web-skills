# Alerting Platform Integration Guides

## Sentry (Exception Alerting + Performance)

### FastAPI
```python
# requirements: sentry-sdk[fastapi]
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    environment=settings.ENVIRONMENT,   # "production" / "staging"
    integrations=[
        FastApiIntegration(transaction_style="endpoint"),
        SqlalchemyIntegration(),
    ],
    traces_sample_rate=0.1,             # 10% performance tracing
    send_default_pii=False,             # NEVER send PII to Sentry
)
```

### Flask
```python
# requirements: sentry-sdk[flask]
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn=app.config["SENTRY_DSN"],
    integrations=[FlaskIntegration()],
    environment=app.config["ENV"],
    send_default_pii=False,
)
```

### Custom security event to Sentry
```python
from sentry_sdk import capture_message, push_scope

def alert_brute_force(username: str, ip: str, attempt_count: int):
    with push_scope() as scope:
        scope.set_tag("alert_type", "brute_force")
        scope.set_tag("ip", ip)
        scope.set_extra("username", username)
        scope.set_extra("attempts", attempt_count)
        capture_message(
            f"Brute force detected: {attempt_count} attempts",
            level="warning"
        )
```

---

## ELK Stack (Elasticsearch + Logstash + Kibana)

### Ship logs via Filebeat (recommended for containers)
```yaml
# filebeat.yml
filebeat.inputs:
  - type: container
    paths:
      - /var/lib/docker/containers/*/*.log
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "app-logs-%{+yyyy.MM.dd}"

processors:
  - add_host_metadata: ~
  - add_docker_metadata: ~
```

### Python → Logstash via TCP
```python
# requirements: python-logstash-async
import logging
import logstash

app.logger.addHandler(
    logstash.TCPLogstashHandler(
        host=settings.LOGSTASH_HOST,
        port=5000,
        version=1,
        message_type='python-fastapi',
        fqdn=False,
        tags=['fastapi', 'production']
    )
)
```

### Kibana alert rule for brute force
Create in Kibana → Stack Management → Rules:
- **Rule type:** Elasticsearch query
- **Query:** `event.action: "auth.failed" AND @timestamp > now-5m`
- **Threshold:** count > 10, grouped by `client.ip`
- **Action:** PagerDuty / Slack webhook

---

## Datadog

### FastAPI + ddtrace
```python
# requirements: ddtrace
# Run with: ddtrace-run uvicorn main:app

# In code — custom security events
from ddtrace import tracer

def log_security_event(event_type: str, **context):
    span = tracer.current_span()
    if span:
        span.set_tags({f"security.{k}": v for k, v in context.items()})
        span.set_tag("security.event_type", event_type)
```

### Custom metric for failed logins
```python
from datadog import statsd

# In auth failure handler
statsd.increment(
    'auth.login.failed',
    tags=[f"ip:{ip}", f"app:myapp", f"env:production"]
)
```

### Datadog monitor YAML (Terraform/API)
```yaml
name: "High Failed Login Rate"
type: "query alert"
query: "sum(last_5m):sum:auth.login.failed{env:production} > 50"
message: |
  High failed login rate detected.
  Possible brute force attack.
  @pagerduty @slack-security-alerts
thresholds:
  critical: 50
  warning: 20
```

---

## Splunk

### Python → Splunk HEC (HTTP Event Collector)
```python
# requirements: splunk-handler
import logging
from splunk_handler import SplunkHandler

splunk_handler = SplunkHandler(
    host=settings.SPLUNK_HOST,
    port=8088,
    token=settings.SPLUNK_HEC_TOKEN,
    index="main",
    source="fastapi-app",
    sourcetype="json",
    ssl_verify=True,
)
app.logger.addHandler(splunk_handler)
```

### Splunk security search (SPL)
```spl
# Detect brute force — >10 failures for same username in 5 min
index=main sourcetype=json event="auth.failed"
| bucket _time span=5m
| stats count by _time, username, ip
| where count > 10
| sort -count
```

---

## Honeytoken Deployment

Honeytokens generate near-zero false-positive intrusion alerts — any access triggers immediately.

```python
# Fake API key honeytoken — if this appears in logs/requests, system is compromised
HONEYTOKEN_API_KEY = "hk_prod_DO_NOT_USE_xK9mP2qR7nL4wZ"

@app.middleware("http")
async def detect_honeytoken_use(request: Request, call_next):
    auth = request.headers.get("Authorization", "")
    api_key = request.headers.get("X-API-Key", "")

    if HONEYTOKEN_API_KEY in auth or HONEYTOKEN_API_KEY in api_key:
        log.critical(
            "honeytoken.triggered",
            ip=request.client.host,
            path=str(request.url.path),
            user_agent=request.headers.get("user-agent"),
        )
        # Alert immediately — DO NOT return 401 (reveals honeytoken is fake)
        # Return 200 to observe attacker behavior
        return JSONResponse({"status": "ok"})

    return await call_next(request)
```

### Canary file honeytoken (filesystem)
```python
# Place fake credentials file — any read attempt = intrusion
# /etc/app/.env.backup (honeytoken — should never be read)
# Use canarytokens.org to generate alerting URLs embedded in fake data
```