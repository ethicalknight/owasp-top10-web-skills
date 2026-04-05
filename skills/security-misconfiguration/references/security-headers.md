# Security Headers Reference

## Required Headers for Production

### Strict-Transport-Security (HSTS)
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- Forces HTTPS for 1 year
- `preload` requires submission to browser preload lists
- Do NOT set on HTTP responses

### X-Content-Type-Options
```
X-Content-Type-Options: nosniff
```
- Prevents MIME-type sniffing attacks
- Always set to `nosniff` — no other valid value

### X-Frame-Options
```
X-Frame-Options: DENY
# or
X-Frame-Options: SAMEORIGIN
```
- Prevents clickjacking via iframe embedding
- Prefer CSP `frame-ancestors` for modern browsers (CSP takes precedence)

### Content-Security-Policy (CSP)
Minimum restrictive policy:
```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

Progressive tightening:
```
# Add only what you need:
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.example.com;
  style-src 'self' 'unsafe-inline';          # tighten later with nonces
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.example.com;
  media-src 'none';
  object-src 'none';
  frame-src 'none';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
```

- Use `report-uri` or `report-to` to collect violations before going strict
- Never use `unsafe-eval` in production

### Referrer-Policy
```
Referrer-Policy: strict-origin-when-cross-origin
```
- Sends origin only on HTTPS → HTTPS cross-origin
- Sends full URL on same-origin
- Sends nothing on HTTPS → HTTP downgrade

### Permissions-Policy
```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```
- Replaces Feature-Policy
- Disable everything not used by the application

### Cache-Control (for authenticated pages)
```
Cache-Control: no-store
Pragma: no-cache
```

## Headers to Remove
These reveal server implementation details:
- `Server` (e.g., `Server: nginx/1.18.0 ubuntu`)
- `X-Powered-By` (e.g., `X-Powered-By: Flask`)
- `X-AspNet-Version`

## Testing Headers

```bash
# curl
curl -sI https://your-app.com | grep -iE "strict-transport|x-content|x-frame|content-security|referrer"

# securityheaders.com API equivalent with Python
pip install requests
python -c "
import requests
r = requests.head('https://your-app.com')
required = ['Strict-Transport-Security','X-Content-Type-Options',
            'X-Frame-Options','Content-Security-Policy','Referrer-Policy']
for h in required:
    status = '✓' if h in r.headers else '✗ MISSING'
    print(f'{status}: {h}')
"
```

## OWASP ZAP Header Scan

```bash
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://your-app.com \
  -r zap-headers-report.html \
  -a  # include ajax spider
```