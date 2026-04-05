# CI/CD Pipeline Templates — Supply Chain Security

## GitHub Actions

### Full supply chain scan workflow

```yaml
# .github/workflows/supply-chain-security.yml
name: Supply Chain Security

on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am UTC

permissions:
  contents: read
  security-events: write

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # pin by SHA!

      - name: Set up Python
        uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2f
        with:
          python-version: '3.12'

      - name: Install from lockfile
        run: |
          pip install poetry
          poetry install --no-root

      - name: pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt -f json -o pip-audit-results.json
        continue-on-error: false  # Fail build on findings

      - name: safety check
        run: |
          pip install safety
          safety check -r requirements.txt --json > safety-results.json
        env:
          SAFETY_API_KEY: ${{ secrets.SAFETY_API_KEY }}

      - name: Generate SBOM
        run: |
          pip install cyclonedx-bom
          cyclonedx-py requirements requirements.txt -o sbom.json --format json

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3
        with:
          name: sbom
          path: sbom.json
          retention-days: 90

      - name: Upload audit results
        uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3
        if: always()
        with:
          name: audit-results
          path: |
            pip-audit-results.json
            safety-results.json
```

### Dependabot configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    groups:
      security-updates:
        applies-to: security-updates
        patterns: ["*"]
    labels:
      - "dependencies"
      - "security"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    # This keeps your Actions pinned by SHA up to date too
```

---

## GitLab CI

```yaml
# .gitlab-ci.yml (supply chain stage)
supply-chain-scan:
  stage: security
  image: python:3.12-slim
  script:
    - pip install pip-audit safety cyclonedx-bom
    - pip-audit -r requirements.txt -f json -o gl-dependency-scanning-report.json
    - safety check -r requirements.txt --json > safety-report.json
    - cyclonedx-py requirements requirements.txt -o sbom.json --format json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - sbom.json
      - safety-report.json
    expire_in: 90 days
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
```

---

## Pre-commit hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pypa/pip-audit
    rev: v2.7.0
    hooks:
      - id: pip-audit
        args: ["-r", "requirements.txt"]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.8
    hooks:
      - id: bandit
        args: ["-c", "pyproject.toml"]
```

---

## SLSA Provenance (for published packages)

```yaml
# .github/workflows/release.yml
name: Release with SLSA Provenance

on:
  release:
    types: [published]

permissions:
  id-token: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Build
        run: python -m build
      - name: Generate hashes
        id: hash
        run: |
          cd dist && echo "hashes=$(sha256sum * | base64 -w0)" >> $GITHUB_OUTPUT

  provenance:
    needs: build
    permissions:
      id-token: write
      contents: write
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
```