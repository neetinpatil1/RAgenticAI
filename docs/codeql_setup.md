# CodeQL Setup

## Install

```bash
brew install codeql
```

## Verify

```bash
codeql version
```

## Query packs (required)

```bash
codeql pack download codeql/java-queries
codeql pack download codeql/python-queries
codeql pack download codeql/javascript-queries
```

## Licence

CodeQL CLI is free for open source.
Commercial use in a regulated/financial environment requires GitHub Advanced Security licence.
Confirm with procurement before using in production.
Contact: github.com/features/security/code

## Air-gap

In an air-gapped environment:
1. Download query packs on an internet-connected machine
2. Copy ~/.codeql/packages/ to the air-gapped machine
3. Set CODEQL_DIST to point to local CLI binary

## Usage

Normal scan (no CodeQL):
```
POST /api/v1/scan { "path": "..." }
```

Deep scan (with CodeQL):
```
POST /api/v1/scan { "path": "...", "deep": true }
```

Deep scan requires:
- codeql CLI installed
- For Java: Maven available (mvn on PATH)
- 4–8 GB free RAM
- 5–20 min additional scan time

## Graceful degradation

If the codeql CLI is not installed, deep scans proceed normally without CodeQL.
The scan status response will include `agents.codeql_done: true` with
`metadata.codeql.skipped: true` and `metadata.codeql.skip_reason: "codeql CLI not found"`.
No error is raised and the rest of the pipeline is unaffected.
