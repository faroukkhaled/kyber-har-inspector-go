# Validation

Executed on 2026-11-01 in the authoring environment.

- Runtime: Go 1.27.3
- Command: `go test ./...`
- Result: 2 tests passed: transport/cache findings, report privacy and invalid URL schemes.

## Limits of verification

These checks are not a penetration test, production certification, load test or independent audit. All fixtures are synthetic. Operating-system and deployment differences may require additional validation.

The release source was reviewed for credential patterns before publication; no live credentials are included.
