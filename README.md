# KYBER HAR Inspector

Offline browser HAR analysis for transport, cache and performance review without exposing request contents.

**Status: v0.1 portfolio implementation.** Created by Farouk Khaled for the KYBER portfolio. This is new work created in November 2026, not a historical client deployment.

## Features

- HTTP-origin, cache-control, server-error, latency and response-size signals.
- JSON output and auto-escaped HTML reports.
- Drops URL paths, queries, user information, headers and bodies from reports.

## Technology

Go 1.22+. No third-party runtime dependencies.

## Run

```sh
go run . -input sample.har -html report.html
```

## Verify

```sh
go test ./...
```

See [VALIDATION.md](VALIDATION.md) for the checks actually run in the authoring environment.

## Scope and limitations

- HAR files may contain highly sensitive data; keep originals private.
- Rules do not establish exploitable vulnerabilities or actual page performance.
- 20 MiB input cap. Exit 0 clean, 1 review signals, 2 malformed input.

## Repository layout

Source, configuration, synthetic sample data and tests are kept in this repository. Runtime databases and generated reports are ignored. Never commit client data, credentials or unredacted reports.

## Roadmap

- Broaden test fixtures and error recovery coverage.
- Gather real usability feedback using synthetic data.
- Version the data format before adding import/migration features.

## Security

Report concerns privately through the contact options on [the maintainer profile](https://github.com/faroukkhaled). Do not include secrets in public issues. See [SECURITY.md](SECURITY.md).

## License

No license has been granted yet. Contact the author before reuse or redistribution.
