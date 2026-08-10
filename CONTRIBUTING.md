# Contributing

## Verify changes

Run:

```sh
go build ./...
go test ./...
go vet ./...
```

Tests should exercise supported, observable behavior: dashboard workflows,
installation and service outcomes, HTTP APIs, persisted state, cryptography,
policies, rate limits, and interoperability. Remove tests together with features
that are removed before release.

All changes must go through a pull request and pass CI.
