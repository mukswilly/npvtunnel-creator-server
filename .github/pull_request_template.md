## Summary

Describe the user-facing or operational reason for this change.

## Public repository checklist

- [ ] The change contains no secrets, private keys, production addresses, customer data, or local paths.
- [ ] The change contains no chat/session transcripts, internal reports, temporary plans, or assistant-specific notes.
- [ ] New comments explain durable constraints rather than implementation history.
- [ ] New documentation has a clear public audience and continuing purpose.
- [ ] No generated binaries, packages, or runtime state are committed.
- [ ] `bash scripts/check-public-tree.sh`, `go test ./...`, and `go vet ./...` pass locally.
