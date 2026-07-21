# CLI reference & exit codes

```text
mispfleet
├── config      init | show | validate | path | add-server | remove-server
├── servers     list | show | test | health | versions | capabilities | templates diff
├── search      value | events | attributes
├── event       get | find | diff | copy | export | validate
├── policy      list | show | validate | test
├── state       info | checkpoints | checkpoint show/delete | operations | prune
├── plugins     list
├── apply       PLAN_FILE
└── version
```

## Global options

`--config PATH`, `--profile NAME`, `--server NAME` (repeatable), `--group`,
`--tag`, `--role`, `--all`, `--exclude-server`, `--format table|json|jsonl|yaml`,
`--output PATH`, `--log-level`, `--log-format text|json`, `--no-color`,
`--quiet`, `--verbose`, `--timeout`, `--concurrency`, `--non-interactive`,
`--trace`, `--version`. Global options may appear before or after the
subcommand (`mispfleet search value X --all --format json`). Shell completion
is available through `--install-completion`.

## Output rules

- Machine output (`json`, `jsonl`, `yaml`) goes to stdout; logs and warnings
  go to stderr. Every document carries `schema_version` and the operation name.
- Timestamps are ISO 8601 UTC; UUIDs are strings; ordering is deterministic.
- Structured output remains valid even when the exit code is non-zero.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0    | Success |
| 1    | Generic execution error |
| 2    | CLI usage or validation error |
| 3    | Configuration error |
| 4    | Authentication error |
| 5    | Connectivity error |
| 6    | Partial fleet failure |
| 7    | Policy rejection |
| 8    | Plan validation failure |
| 9    | Conflict detected |
| 10   | Unsupported server capability |
| 11   | No matching records |
| 12   | User-cancelled operation |
| 13   | Security validation failure (e.g. TLS) |
