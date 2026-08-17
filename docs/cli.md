# CLI reference & exit codes

```text
mispfleet
├── config      init | show | validate | path | add-server | remove-server
├── servers     list | show | test | health | versions | capabilities | templates diff
├── search      value | events | attributes
├── event       get | find | diff | copy [plan] | export | validate
├── attribute   get | search
├── policy      list | show | validate | test
├── sync        list | plan | run
├── stix        export | push
├── opencti     test | push
├── state       info | checkpoints | checkpoint show/delete | operations | prune
├── plugins     list
├── apply       PLAN_FILE
├── health      --all
├── completion  bash | zsh | fish
└── version
```

`mispfleet health` is a top-level alias of `mispfleet servers health`; both
accept the same selectors and produce the same document.

## Global options

`--config PATH`, `--profile NAME`, `--server NAME` (repeatable), `--group`,
`--tag`, `--role`, `--all`, `--exclude-server`,
`--format table|json|jsonl|yaml|patch`, `--output PATH`, `--log-level`,
`--log-format text|json`, `--no-color`, `--quiet`, `--verbose`, `--timeout`,
`--concurrency`, `--non-interactive`, `--no-verify-tls`, `--trace`,
`--version`. Global options may appear before or after the subcommand
(`mispfleet search value X --all --format json`).

`--format patch` is only accepted by `event diff`; other commands reject it
as a usage error. `--no-verify-tls` disables certificate verification for
every server and prints a visible warning on stderr; a configuration with
`security.forbid_insecure_tls: true` refuses the flag with exit code 3.

## Search filters

`search events` accepts `--info`, `--since`, `--tag`, `--org`,
`--threat-level`, `--analysis` and `--distribution`. `search attributes`
accepts `--type`, `--tag`, `--since`, `--limit`, `--org`, `--object-name`,
`--distribution`, `--timestamp-since` and `--timestamp-until`.

## Attributes

`attribute get UUID --server NAME` fetches a single attribute; add
`--download DIR` to store an attachment payload (the remote filename is
sanitized, the file is created with owner-only permissions and an existing
file is never overwritten). `attribute search` streams JSON lines without
buffering the dataset, honoring the global selector and `--output`.

## Shell completion

`mispfleet completion zsh` (or `bash`/`fish`) prints the completion script:

```bash
mispfleet completion zsh > ~/.zfunc/_mispfleet
```

Typer's `--install-completion` also remains available.

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
