# Server groups

A fleet is rarely uniform: production and research instances, partner
communities, sandboxes. Groups, tags and roles let you address subsets of the
fleet without repeating server names on every command.

## Declaring groups

Every server may declare `groups`, `tags` and a `role` in the configuration
file:

```yaml
version: 1
servers:
  production:
    url: https://misp.internal
    credential: {provider: keyring, key: mispfleet/production}
    groups: [core, internal]
    tags: [tier-1, eu]
    role: primary
  research:
    url: https://research.internal
    credential: {provider: keyring, key: mispfleet/research}
    groups: [core, lab]
    tags: [tier-2]
    role: research
  partner-circl:
    url: https://misp.partner.example
    credential: {provider: keyring, key: mispfleet/partner-circl}
    groups: [partners]
    tags: [external, eu]
    role: general
```

`groups` are free-form labels, a server may belong to several. `tags` are
independent labels for cross-cutting concerns (tier, region, owner). `role`
is one of `general`, `primary`, `research` or `partner`.

## Selecting servers

Every fleet-wide command accepts the same selector options:

| Option | Effect |
| ------ | ------ |
| `--server NAME` | select one server; repeatable |
| `--group NAME` | select every server in the group; repeatable |
| `--tag NAME` | select every server carrying the tag; repeatable |
| `--role NAME` | select every server with that role; repeatable |
| `--all` | select every enabled server |
| `--exclude-server NAME` | remove a server from the selection; repeatable |

Selectors combine as a union of the positive criteria, minus the exclusions:

```bash
mispfleet search value evil.example --group partners --group core
mispfleet servers health --all --exclude-server partner-circl
mispfleet search attributes --type sha256 --role research
```

Commands that mutate data or target exactly one instance (`event get`,
`event copy`, `attribute get`, `stix export`) require an explicit single
`--server`; they never fan out implicitly.

Disabled servers (`enabled: false`) are never selected, including under
`--all`. A selector matching no enabled server is a configuration error
(exit code 3) rather than a silent no-op.

## Selecting from Python

The same rules are available through `ServerSelector`:

```python
from mispfleet import MispFleet, SearchQuery, ServerSelector

fleet = await MispFleet.from_file()
partners = ServerSelector(groups={"partners"}, excluded={"partner-circl"})
result = await fleet.search(SearchQuery(value="evil.example"), selector=partners)
```

`ServerSelector.all()` selects every enabled server, and
`fleet.select(selector)` resolves a selector to the concrete server names it
matches — useful to preview a selection before running an operation.

## Profiles versus groups

Groups pick *which* servers an operation touches. [Profiles](configuration.md)
pick *which configuration* is loaded (different defaults, different servers
entirely). Use profiles to separate environments, groups to address subsets
within one environment.
