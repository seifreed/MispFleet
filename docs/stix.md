# STIX, TAXII and OpenCTI

MispFleet exports MISP events as STIX 2.1 bundles and ships them to TAXII 2.1
collections or OpenCTI. No extra dependencies are required.

## STIX 2.1 export

```bash
mispfleet --server production stix export EVENT_UUID --format json
```

The mapping is deterministic: identifiers are UUIDv5 values derived from event
content, so exporting the same event twice yields the identical bundle. Each
event becomes a `report`; supported attribute types become `indicator` objects
with STIX patterns:

| MISP type | STIX pattern |
| --------- | ------------ |
| `ip-src`, `ip-dst` | `[ipv4-addr:value = '…']` |
| `domain`, `hostname` | `[domain-name:value = '…']` |
| `url` | `[url:value = '…']` |
| `md5`, `sha1`, `sha256` | `[file:hashes.… = '…']` |
| `email-src`, `email-dst` | `[email-addr:value = '…']` |
| `filename` | `[file:name = '…']` |

`tlp:*` tags map to the standard TLP marking-definitions; the source
organisation becomes an `identity`. Attribute types without a pattern mapping
are **reported** in a `skipped` list, never dropped silently.

## TAXII 2.1 push

```bash
export MISPFLEET_TAXII_TOKEN=...
mispfleet --server production stix push EVENT_UUID \
  --taxii-url https://taxii.example \
  --collection 91a7b528-80eb-42ed-a74d-c6fbd5a26116 \
  --credential-key MISPFLEET_TAXII_TOKEN \
  --api-root api1
```

The client supports discovery, collection listing and object push over the
`application/taxii+json;version=2.1` media type, with bearer or basic auth.

## OpenCTI

```bash
export MISPFLEET_OPENCTI_TOKEN=...
mispfleet opencti test \
  --opencti-url https://opencti.example \
  --credential-key MISPFLEET_OPENCTI_TOKEN

mispfleet --server production opencti push EVENT_UUID \
  --opencti-url https://opencti.example \
  --credential-key MISPFLEET_OPENCTI_TOKEN
```

`opencti push` converts the event to a STIX bundle and imports it through the
OpenCTI GraphQL `stixBundlePush` mutation. The token is sent as a bearer header
and is never included in logs or error messages.
