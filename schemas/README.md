# Machine API schemas and fixtures

`machine-api-v1.schema.json` describes every document an irlume machine-mode
command (`--json`) writes under contract version 1. It is JSON Schema 2020-12.
Packaged builds install it at `/usr/share/irlume/schemas/`, so the schema and
the engine that implements it are never a version apart on a user's machine.

Validate against the copy your engine shipped, not against a copy from a
different release.

## The schema allows properties it does not describe

Fields may be added within a contract version, so the schema does not close its
objects. A consumer that rejects unknown properties will break on an engine
update the contract explicitly permits. Removing a field or changing its meaning
is what requires a new contract version, and a new contract gets its own schema
file beside this one.

`scripts/machine-api-conformance.py --strict` closes the objects for irlume's own
CI, where an undescribed property should be a decision rather than a surprise.

## Fixtures

`fixtures/v1/` holds documents captured from a real engine: the five read-only
commands, a status document with the daemon unreachable, and the three refusals
(`daemon-unavailable`, `unsupported-contract`, `usage-error`). They exist so a
consumer can build against documents irlume actually wrote rather than documents
someone imagined, which is a mistake that has already reached a downstream
project.

Two things are not verbatim, and both are deliberate:

- profile and scan display names are replaced with placeholders, because they
  are user text and the maintainer capturing a fixture should not have to
  publish their own. Counts, ordering and every other field are as captured;
- the host facts are one machine's. `login-status.json` shows a Fedora KDE box
  with plasmalogin wired, and `doctor.json` reports that machine's checks. Read
  them as shapes, not as expected values.

Regenerate before a release, and read the diff:

```sh
scripts/capture-machine-fixtures.py --irlume ./target/release/irlume
scripts/machine-api-conformance.py --irlume ./target/release/irlume --strict
```

A fixture that no longer validates is either a schema that fell behind or an
output that changed without a contract decision. Both are worth stopping for.
