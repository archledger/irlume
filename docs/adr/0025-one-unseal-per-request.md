# ADR-0025: One template-key unseal per authentication request

## Status

Accepted 2026-09-22 (proposed the same day; Phase 1 implemented with this
revision, Phase 2 measurement pending). Motivated by the latency
measurements in issue #797 on the then-current `main` (a44b5037) with the
schema 4 trace stages of #798.
Depends on ADR-0024 (multi-camera enrollment) and ADR-0021 (rate-evidence
amortization); changes neither's invariants. No implementation yet.

## Context

Encrypted enrollment stores are decrypted with the account template key,
which is sealed to the TPM under the PCR policy. Unsealing costs about
1.5 s on the archhost reference machine (context open, SRK load, policy
session, unseal, decrypt; `irlume-core` `tpm::unseal_literal`). The key
returned is a `Zeroizing<Vec<u8>>`, memlocked, and lives only as long as its
holder.

An authentication request on the account's primary camera pair unseals
once, inside `enrollment_load`. An authentication request on a secondary
camera pair (ADR-0024 §5) unseals the same key four times:

1. `enrollment_load`: the primary store (1.5 s).
2. `SecondaryAuthContext::pin`: the secondary store envelope
   (`load_secondary` → `production_key_for`).
3. `SecondaryAuthContext::pin`: the primary store again, through
   `storage::load_path_unlocked`, so that legacy migration and envelope
   handling match the authentication loader.
4. The grant boundary (`grant_boundary_now`): the secondary store envelope
   again. The primary is compared by digest from raw bytes and is not
   unsealed here.

Measured on the NexiGo N930W pair (a secondary group on archhost, whose
primary binding is the BRIO) with the first #798 commit installed on
archhost and its schema 4 stages traced (the runs are recorded in #797,
comments of 2026-09-22 03:31Z and 03:41Z): three granted attempts, the
2.9–3.0 s interval before `stream_arm` (the pin; the first #798 cut placed
`capture_setup` after it and read 0 ms, which located the cost), and
`finalization` 1.5 s (the boundary), on top of `enrollment_load` 1.5 s:
about 6 s of a 13.4 s grant, against a 15 s window. One attempt on the same
pair expired at 15.1 s. On the primary pair the same build grants in about
8 s with one unseal. The other large costs (IR stream start-up inside rate
establishment, five PAD samples, stream release) are per-camera or are
measured security parameters and are out of scope here.

Each of the four unseals produces the same secret: the account template key
for the same user, under the same PCR policy, within the same request. The
repeated unseals were never a security decision; they are the consequence
of each loader resolving its key independently.

## Decision

### 1. The request owns one unsealed key

An authentication request unseals the account template key at most once.
The request holds a lazy key resolver: the first encrypted read in the
request (normally `enrollment_load`; the pin when the primary is a legacy
plaintext store and the secondary is encrypted, a supported mixed state
under ADR-0024 §1.2) performs the unseal and the resolver adopts that key;
every later encrypted read in the same request borrows it. A request whose
reads are all plaintext, or on a host without a TPM, never unseals. The
resolver is owned by the request scope, not by the engine across requests.

Later readers borrow the key as `&[u8]`; no copy is made. The borrowed-key
entry points are `multi_camera::load_secondary_with_key(path, Option<&[u8]>)`
(existing; the pin and the grant boundary read the secondary store through
it instead of `load_secondary`) and a new borrowed-key variant of the
primary loader beside `storage::load_path_unlocked` for the pin's primary
re-load (same legacy migration and envelope handling, key injected instead
of resolved). The callback-based `load_secondary_resolved` and the
`load_with` seam, which take an owned key, are not used for reuse because
an owned copy of the TPM output would not be memlocked
(`SecretBytes::clone` documents this). No new decryption path is added.

### 2. Every read still happens

The pin and the grant boundary keep reading the stores from disk at their
existing points and keep every existing check: format version, envelope
authentication, owner match, primary-snapshot digest, secondary generation,
group activation, and the account-state lock discipline of ADR-0024 §1.1.
Only the key resolution changes. A store rewritten under a different key
during the request fails envelope authentication exactly as it does today;
that is the correct outcome, since such a rewrite is a re-keying transaction
this request must not follow.

### 3. Lifetime and disposal

The retained key is the single memlocked `Zeroizing<Vec<u8>>` the unseal
produced, owned by the request scope and dropped, and therefore zeroized,
when the request returns, whatever the outcome. It is not copied, not
stored on the engine, not shared between requests, not written anywhere,
and not exposed through any diagnostic or trace. Cancel, deadline, refusal
and error paths drop it the same way as a grant.

### 4. What this ADR does not do

It does not cache the key or the decrypted enrollment across requests
(the step-3 design in #797 remains a separate decision with its own PCR
drift, suspend and lock-screen questions). It does not skip the primary
unseal for a request, so a PCR change between requests still refuses at
the first load as today. It does not change ADR-0024's grant-boundary
re-read, its digest binding, or the serialized commit protocol.

## Phasing

- **Phase 1: key threading.** Add the request-scoped lazy resolver; thread
  a borrowed key through `resolve_attempt_enrollment` →
  `SecondaryAuthContext::pin` (secondary via `load_secondary_with_key`,
  primary via the new borrowed-key primary loader) and the boundary check.
  Keep the unlocked loaders' signatures for existing callers.
- **Phase 2: measurement.** Re-run the schema 4 trace on the NexiGo pair
  and record `capture_setup` and `finalization` before and after.

## Acceptance tests

- A secondary-pair authentication with encrypted stores performs exactly
  one template-key unseal: count unseals through the TPM seam in the
  daemon's existing fake TPM tests, for grant, refusal, cancellation and
  deadline outcomes. With a plaintext primary and an encrypted secondary,
  the pin performs that one unseal and the boundary borrows it. With
  plaintext stores throughout, or without a TPM, the count is zero.
- A primary-pair authentication is unchanged: one unseal for an encrypted
  store, and the secondary loaders are never invoked.
- No read in the request copies the key: the only `Zeroizing` allocation
  holding it is the unseal output (asserted through the memlock seam or an
  allocation-counting test double).
- The pin and boundary reads still refuse on a primary digest mismatch, a
  stale secondary generation, an inactive group, and a secondary store
  re-keyed during the request, with the retained key offered.
- The retained key is dropped on every return path of the request; a
  zeroize-on-drop witness observes it for grant, refusal and error.
- No trace, support report or log gains any key material (existing
  share-safety tests extended to the new holder).
- Hardware: NexiGo pair on archhost, three consecutive granted attempts,
  `capture_setup` below 0.5 s and `finalization` below 0.3 s, with the
  primary pair's timings unchanged.

## Consequences

- Secondary-pair authentication drops by about 4.5 s on the reference
  machine (three unseals), moving a 13.4 s grant to about 9 s and away from
  the 15 s window edge. Primary-pair attempts are unchanged.
- The account key is held in process memory for the duration of the
  request instead of four shorter intervals; the memlocked, zeroizing
  holder already exists for the first interval, so the exposure class does
  not change.
- Loader entry points gain an explicit-key variant, which also makes the
  unseal count testable; today it is implicit in how many loaders run.
- The remaining per-attempt unseal (1.5 s) is the subject of the
  cross-request design in #797 step 3, not of this ADR.
