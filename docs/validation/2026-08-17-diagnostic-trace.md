# Privacy-bounded diagnostic trace hardware validation, 2026-08-17

The final trace matrix ran from signed commit
`ccecf8636ffaccb34ff157d7d9160ae88206ff42` on the same four isolated hosts as
the support-report validation. Each 20-second trace overlapped one explicit,
production-shaped support probe and was parsed offline by the exact-build
`irlume trace explain` command.

## Matrix

| Host and camera | Selected capture evidence | Trace artifact |
|---|---|---|
| ASUS RGB+IR `3277:0059` | sequential default; exact RGB/IR contracts; delivered-rate floors, zero drops, continuity epoch 0, and ActiveIr=true; capture/detection timings and categorical decision | 19 records, 2 operation IDs, 1 terminal, 0 dropped, 5,633 bytes; SHA-256 `869f9aac25601f611203beef03d7198a6ec2dc9f82d3910abac1b7d814db6c1e` |
| Logitech BRIO `046d:085e` | stored sequential; RGB accepted 640x480 and IR accepted 340x340; delivered-rate/continuity/ActiveIr evidence plus capture, detection, liveness, and decision events | 20 records, 2 operation IDs, 1 terminal, 0 dropped, 6,382 bytes; SHA-256 `1d0dab59d8c7c61c5945c9f55be2d207048c410f9d0cedae50ca5915b5637307` |
| NexiGo N930W `3443:c803` | sequential default; RGB accepted 640x480 and IR accepted 640x360; delivered-rate/continuity/ActiveIr evidence plus capture/detection and decision events | 19 records, 2 operation IDs, 1 terminal, 0 dropped, 5,631 bytes; SHA-256 `de3cc183da346fd496c959476815b2850a17f94ba5df8ced5400f85a8a8a80eb` |
| Chicony RGB-only `04f2:b7bf` | `no_ir_pair`; exact RGB contract and rate/continuity evidence; RGB capture, detection, detector count, liveness timing, and decision; no invented IR event | 12 records, 2 operation IDs, 1 terminal, 0 dropped, 3,943 bytes; SHA-256 `c45a2aabd42765641eb2ae20418a67b4abd8818c6c130e479fbd7b9c46690c5f` |

All final JSONL files and their offline explanations were mode 0600. Every
trace was far below the 16 MiB and 50,000-event caps. The runner rejected the
forbidden key set for account/profile identity, frames/crops/landmarks,
embeddings, credentials, and emitter payloads.

## Real concurrent failure and bounded retry

The final BRIO override run started concurrent despite its stored
measured-sequential qualification. The trace preserved this order under one
support-probe operation ID:

```text
CaptureScheduleSelected(Concurrent, EnvironmentOverride)
CaptureFallback(PairRateEstablishmentFailure)
sequential RGB capture
sequential IR capture
exact stream contracts and delivered evidence
OperationFinished(Completed)
```

The fallback trace contained 21 records, one terminal, zero dropped events,
and was 6,697 bytes (SHA-256
`25c0004f9c3ec32cc93b966b4f1d364a088d8d43f4ecad5af65ba4f023c728f6`).
Both roles were captured. The before/after durable qualification hashes were
identical, proving that an operator-forced initial schedule did not turn the
support probe into a qualification writer.

## Disconnect, replacement, and non-interference

On every host a client was forcibly disconnected after two seconds. The final
`.jsonl` path did not exist; one mode-0600 partial remained. A new subscriber
was then accepted and published a complete one-second replacement trace,
showing that disconnect releases the singleton subscription.

The daemon's bounded-subscriber unit test separately saturates the queue with
10,000 emissions, proves producer completion within its fixed budget, and
requires an explicit `EventsDropped` marker. Authentication/capture return
values are also tested with no-op and diagnostic sinks. The physical runs add
real V4L2 STREAMON/DQBUF, rate, emitter-provenance, topology, and fallback
coverage; tracing did not change any probe category or durable qualification
record, and every installed daemon was restored active.

The physical trace duration was intentionally set to 20 seconds so the same
bounded lifecycle could run simultaneously on all four devices. Parser and CLI
tests cover the 60-second default and five-minute maximum. No live enrollment
or authentication identity was placed in these trace artifacts; the explicit
support probe exercises the same capture/assessment/fallback path without
requiring account data.

## Evidence location

Raw JSONL, offline explanations, partials, hashes, and daemon logs remain on
the test hosts in the `/var/tmp/irlume-diag-evidence-ccecf86-*` directories
listed by the companion support-report validation. Only this sanitized summary
is committed.
