# Per-Role Delivered-Rate Shortfall Evidence Design

## Problem

Capture qualification already receives typed `Error::DeliveredRate` payloads with the exact role, delivered rate, required floor, tolerance, and rolling-window facts. The qualification accumulator currently discards that payload and retains only a round count. A stored sequential verdict and a partial `camera-tune` attempt therefore cannot explain which stream missed its floor or by how much.

## Scope

Add diagnostics-only evidence for issue #644. Preserve every qualification threshold, tolerance, retry count, attempt outcome, authority replacement rule, capture schedule, and authentication decision.

## Data Contract

`irlume-common` owns the share-safe DTOs:

- `RateShortfallEvidence` records a typed RGB or IR role, failure count, worst exact delivered rate, exact required floor, tolerance percent, window count, and window span.
- `RateShortfallsByRole` has fixed optional RGB and IR slots. No map or unbounded collection is permitted.
- `RateShortfallsByArm` has optional sequential and concurrent `RateShortfallsByRole` values.

The worst sample for one role is the minimum exact delivered-to-floor ratio. Selection uses integer arithmetic and must not convert the ratio to floating point. A round in which both streams report `Error::DeliveredRate` increments the arm's failed-round count once and each role's shortfall count once.

## Persistence Semantics

`ArmEvidence` gains an additive `Option<RateShortfallsByRole>` field:

- Missing field or `None`: a legacy producer did not record per-role shortfall evidence.
- `Some` with empty RGB and IR slots: a current producer measured the arm and observed no typed shortfall.
- `Some` with one or both slots: a current producer measured typed shortfalls.

Fresh `ArmEvidence::new` values always store `Some`, including measured-empty values. Capture qualification schema version remains `2`; old schema-2 records continue to deserialize and validate.

## Authority Semantics

`CaptureStatus` exposes two separately labeled optional `RateShortfallsByArm` fields:

- `authoritative_rate_shortfalls`: evidence attached to the conclusive attempt that currently governs capture.
- `latest_attempt_rate_shortfalls`: evidence attached to the most recent attempt, including an inconclusive retune.

An inconclusive retune may update latest-attempt evidence but cannot replace or visually masquerade as authoritative evidence.

## Presentation

`camera-tune` names each failing role and prints its failure count, worst exact delivered rate, exact required floor, tolerance, and window. This applies to conclusive delivered-rate verdicts and partial attempts such as one completed round plus four typed shortfalls.

The human support report renders authoritative and latest-attempt evidence in separate labeled sections. For each arm it distinguishes legacy unknown, measured with no shortfalls, and measured shortfalls. The output remains share-safe and contains no paths, serial values, frames, embeddings, or user identity.

## Compatibility And Tests

Tests cover exact worst-sample selection, simultaneous RGB and IR failures, legacy unknown versus measured-empty persistence, schema-2 round trips, inconclusive attempts preserving authority, old `CaptureStatus` payloads, daemon wording for conclusive and partial attempts, and support-report rendering.
