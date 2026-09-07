# Authentication retry budget contract

A private capture/clock seam makes the existing retry loop deterministic in tests.
The production caller retains the same capture implementation and monotonic clock.
The tests retain real vote/admission behavior and cover a slow first assessment,
five fitting assessments, equality, expiry, worst observed cost, fallback cost
seeding, elevation, terminal denial and capture errors.

The change does not widen request windows, change matcher thresholds or add a
public API. Historical mutation testing verified that removing the fit guard
makes the budget regression fail. Final scoped execution results accompany the PR.
