# Grouped sequential authentication validation

Qualified sequential login/unlock captures five RGB samples, releases RGB, then
captures five IR samples and releases IR. Every pair retains its exact runtime
contract, delivered-rate/continuity evidence, active IR provenance and existing
eight-second gap limit. Evidence is assessed in order; only the final eligible
sample materializes identity and reaches the existing matcher. The five-score
PAD rule, separated IR identity and 15-second login deadline remain enforced.
Elevation, app consent, credential release and known remote services are excluded.

The final combined source passed 1,978 workspace tests, zero failed and 101
existing ignored, plus all-target Clippy and workspace rustdoc with warnings
denied, formatting and diff checks. Fourteen grouped-auth tests and twelve camera
collector tests cover the new path. Independent review found no new grouped/PAD
correctness issue after the earlier four review findings were corrected.

ASUS built-in RGB/IR isolated trials used temporary encrypted enrollment and the
measured sequential qualification. Genuine grants took 12.044 seconds and then
11.999, 11.982 and 12.015 seconds. In the adjacent recovery sequence, confirmed
absence denied in 10.172 seconds with both cameras absent in all five samples,
zero PAD samples and no identity-embedding timing event. Confirmed return granted
in 11.844 seconds with five fresh PAD samples and one final embedding timing event.
The same candidate and enrollment served both logins. An initial enrollment was
retried after the user moved away before completion; both attempts were retained
in local aggregate evidence. No installed enrollment/configuration/binary changed,
and candidate/enrollment cleanup, camera release and installed service state were
independently verified.

These observations apply to the complete dependency chain. They are single-user,
condition-specific observations, not a broad reliability result or end-to-end
speedup benchmark. Dim-light validation was explicitly skipped and remains
untested. No per-species APCER/BPCER study, installed-desktop unlock qualification,
elevation qualification or spoof-resistance certification is claimed. Remote CI
and MSRV lanes must run on the eventual PR commits.
