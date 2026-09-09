# IR identity acceptance evidence

The optional IR-only login workflow needs empirical coverage of both existing
identity acceptance rules. The diagnostic currently collapses these into one
candidate category, so a live campaign cannot establish that coverage.

Add one bounded `identity_acceptance` field to diagnostic schema 4: `best_template`,
`centroid`, or `both` only when the final category is `candidate_match`; otherwise
null. Report which predicates actually passed, not which branch happened to run
first. Preserve the current finite-score checks, thresholds, profile/template
scaling, enrollment compatibility, capture path and PAD policy. A cancelled or
expired attempt must clear acceptance evidence even if identity finished.

The wrapper accepts exact schemas 1, 2, 3 and 4. Historical reports remain
immutable. Schema 4 retains all fifteen capture timing fields and enforces the
category/acceptance relationship. No score, name, embedding, image, free-form
error, additional model or dependency is introduced. Diagnostic results never
authorize authentication or credential release.

This is a prerequisite deliverable, not the IR-only granting integration. The
broader workflow tracks qualification, opt-in policy integration, Windows Hello
lessons and unresolved audit findings separately. Dual-camera authentication
remains the default; stock-desktop experimental hands-free remains retired.
