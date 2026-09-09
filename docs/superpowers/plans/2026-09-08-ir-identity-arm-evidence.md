# IR identity acceptance evidence implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Make both IR identity acceptance rules observable during qualification without disclosing biometric scores.

**Architecture:** Extend the existing non-granting diagnostic and strict Python consumer together. Keep one identity predicate implementation and carry its bounded result through final deadline/cancellation admission.

**Tech Stack:** Existing Rust 1.88 workspace and Python 3 standard-library harness; no new dependencies.

**Spec:** ../specs/2026-09-08-ir-identity-arm-evidence-design.md

## Global Constraints

- Preserve dual-camera authentication, thresholds, PAD, enrollment, retry and credential-release behavior.
- Schema 4 accepts `identity_acceptance` values `best_template`, `centroid`, `both` for `candidate_match` only; all other categories require null.
- Preserve exact historical schemas 1, 2 and 3 and all fifteen schema-3 capture timing fields.
- No scores, names, embeddings, images, free-form errors, extra crates or dependencies.
- Keep work local and uncommitted; preserve the existing unpublished changes and durable attempt ledgers.

### Task 1: Emit and validate acceptance evidence

**Files:**
- Modify/test: crates/irlume-auth/src/ir_only_evaluation.rs
- Modify: scripts/ir-evaluation/harness.py
- Test: scripts/ir-evaluation/test_harness.py
- Modify: scripts/ir-evaluation/README.md
- Modify: docs/IR_ONLY_QUALIFICATION.md
- Modify: docs/research/2026-09-08-ir-only-evaluation.md

**Interfaces:**
- Consume existing `IrMatch`, `EvaluationStages::identify`, `Report::to_json`, and `checked_report(record)`.
- Produce a typed acceptance result from the same `identity_category` predicates; no second independent threshold implementation. Change the private stage interface as needed so acceptance travels with the category. The public report exposes a bounded optional enum, not arbitrary strings.

- [ ] Add Rust regression tests for each truth-table case, both matching thresholds, adapter selection and no compatible templates. Use synthetic `IrMatch` values and actual `scaled_threshold` boundaries. Preserve existing tests.

```rust
// Test vectors: neither predicate, best only, centroid only, both.
// Set best to threshold +/- 0.01 and centroid to its separate threshold +/- 0.01.
// Assert serialized identity_acceptance equals null, best_template, centroid, both.
// Infinity/NaN never counts as a passing predicate.
```

- [ ] Add strict Python schema-4 positive/negative tests, including unknown labels, boolean/numeric/list/dict values, missing/extra keys, candidate/null and noncandidate/non-null contradictions; preserve schemas 1/2/3 tests.

```python
record = dict(schema3_record, schema=4, category="candidate_match", identity_acceptance="centroid")
assert harness.checked_report(record) == record
for invalid in (None, "unknown", True, 1, [], {}):
    with self.assertRaises(ValueError):
        harness.checked_report(dict(record, identity_acceptance=invalid))
```

- [ ] Run targeted new tests before implementation and retain expected failure evidence. Implement schema 4 with the exact vocabulary above and clear acceptance evidence on every final interruption/refusal. Extend cancellation/expiry stage tests to verify null evidence after a late match; verify a completed candidate retains its arm.
- [ ] Run auth feature library/examples tests and Python discovery, Rust 1.88 feature Clippy, rustdoc with warnings denied, formatter, Ruff lint/format and git diff whitespace checks. Use CARGO_BUILD_JOBS=4 and ORT_DYLIB_PATH=/usr/share/irlume/onnxruntime/lib/libonnxruntime.so. Commands execute in the absolute worktree.

```bash
cargo +1.88.0 test --locked -p irlume-auth --features ir-only-evaluation --lib --examples
python3 -m unittest discover -s scripts/ir-evaluation -p 'test_*.py'
cargo +1.88.0 clippy --locked -p irlume-auth -p irlume-camera --features irlume-auth/ir-only-evaluation --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +1.88.0 doc --locked -p irlume-auth --features ir-only-evaluation --no-deps
cargo +1.88.0 fmt --all -- --check
```

- [ ] Update current contributor documentation for schema 4 and explain that instrumenting acceptance enables empirical coverage but does not itself supply it. Correct the stale schema-1 description in the diagnostic research guide while preserving historical evidence.
- [ ] Self-review necessity and privacy, then deliver exact changed-file hashes, incremental patch against the pre-task files, commands/results and concerns. Parent dispatches independent spec/quality review. Do not commit or run cameras.
