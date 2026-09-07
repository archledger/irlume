# Complete RGB PAD admission

Authentication and one-scan enrollment require the existing five-score RGB PAD
vote before visible-light admission. Pending evidence is retryable; unusable
evidence resets the vote. Pending RGB evidence cannot hide a required IR PAD
refusal at admission. Vote size,
median, thresholds, matching and the independent dark IR route are unchanged.

Fresh authentication verification: 160 passed, zero failed, three existing ignored.
Regression tests exercise the actual voting and admission code with synthetic
identity inputs: incomplete votes, interrupted evidence, a completed-vote outlier,
spoof decisions and required PAD failures. The regressions failed before the fix.

This is admission-correctness evidence, not a per-species presentation-attack
study. No APCER/BPCER result or spoof-resistance certification is claimed.
