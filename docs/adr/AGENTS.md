# AGENTS.md: architecture decision records

The root [AGENTS.md](../../AGENTS.md) applies. ADRs record security-posture and
design decisions. Weakening a guarantee (votes, budgets, modes, authorization
posture) needs an ADR ([docs/CODE_REVIEW.md](../CODE_REVIEW.md)); other
security-posture changes (grant arms, consent, rate limits, fallbacks) usually
do, so sketch one in the PR early ([CONTRIBUTING.md](../../CONTRIBUTING.md)
"Changes that touch cameras, PAM, or the daemon").

## Recipe: write an ADR

1. Take the next number after the highest file here; 0022 is reserved
   ([docs/README.md](../README.md)). Name the file `NNNN-kebab-title.md` and
   title it `# ADR-NNNN: Title`.
2. Use the sections of ADR-0021 onward: `## Status` (Proposed or Accepted, the
   date, and what it amends, supersedes or depends on), `## Context`,
   `## Decision` with numbered `### 1.` subsections (ADR-0024, 0025, 0030) or
   numbered bold items (ADR-0029), `## Consequences`, optionally `## Phasing`,
   and `## Acceptance tests` (ADR-0024 onward). ADR-0020 and older use bold
   `**Status:**` and `**Date:**` lines, and ADR-0007 and 0008 plain `Status:`
   and `Date:` lines and a `# ADR 0007:` title; do not copy those forms.
3. Prefer landing it alone, before the implementation, as
   `docs(adr): ADR-NNNN <title>` (#799, #807, #810, #812); ADR-0026 and ADR-0027
   shipped with their implementation (#802, #806), so ask the maintainer which
   the change needs. Implementation PRs and CHANGELOG entries then cite
   `ADR-NNNN §x`.
4. Record a later change as a dated `## Amendment YYYY-MM-DD: ...` section
   (ADR-0021). When a new ADR makes it, name the amended ADR in the new one's
   Status (ADR-0027) and add a dated "Amended by ADR-NNNN" note at the changed
   text of the old one (ADR-0020).
5. Plain punctuation, no em dashes (CONTRIBUTING.md "Writing style").

Before camera or TUI work, read ADR-0007, 0023, 0024, 0027, 0028, 0029 and
0030; before camera work, also ADR-0020 and 0021.
