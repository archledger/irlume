# Brio emitter output against capture cadence

Date: 2026-08-12, 14:43-14:46 EDT. Instrument: `ir_strobe_probe` (36-frame
raw bursts on /dev/video2, GREY) at repo `5f7eb6b`, the archhost Logitech
BRIO (046d:085e) on USB3. Room lighting uncontrolled and LIT (ambient-phase
mean near 30; the 2026-08-07 dark-room runs read 0.6 to 1.7), so absolute
levels are not comparable with the dark-room decay observation this
campaign was designed to chase; the cadence CONTRAST within the campaign is
the measurement. Lit-phase mean = mean of burst frames above the burst's
min/max midpoint (18 of 36 frames in every burst).

| burst | regime | lit-phase mean | ambient-phase mean | lit minus ambient |
|---|---|---|---|---|
| A1 | back-to-back | 83.8 | 37.9 | 45.8 |
| A2 | back-to-back | 62.1 | 28.4 | 33.7 |
| A3-A8 | back-to-back | 66.4 to 67.0 | 30.4 to 30.8 | 35.9 to 36.2 |
| B1 | after 90s idle | 65.8 | 29.9 | 35.9 |
| C1-C6 | 15s gaps | 65.8 to 66.8 | 29.9 to 30.6 | 35.8 to 36.3 |

Raw per-frame means: 21 bursts in the session record
(`2026-08-12-brio-cadence` in the research store; first line of each burst
names the phase). The paired lit-minus-ambient differential is the column
the probe's own documentation names as isolating the emitter's
contribution; the review round on this document caught the first draft
reading raw lit-phase means instead.

## Reading

- After the session's first two bursts, the paired lit-minus-ambient
  differential holds between 35.8 and 36.3 across all three regimes: eight
  back-to-back bursts, the single post-idle burst, and six bursts at
  15-second gaps. Total lit-phase brightness overlaps the same way. Within
  this session, no cadence association appears in either the total
  brightness or the emitter-isolated differential.
- What this does not establish: equivalence of the regimes (the post-idle
  arm has one burst), and it does not close out mechanisms outside the
  tested envelope, since room lighting was uncontrolled and a synchronised
  ambient drift compensating an emitter change, however unlikely, is not
  excluded by one session.
- The first burst read 83.8 lit over 37.9 ambient (differential 45.8) and
  the second 62.1 over 28.4 (33.7) before the differential settled. The
  cause was not identified; both phases moved together, and the
  differential moved too. Recorded, not explained.
- For #264: the minutes-scale cadence mechanism, the thread's last open
  proposal, shows no effect in this session's differential. The
  224-toward-36 morning decay of 2026-08-07 was observed across hours in a
  dark room and remains unexplained; nothing currently distinguishes it
  from lighting or scene drift, and no diagnosis keyed on an
  uncharacterised effect would be more than a guess.
