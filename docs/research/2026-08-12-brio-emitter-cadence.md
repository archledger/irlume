# Brio emitter output against capture cadence

Date: 2026-08-12, 14:43-14:46 EDT. Instrument: `ir_strobe_probe` (36-frame
raw bursts on /dev/video2, GREY) at repo `5f7eb6b`, the archhost Logitech
BRIO (046d:085e) on USB3. Room lighting uncontrolled and LIT (ambient-phase
mean near 30; the 2026-08-07 dark-room runs read 0.6 to 1.7), so absolute
levels are not comparable with the dark-room decay observation this
campaign was designed to chase; the cadence CONTRAST within the campaign is
the measurement. Lit-phase mean = mean of burst frames above the burst's
min/max midpoint (18 of 36 frames in every burst).

| burst | regime | lit-phase mean | ambient-phase mean |
|---|---|---|---|
| A1 | back-to-back | 83.8 | 37.9 |
| A2 | back-to-back | 62.1 | 28.4 |
| A3-A8 | back-to-back | 66.4 to 67.0 | 30.4 to 30.8 |
| B1 | after 90s idle | 65.8 | 29.9 |
| C1-C6 | 15s gaps | 65.8 to 66.8 | 29.9 to 30.6 |

Raw per-frame means: 21 bursts in the session record
(`2026-08-12-brio-cadence` in the research store; first line of each burst
names the phase).

## Reading

- No cadence-dependent emitter depression at the minutes scale: eight
  sustained back-to-back bursts hold lit-phase mean within 0.6 of the paced
  regime's, and 90 seconds of idle produces no rebound. The three regimes
  are indistinguishable.
- The first burst of the session read high (83.8 lit, 37.9 ambient) and the
  second low (62.1) before settling; both phases moved together, which
  points at exposure settling or scene, not the emitter. Recorded, not
  explained.
- For #264 this eliminates the last proposed mechanism reachable by
  measurement here. The 224-toward-36 morning decay of 2026-08-07 was
  observed across hours in a dark room and remains unexplained; nothing in
  it is currently distinguishable from lighting or scene drift, and no
  diagnosis keyed on an uncharacterised effect would be more than a guess.
