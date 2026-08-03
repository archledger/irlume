# Centre/edge ratio corpus, 2026-08-02

Captured with `irlume padcapture` (the real `LivenessGate`) on the ASUS FHD IR pin,
GREY8 640x400, dark room, one subject, glasses noted per batch. Raw records in
`2026-08-02-center-edge-corpus.jsonl`. This is the evidence for raising
`MIN_CENTER_EDGE_RATIO` from 1.03 to 1.25 (#235).

| kind | species | n | ratio min | ratio max | called Live |
|---|---|---|---:|---:|---:|
| attack | print_vinyl_close | 12 | 1.12 | 1.21 | 12 |
| attack | print_vinyl_normal | 12 | 1.02 | 1.16 | 10 |
| bonafide | live_close | 12 | 1.26 | 1.37 | 10 |
| bonafide | live_far | 12 | 1.36 | 1.41 | 12 |
| bonafide | live_normal_glasses | 12 | 1.40 | 1.47 | 12 |
| bonafide | live_normal_noglasses | 12 | 1.40 | 1.43 | 12 |
| bonafide | live_offangle | 12 | 1.43 | 1.49 | 12 |

Against the 1.03 floor in place at capture time, 22 of 24 print presentations
were accepted as Live. The print's ceiling was 1.21; the lowest genuine capture that
passed liveness read 1.31. Any floor from 1.22 to 1.30 separates the two populations
completely here, and 1.25 was chosen near the middle.

One subject, one camera, one room, one attack medium. A glossy print was not
captured; the 2026-06-30 result used one and cleared the old floor 69 times in 70.
