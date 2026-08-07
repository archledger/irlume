# MediaPipe latency on archhost, re-run at the merged default (3 runs)

Date: 2026-08-07. Machine: archhost (AMD Ryzen 7 5700G), main `e59f935`,
the first measurement since the native-mesh switch (#315) merged. Full
CSVs: `2026-08-07-mp-latency-archhost-run{1,2,3}.csv`. Three runs because
one run is not a latency claim: the 2026-08-06 measurements saw ort move
36% between runs on this machine.

Input frame: `zenbook/frontal/rgb/rgb00.ppm` from the stage-3 corpus.
Models pinned by the harness (`mp_latency_bench`).

What the runs show, run 2 and 3 agreeing within 2% on every row (run 1's
detection rows carry cold-cache noise):

- Native 478-point mesh: 4.52 to 4.54 ms at 2 threads, 3.05 to 3.06 ms at
  4, against 7.44 to 7.46 ms for the ONNX 468 mesh. The production choice
  (tflite, 2 threads) keeps its ~1.6x advantage after the merge.
- Short-range BlazeFace: ort stays ahead on this CPU (0.86 to 0.88 ms vs
  1.13 ms tflite at 2 threads), the reversal of the Zenbook ordering
  first seen in the LFW run. tflite at 4 threads (0.72 to 0.73 ms) beats
  both, unchanged.
- Blendshapes: 1.376 to 1.380 ms across all three runs, the steadiest row
  in the table.

No production default changes from this: it confirms the merged
configuration measures on archhost as the pre-merge branch did.
