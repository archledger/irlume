# Credits

irlume relies on models and code from other projects. Each bundled model's
licence ships with the package; this page names the projects and what they do.

The bundled models:

- **[YuNet](https://github.com/opencv/opencv_zoo)** (OpenCV Zoo, MIT) detects faces in both streams.
- **[AuraFace](https://huggingface.co/fal/AuraFace-v1)** by fal (Apache-2.0) is the 512-D ArcFace recognizer; irlume ships only its `glintr100.onnx`.
- **[MediaPipe FaceLandmarker](https://ai.google.dev/edge/mediapipe/solutions/vision/face_landmarker)** and **[BlazeFace short-range](https://ai.google.dev/edge/mediapipe/solutions/vision/face_detector)** (Google, Apache-2.0) supply the dense landmarks behind blink liveness, and the detection-rescue stage for saturated frames.

The TPM and camera code builds on:

- **[rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi)** (Parsec, Apache-2.0) wraps TPM 2.0 ESAPI; irlume builds from a small patch branch pinned to an exact commit.
- **[systemd](https://github.com/systemd/systemd)** (LGPL-2.1-or-later): the Tier-2 pcrlock seal follows the scheme in its `tpm2-util.c` and `pcrlock.c`.
- **[linux-enable-ir-emitter](https://github.com/EmixamPP/linux-enable-ir-emitter)** first showed the 850nm emitter can be driven from userspace over UVC Extension Units. irlume no longer uses its search technique, which destroyed a camera here ([#159](https://github.com/archledger/irlume/issues/159)).
- **[ort](https://github.com/pykeio/ort)** binds ONNX Runtime, which irlume loads at runtime.
- **[TensorFlow Lite](https://github.com/tensorflow/tensorflow)** (Apache-2.0) is bundled as a C runtime; its statically linked components are named in the notices beside it.

Prior art: **Windows Hello** for the infrared dual-sensor credential model, and
[Howdy](https://github.com/boltgolt/howdy) and [visage](https://github.com/sovren-software/visage)
as the existing Linux face-unlock projects. irlume is the from-scratch successor
to the author's earlier linhello.

*Windows and Windows Hello are trademarks of Microsoft Corporation. irlume is an
independent project, not affiliated with or endorsed by Microsoft; the marks are
used only to describe compatibility and prior art.*
