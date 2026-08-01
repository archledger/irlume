//! Why an IR burst came back dark, named from evidence instead of guessed.
//!
//! `capture_with_stats` used to answer every dark burst with one hint: "no
//! active emitter; run `sudo irlume ir-setup`". A dark IR frame has at least
//! six causes and that advice fits exactly one of them; for a covered sensor,
//! an out-of-range subject or an emitter firing uselessly into a bright room
//! it sends the user to write to camera firmware for a problem that is not
//! there (#185). The capture path already holds the evidence to do better:
//! whether irlume drove the control this stream, the camera's own per-frame
//! illumination metadata (#167), the privacy control where the camera
//! publishes one, and the chosen frame's pixel statistics.
//!
//! The decision is a pure function over that evidence, so every arm is
//! testable without a camera, and the renderer returns the full message so
//! wording and advice stay in one place.

/// The chosen frame's pixel standard deviation below which it is treated as a
/// firmware-substituted blank rather than a dark scene. Measured on the ASUS
/// 3277:0059 (#186, eight frames per state): an engaged shutter's blank is a
/// constant 144.0 with a standard deviation of exactly 0.00, six runs out of
/// six, while every real scene measured there reads 34 or higher. The floor
/// only has to sit between "exactly constant" and "carries any signal at all";
/// 0.5 is an order of magnitude from both measurements.
const FLAT_STDDEV_MAX: f64 = 0.5;

/// What the capture path observed about a dark burst. Every field is a plain
/// value so [`diagnose`] stays pure.
#[derive(Debug, Clone, Copy)]
pub struct DarkEvidence {
    /// The emitter control is active for this stream (irlume applied it, or it
    /// already held the wanted value). `StreamMode::lit`.
    pub emitter_active: bool,
    /// `IRLUME_IR_EMITTER=off`: the user told irlume to drive nothing.
    pub emitter_disabled: bool,
    /// The V4L2 privacy control read engaged. `false` covers released, absent
    /// AND unreadable alike: this is a diagnosis, not an authorization, and
    /// only a positive reading is evidence of a cause (the firmware-write
    /// paths make the three-way distinction; see `privacy_permits_setup`).
    pub privacy_engaged: bool,
    /// Burst frames the camera's illumination metadata flagged LIT (#167).
    pub frames_lit: usize,
    /// Burst frames carrying any illumination metadata at all.
    pub frames_classified: usize,
    /// Pixel standard deviation of the chosen frame.
    pub frame_stddev: f64,
}

/// The named cause of a dark IR burst, most specific evidence first.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IrDarkCause {
    /// The privacy control reads engaged: the sensor is blanked by the shutter.
    PrivacyEngaged,
    /// The camera marked frames as captured with illumination ON, yet the
    /// image stayed dark. The Microsoft metadata reports the illumination
    /// STATE; it does not measure optical output, so a failed LED and a
    /// covered lens are both still in play (#196 review).
    LitButDark {
        frames_lit: usize,
        frames_classified: usize,
    },
    /// The decoded frame is nearly constant. Evidence of a FLAT OUTPUT, not
    /// by itself evidence of why: the blank-vs-scene gap behind
    /// `FLAT_STDDEV_MAX` was measured on one camera, and an ISP may clamp a
    /// genuinely dark scene to a constant (#196 review).
    FlatFrame { stddev: f64 },
    /// The requested control value was ACTIVE for the stream (irlume wrote
    /// it, or it was already held: `StreamMode::lit` does not distinguish),
    /// but no classified frame was marked illuminated. Whether the camera
    /// ignored the mode, the emitter failed, or the metadata did not reflect
    /// the control cannot be told apart from here (#196 review).
    ActiveButNotReported { frames_classified: usize },
    /// The user set `IRLUME_IR_EMITTER=off`; a dark frame is the configured
    /// outcome, and saying anything would be noise they opted out of.
    EmitterDisabled,
    /// No emitter was driven and nothing else explains the darkness: the one
    /// case where `ir-setup` is the right advice. Never
    /// `linux-enable-ir-emitter`: that tool finds a control by writing
    /// invented payloads across units and selectors until the picture
    /// brightens, the exact search irlume removed from its own code after it
    /// destroyed a reporter's camera (#159). `ir-setup` does the same job
    /// from the camera's own descriptor and its own `GET_DEF` values.
    NoEmitterDriven,
    /// The control is active, the camera supplies no metadata, and the frame
    /// carries real signal: the evidence cannot separate an emitter the
    /// camera ignored from a subject out of range or a genuinely dark scene.
    Undetermined,
}

/// Name the cause of a dark burst. Pure; the caller decides whether the burst
/// was dark at all (the `IR_DARK_HINT_MAX` gate, unchanged).
pub fn diagnose(e: &DarkEvidence) -> IrDarkCause {
    // An explicit output policy, not an inferred hardware cause: the user
    // said "drive nothing", and every line below is chatter they opted out
    // of, so it precedes every diagnosis that would speak (#196 review).
    if e.emitter_disabled {
        return IrDarkCause::EmitterDisabled;
    }
    if e.privacy_engaged {
        return IrDarkCause::PrivacyEngaged;
    }
    if e.frames_lit > 0 {
        return IrDarkCause::LitButDark {
            frames_lit: e.frames_lit,
            frames_classified: e.frames_classified,
        };
    }
    if e.frame_stddev < FLAT_STDDEV_MAX {
        return IrDarkCause::FlatFrame {
            stddev: e.frame_stddev,
        };
    }
    if e.emitter_active && e.frames_classified > 0 {
        return IrDarkCause::ActiveButNotReported {
            frames_classified: e.frames_classified,
        };
    }
    if !e.emitter_active {
        return IrDarkCause::NoEmitterDriven;
    }
    IrDarkCause::Undetermined
}

/// The user-facing line for a cause, or `None` where silence is the right
/// output (`EmitterDisabled`: the hint's own text has always promised that
/// `off` silences it, and this is where the promise is kept).
pub fn render(card: &str, mean: f64, cause: &IrDarkCause) -> Option<String> {
    match cause {
        IrDarkCause::PrivacyEngaged => Some(format!(
            "[ir] {card:?}: IR is dark because the privacy shutter is engaged (the \
             `privacy` control reads 1); release it. No emitter problem is in evidence."
        )),
        IrDarkCause::LitButDark {
            frames_lit,
            frames_classified,
        } => Some(format!(
            "[ir] {card:?}: the camera marked {frames_lit}/{frames_classified} frames \
             as captured with illumination on, yet the image stayed dark (mean \
             {mean:.0}). That metadata does not measure optical output, so irlume \
             cannot distinguish a failed or ignored emitter from a lens cover, range, \
             or exposure problem. Check the cover, distance and exposure; if those do \
             not explain it, `sudo irlume ir-setup` re-measures the control."
        )),
        IrDarkCause::FlatFrame { stddev } => Some(format!(
            "[ir] {card:?}: the IR frame is nearly constant (mean {mean:.0}, stddev \
             {stddev:.2}). On the tested ASUS camera this matched a privacy-blanked \
             frame, but pixel variance alone cannot distinguish a blanked or covered \
             sensor from camera processing of a dark scene. Check the privacy shutter \
             and lens cover; if neither explains it, move closer and re-test."
        )),
        IrDarkCause::ActiveButNotReported { frames_classified } => Some(format!(
            "[ir] {card:?}: the emitter control held the requested value, but none of \
             {frames_classified} metadata-classified frames was marked as captured \
             with illumination on. The evidence cannot tell whether the camera \
             ignored the mode, the emitter failed, or the metadata does not reflect \
             the control. `sudo irlume ir-setup` re-measures the control."
        )),
        IrDarkCause::EmitterDisabled => None,
        IrDarkCause::NoEmitterDriven => Some(format!(
            "[ir] {card:?}: IR is dark (mean {mean:.0}) with no active emitter; run \
             `sudo irlume ir-setup` to find this camera's emitter control from what it \
             publishes (IRLUME_IR_EMITTER=off silences this)"
        )),
        IrDarkCause::Undetermined => Some(format!(
            "[ir] {card:?}: IR is dark (mean {mean:.0}) with the emitter control \
             active; this camera supplies no illumination metadata, so irlume cannot \
             tell an ignored control from a subject out of range or a dark scene. If \
             moving closer changes nothing, `sudo irlume ir-setup` re-measures the \
             control."
        )),
    }
}

/// Pixel standard deviation of one 8-bit frame.
pub fn frame_stddev(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let n = data.len() as f64;
    let mean = data.iter().map(|&p| f64::from(p)).sum::<f64>() / n;
    let var = data
        .iter()
        .map(|&p| {
            let d = f64::from(p) - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    var.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn textured_dark() -> DarkEvidence {
        DarkEvidence {
            emitter_active: false,
            emitter_disabled: false,
            privacy_engaged: false,
            frames_lit: 0,
            frames_classified: 0,
            frame_stddev: 40.0,
        }
    }

    /// Each cause is reachable, and the precedence follows evidence
    /// specificity: a positive shutter reading beats everything, the camera
    /// saying "fired" beats inference, a flat frame beats metadata absence.
    #[test]
    fn each_cause_is_reachable_and_ordered_by_evidence() {
        assert_eq!(
            diagnose(&DarkEvidence {
                privacy_engaged: true,
                frames_lit: 3,
                ..textured_dark()
            }),
            IrDarkCause::PrivacyEngaged,
            "an engaged shutter outranks even a lit flag"
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                frames_lit: 3,
                frames_classified: 8,
                frame_stddev: 0.0,
                ..textured_dark()
            }),
            IrDarkCause::LitButDark {
                frames_lit: 3,
                frames_classified: 8
            },
            "the camera saying FIRED outranks the flat-frame inference"
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_stddev: 0.0,
                emitter_active: true,
                frames_classified: 8,
                ..textured_dark()
            }),
            IrDarkCause::FlatFrame { stddev: 0.0 },
            "a flat frame outranks active-but-not-reported"
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_active: true,
                frames_classified: 8,
                ..textured_dark()
            }),
            IrDarkCause::ActiveButNotReported {
                frames_classified: 8
            },
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_disabled: true,
                ..textured_dark()
            }),
            IrDarkCause::EmitterDisabled,
        );
        assert_eq!(diagnose(&textured_dark()), IrDarkCause::NoEmitterDriven);
        // `off` is an output policy, not an inferred cause: it silences every
        // other observation, through the production precedence, because the
        // render-only check could not fail when diagnose never picked it
        // (#196 review).
        let off = diagnose(&DarkEvidence {
            emitter_active: false,
            emitter_disabled: true,
            privacy_engaged: true,
            frames_lit: 8,
            frames_classified: 8,
            frame_stddev: 0.0,
        });
        assert_eq!(off, IrDarkCause::EmitterDisabled);
        assert!(render("cam", 20.0, &off).is_none());
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_active: true,
                ..textured_dark()
            }),
            IrDarkCause::Undetermined,
            "active control, no metadata, real signal: the honest answer is no answer"
        );
    }

    /// `off` genuinely silences the output. The old hint PROMISED this in its
    /// own text and did not do it: with the override set to off the emitter is
    /// inert, `lit` is false, and the hint printed anyway, naming the very
    /// variable that was already set.
    #[test]
    fn disabled_renders_nothing_and_ir_setup_is_advised_only_where_it_helps() {
        assert!(render("cam", 20.0, &IrDarkCause::EmitterDisabled).is_none());
        for (cause, wants_setup) in [
            (IrDarkCause::NoEmitterDriven, true),
            (
                IrDarkCause::LitButDark {
                    frames_lit: 3,
                    frames_classified: 8,
                },
                false,
            ),
            (IrDarkCause::PrivacyEngaged, false),
            (IrDarkCause::FlatFrame { stddev: 0.0 }, false),
        ] {
            let msg = render("cam", 20.0, &cause).expect("these causes all speak");
            assert_eq!(
                msg.contains("run `sudo irlume ir-setup` to find"),
                wants_setup,
                "ir-setup discovery advice on the wrong cause sends a user to write \
                 firmware for a problem that is not there: {msg}"
            );
        }
    }

    /// The metadata flag reports illumination STATE; the message must not
    /// claim measured optical output, and must not rule the emitter out
    /// (#196 review: a failed LED sets the flag and emits nothing).
    #[test]
    fn lit_metadata_does_not_claim_measured_optical_output() {
        let msg = render(
            "cam",
            20.0,
            &IrDarkCause::LitButDark {
                frames_lit: 3,
                frames_classified: 8,
            },
        )
        .unwrap();
        assert!(msg.contains("captured with illumination on"), "{msg}");
        assert!(msg.contains("does not measure optical output"), "{msg}");
        assert!(!msg.contains("light is leaving"), "{msg}");
        assert!(!msg.contains("will not help"), "{msg}");
    }

    /// The arithmetic separates a constant sample from a non-constant one.
    /// That is ALL it establishes: the hardware meaning of a constant frame
    /// is measured on one camera and worded accordingly in the renderer.
    #[test]
    fn frame_stddev_classifies_constant_and_nonconstant_samples() {
        assert_eq!(frame_stddev(&[144; 1000]), 0.0);
        assert!(frame_stddev(&[144; 1000]) < FLAT_STDDEV_MAX);
        // Alternating values two apart: stddev 1.0, above the floor.
        let noisy: Vec<u8> = (0..1000)
            .map(|i| if i % 2 == 0 { 19 } else { 21 })
            .collect();
        assert!(frame_stddev(&noisy) > FLAT_STDDEV_MAX);
        assert_eq!(frame_stddev(&[]), 0.0);
    }
}
