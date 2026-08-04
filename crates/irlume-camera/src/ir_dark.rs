//! Why an IR burst is not a usable scene, named from evidence, not guessed.
//!
//! `capture_with_stats` used to answer every dark burst with one hint: "no
//! active emitter; run `sudo irlume ir-setup`". A dark IR frame has at least
//! six causes and that advice fits exactly one of them; for a covered sensor,
//! an out-of-range subject or an emitter firing uselessly into a bright room
//! it sends the user to write to camera firmware for a problem that is not
//! there (#185). And the most common cover case is not dark at all: an opaque
//! cover under an active emitter reflects it straight back and SATURATES the
//! sensor (#197, measured on both test cameras). The capture path already
//! holds the evidence to do better: whether irlume drove the control this
//! stream, the camera's own per-frame illumination metadata (#167), the
//! privacy control where the camera publishes one, and the chosen frame's
//! mean and spread.
//!
//! The decision is a pure function over that evidence, so every arm is
//! testable without a camera, and the renderer returns the full message so
//! wording and advice stay in one place.

/// The dark gate: below this mean a burst is dark and gets a diagnosis.
/// Public so the call site's shortcut range and this module's real gate are
/// one constant and cannot drift apart.
pub const DARK_MEAN_MAX: f64 = 35.0;

/// At or above this mean the frame is treated as saturated. Covered chosen
/// frames measured 252.8 (NexiGo, its clip point) to 255.0 (ASUS) across
/// twelve runs; the brightest real scene this hardware has ever measured is
/// 168 (`ir_emitter` records it), so 250 sits far from both.
pub const SATURATED_MIN_MEAN: f64 = 250.0;

/// A saturated frame at or below this spread is a constant, not a scene.
/// Measured covered chosen frames: stddev 0.00 (ASUS, fully clipped), 0.76
/// (NexiGo at its 252.8 clip), up to 3.63 mid auto-exposure walk-down; real
/// scenes measure 35 and up. Deliberately wider than "exactly constant":
/// saturation clips UNEVENLY on the NexiGo (0.76 at its 252.8 clip point),
/// so a zero floor would miss a fully covered camera there.
const SATURATED_FLAT_MAX: f64 = 8.0;

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
    /// Mean of the chosen frame.
    pub frame_mean: f64,
    /// Pixel standard deviation of the chosen frame.
    pub frame_stddev: f64,
    /// Mean of the BRIGHTEST frame in the burst. Inter-frame evidence the
    /// diagnosis lacked (#264): a strobing emitter interleaves lit and
    /// ambient frames, so a dark CHOSEN frame beside a bright burst maximum
    /// means the emitter fired and selection (or clipping demotion, #221)
    /// landed elsewhere; the BRIO measured lit 54-128 against ambient 0.6-1.7
    /// with no irlume write at all, while the old evidence read its ambient
    /// phase as a dead emitter and recommended a firmware write.
    pub burst_max_mean: f64,
}

/// The named cause of a dark IR burst, most specific evidence first.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IrDarkCause {
    /// The privacy control reads engaged: the sensor is blanked by the shutter.
    PrivacyEngaged,
    /// The frame is saturated AND nearly constant: on both test cameras this
    /// matched an opaque cover directly in front of the active emitter,
    /// reflecting it straight back (measured 252.8-255.0 covered, twelve runs;
    /// see `SATURATED_MIN_MEAN`/`SATURATED_FLAT_MAX` for the floors). A
    /// saturated frame WITH texture is a scene, extremely close and bright,
    /// and gets no diagnosis.
    SaturatedFlat {
        stddev: f64,
        frames_lit: usize,
        frames_classified: usize,
    },
    /// The camera marked frames as captured with illumination ON, yet the
    /// image stayed dark. The Microsoft metadata reports the illumination
    /// STATE; it does not measure optical output, so a failed LED and a
    /// covered lens are both still in play (#196 review).
    LitButDark {
        frames_lit: usize,
        frames_classified: usize,
    },
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
    /// The chosen frame is dark but the burst holds a bright frame: light
    /// reached the sensor this capture, so the emitter works (a strobing
    /// module interleaves lit and ambient phases) and the question is frame
    /// SELECTION, never the firmware. Advising `ir-setup` here is the #185
    /// wrong-turn this module exists to end (#264).
    LitBurstDarkChoice { burst_max_mean: f64 },
    /// The control is active, the camera supplies no metadata, and the frame
    /// carries real signal: the evidence cannot separate an emitter the
    /// camera ignored from a subject out of range or a genuinely dark scene.
    Undetermined,
}

/// Name the cause of an unusable burst, or `None` for a scene. Self-gating:
/// the two bands that carry a diagnosis are dark (mean below `DARK_MEAN_MAX`)
/// and saturated-flat (`SATURATED_MIN_MEAN` up, spread under
/// `SATURATED_FLAT_MAX`); everything else is a frame to authenticate against,
/// not to explain. The call site may skip building evidence for frames
/// outside both bands; that shortcut must agree with the gates here.
pub fn diagnose(e: &DarkEvidence) -> Option<IrDarkCause> {
    // An explicit output policy, not an inferred hardware cause: the user
    // said "drive nothing", and every line below is chatter they opted out
    // of, so it precedes every diagnosis that would speak (#196 review).
    if e.emitter_disabled {
        return match () {
            _ if e.frame_mean < DARK_MEAN_MAX || saturated_flat(e) => {
                Some(IrDarkCause::EmitterDisabled)
            }
            _ => None,
        };
    }
    if e.frame_mean >= SATURATED_MIN_MEAN {
        return saturated_flat(e).then_some(IrDarkCause::SaturatedFlat {
            stddev: e.frame_stddev,
            frames_lit: e.frames_lit,
            frames_classified: e.frames_classified,
        });
    }
    if e.frame_mean >= DARK_MEAN_MAX {
        return None;
    }
    if e.privacy_engaged {
        return Some(IrDarkCause::PrivacyEngaged);
    }
    // Direct optical evidence beats every emitter inference below: a bright
    // frame ANYWHERE in the burst means light reached the sensor this
    // capture, so "no active emitter" and "ignored control" are both refuted
    // regardless of who drove the control or what the metadata says (#264).
    if e.burst_max_mean >= DARK_MEAN_MAX {
        return Some(IrDarkCause::LitBurstDarkChoice {
            burst_max_mean: e.burst_max_mean,
        });
    }
    if e.frames_lit > 0 {
        return Some(IrDarkCause::LitButDark {
            frames_lit: e.frames_lit,
            frames_classified: e.frames_classified,
        });
    }
    // No dark-flat arm. Two measured facts killed it (#198 review): a
    // genuine strobe-off exposure is itself nearly constant (mean 0.0 at
    // stddev 0.08-0.13 on both test cameras), and the one measured dark-band
    // blank, the ASUS shutter's constant 144.0, never reaches capture because
    // the privacy control refuses at open. What remained was an inference
    // about the 5-35 mean band that nothing has ever measured, so a dark flat
    // frame falls through to the emitter causes, where the advice is at least
    // grounded; the shutter keeps its named cause through the privacy
    // evidence above.
    if e.emitter_active && e.frames_classified > 0 {
        return Some(IrDarkCause::ActiveButNotReported {
            frames_classified: e.frames_classified,
        });
    }
    if !e.emitter_active {
        return Some(IrDarkCause::NoEmitterDriven);
    }
    Some(IrDarkCause::Undetermined)
}

/// Saturated and nearly constant: the measured cover-under-emitter signature.
fn saturated_flat(e: &DarkEvidence) -> bool {
    e.frame_mean >= SATURATED_MIN_MEAN && e.frame_stddev <= SATURATED_FLAT_MAX
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
        IrDarkCause::SaturatedFlat {
            stddev,
            frames_lit,
            frames_classified,
        } => Some(format!(
            "[ir] {card:?}: the IR frame is saturated and nearly constant (mean \
             {mean:.0}, stddev {stddev:.2}){}. On both tested cameras this pattern \
             matched an opaque cover directly in front of the lens{}; strong IR \
             flooding the lens could read the same (covered measured 252.8-255.0; \
             real scenes carry spread 35+). Check for a cover or anything flush \
             against the camera.",
            if *frames_lit > 0 {
                format!(", with {frames_lit}/{frames_classified} frames marked illuminated")
            } else {
                String::new()
            },
            // The reflection mechanism is asserted only when the camera says
            // its illuminator was on; a saturated frame without that flag
            // could as easily be ambient overexposure (review thread).
            if *frames_lit > 0 {
                ", bouncing the emitter straight back"
            } else {
                ""
            }
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
        IrDarkCause::LitBurstDarkChoice { burst_max_mean } => Some(format!(
            "[ir] {card:?}: the chosen IR frame is dark (mean {mean:.0}) but the burst \
             holds a lit frame (mean {burst_max_mean:.0}): the emitter works, likely \
             strobing, and frame selection landed on a dark phase. Not a firmware \
             problem; if authentication fails here, report these two numbers"
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
            frame_mean: 20.0,
            frame_stddev: 40.0,
            // As dark as the chosen frame: a whole-burst-dark baseline, so
            // each existing arm stays reachable (a bright maximum would route
            // every case into LitBurstDarkChoice by design).
            burst_max_mean: 20.0,
        }
    }

    // The measured BRIO shape (2026-08-04, #264): the strobe interleaves lit
    // frames (54-128) with ambient ones (0.6-1.7), no irlume write, and the
    // chosen frame landed dark. The old evidence called this "no active
    // emitter" and recommended a firmware write for hardware that works.
    #[test]
    fn a_lit_burst_with_a_dark_choice_names_selection_not_the_emitter() {
        let brio = DarkEvidence {
            frame_mean: 34.0,
            burst_max_mean: 128.0,
            ..textured_dark()
        };
        assert_eq!(
            diagnose(&brio),
            Some(IrDarkCause::LitBurstDarkChoice {
                burst_max_mean: 128.0
            })
        );
        let line = render("Logitech BRIO", 34.0, &diagnose(&brio).unwrap()).unwrap();
        assert!(line.contains("emitter works"), "{line}");
        assert!(
            !line.contains("ir-setup"),
            "must not point at firmware: {line}"
        );

        // Direct optical evidence outranks the metadata arms too: a bright
        // frame refutes "ignored control" as surely as "no emitter".
        assert_eq!(
            diagnose(&DarkEvidence {
                frames_lit: 3,
                frames_classified: 8,
                burst_max_mean: 90.0,
                ..textured_dark()
            }),
            Some(IrDarkCause::LitBurstDarkChoice {
                burst_max_mean: 90.0
            })
        );
        // But the shutter still wins: an engaged privacy control explains a
        // dark choice regardless of what earlier frames held.
        assert_eq!(
            diagnose(&DarkEvidence {
                privacy_engaged: true,
                burst_max_mean: 128.0,
                ..textured_dark()
            }),
            Some(IrDarkCause::PrivacyEngaged)
        );
        // And a burst that is dark END TO END (the BRIO's pre-strobe warm-up
        // window) keeps the emitter diagnosis: there is no optical evidence
        // to refute it with.
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_mean: 16.0,
                burst_max_mean: 24.0,
                ..textured_dark()
            }),
            Some(IrDarkCause::NoEmitterDriven)
        );
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
            Some(IrDarkCause::PrivacyEngaged),
            "an engaged shutter outranks even a lit flag"
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                frames_lit: 3,
                frames_classified: 8,
                frame_stddev: 0.0,
                frame_mean: 10.0,
                ..textured_dark()
            }),
            Some(IrDarkCause::LitButDark {
                frames_lit: 3,
                frames_classified: 8
            }),
            "the camera saying FIRED outranks the flat-frame inference"
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_active: true,
                frames_classified: 8,
                ..textured_dark()
            }),
            Some(IrDarkCause::ActiveButNotReported {
                frames_classified: 8
            }),
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_disabled: true,
                ..textured_dark()
            }),
            Some(IrDarkCause::EmitterDisabled),
        );
        assert_eq!(
            diagnose(&textured_dark()),
            Some(IrDarkCause::NoEmitterDriven)
        );
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
            frame_mean: 20.0,
            frame_stddev: 0.0,
            // A bright maximum too: `off` must silence even the optical arm.
            burst_max_mean: 128.0,
        })
        .expect("a dark burst under off still resolves, to a silent cause");
        assert_eq!(off, IrDarkCause::EmitterDisabled);
        assert!(render("cam", 20.0, &off).is_none());
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_active: true,
                ..textured_dark()
            }),
            Some(IrDarkCause::Undetermined),
            "active control, no metadata, real signal: the honest answer is no answer"
        );
    }

    /// The self-gate: scenes get no diagnosis, in both directions. A textured
    /// mid frame is an authentication subject; a SATURATED textured frame is a
    /// close bright subject, not a cover (#197: covers measured stddev 0.00
    /// to 3.63, scenes 35+).
    #[test]
    fn scenes_are_not_diagnosed() {
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_mean: 100.0,
                ..textured_dark()
            }),
            None,
            "a mid-brightness textured frame is a scene"
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_mean: 252.0,
                frame_stddev: 40.0,
                emitter_active: true,
                frames_lit: 5,
                frames_classified: 10,
                ..textured_dark()
            }),
            None,
            "a saturated frame WITH texture is a close subject, not a cover"
        );
        // Off is silent for scenes too, and resolves for both covered bands.
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_disabled: true,
                frame_mean: 100.0,
                ..textured_dark()
            }),
            None
        );
        // Flat at MID brightness is unmeasured territory: neither band claims
        // it (the 144 shutter blank never reaches capture on cameras with a
        // privacy control, and no other mid-flat source has been measured).
        // This row pins the saturated floor at its measured height.
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_mean: 200.0,
                frame_stddev: 0.5,
                ..textured_dark()
            }),
            None
        );
    }

    /// The measured cover signature: saturated and nearly constant fires on
    /// the exact chosen-frame values from the #197 measurement runs, on both
    /// cameras, including the NexiGo's non-zero clip spread that the dark
    /// flat floor would have missed.
    #[test]
    fn the_measured_covers_are_named_and_off_still_silences_them() {
        for (mean, sd) in [(255.0, 0.0), (252.8, 0.76), (254.7, 3.63)] {
            let cause = diagnose(&DarkEvidence {
                frame_mean: mean,
                frame_stddev: sd,
                emitter_active: true,
                frames_lit: 5,
                frames_classified: 10,
                ..textured_dark()
            })
            .unwrap_or_else(|| panic!("covered at mean {mean} stddev {sd} must be named"));
            assert_eq!(
                cause,
                IrDarkCause::SaturatedFlat {
                    stddev: sd,
                    frames_lit: 5,
                    frames_classified: 10
                }
            );
            let msg = render("cam", mean, &cause).expect("the cover speaks");
            assert!(msg.contains("saturated and nearly constant"), "{msg}");
            assert!(
                !msg.contains("ir-setup"),
                "no firmware advice for a cover: {msg}"
            );
            assert!(
                msg.contains("bouncing the emitter"),
                "lit flags support the mechanism: {msg}"
            );
        }
        {
            // Without lit flags the mechanism claim must vanish: saturation
            // could be ambient overexposure, and the message may only name
            // the pattern (review thread on this PR).
            let msg = render(
                "cam",
                255.0,
                &IrDarkCause::SaturatedFlat {
                    stddev: 0.0,
                    frames_lit: 0,
                    frames_classified: 0,
                },
            )
            .expect("still speaks");
            assert!(!msg.contains("bouncing the emitter"), "{msg}");
            assert!(!msg.contains("marked illuminated"), "{msg}");
        }
        assert_eq!(
            diagnose(&DarkEvidence {
                emitter_disabled: true,
                frame_mean: 255.0,
                frame_stddev: 0.0,
                ..textured_dark()
            }),
            Some(IrDarkCause::EmitterDisabled),
            "off silences the saturated band too"
        );
    }

    /// Near-zero flatness is what clean darkness looks like (measured mean
    /// 0.0 at stddev 0.08-0.13 on both cameras), so it falls through to the
    /// emitter causes instead of claiming a cover; the informative flat band
    /// (the 144 shutter blank) still names one.
    #[test]
    fn near_zero_flat_is_darkness_not_a_cover() {
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_mean: 0.0,
                frame_stddev: 0.1,
                ..textured_dark()
            }),
            Some(IrDarkCause::NoEmitterDriven),
            "a flat zero frame with no emitter is a dark room, and ir-setup is right"
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_mean: 0.0,
                frame_stddev: 0.1,
                emitter_active: true,
                frames_classified: 10,
                ..textured_dark()
            }),
            Some(IrDarkCause::ActiveButNotReported {
                frames_classified: 10
            }),
        );
        assert_eq!(
            diagnose(&DarkEvidence {
                frame_mean: 20.0,
                frame_stddev: 0.0,
                ..textured_dark()
            }),
            Some(IrDarkCause::NoEmitterDriven),
            "a dark flat frame carries no measured cover signature (#198 review: \
             the only measured dark-band blank never reaches capture), so the \
             emitter causes answer"
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
            (
                IrDarkCause::SaturatedFlat {
                    stddev: 0.0,
                    frames_lit: 5,
                    frames_classified: 10,
                },
                false,
            ),
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

    /// The arithmetic separates a constant sample from a non-constant one,
    /// against the saturated floor that now carries the flat inference.
    #[test]
    fn frame_stddev_classifies_constant_and_nonconstant_samples() {
        assert_eq!(frame_stddev(&[255; 1000]), 0.0);
        // Alternating values two apart: stddev 1.0.
        let noisy: Vec<u8> = (0..1000)
            .map(|i| if i % 2 == 0 { 19 } else { 21 })
            .collect();
        assert!(frame_stddev(&noisy) > 0.5);
        assert_eq!(frame_stddev(&[]), 0.0);
    }
}
