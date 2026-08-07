// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlumed`: the privileged daemon. Owns the camera + models and is the only
//! component that runs the biometric pipeline. Untrusted clients (`pam_irlume`,
//! the CLI) connect over a Unix socket and send line-delimited JSON requests;
//! the daemon authenticates each peer with `SO_PEERCRED` before honoring
//! privileged operations (enroll/delete).
//!
//! Single-threaded by design: the camera is a single shared resource, so
//! requests are served one at a time.

use irlume_common::{Request, Response, SOCKET_PATH};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

mod arbiter;
mod users;

/// Release checksums of the bundled models (models/SHA256SUMS, committed next
/// to the weights and embedded at build time).
const MODEL_MANIFEST: &str = include_str!("../../../models/SHA256SUMS");

/// Hash each configured model file and compare against the release manifest.
/// Matching by digest (not filename) so packaging renames stay irrelevant.
/// Unknown weights WARN by default: operators legitimately deploy self-trained
/// adapters, and refusing to start would turn a model swap into a lockout.
/// `IRLUME_MODELS_STRICT=1` upgrades the warning to a startup refusal.
///
/// `keep` names the one model the caller wants back, returned with the digest
/// this function checked and only when the file was actually read (an
/// unreadable model in non-strict mode returns `None` and the loader reports
/// it). The recognizer is what the daemon asks for: without this the 260MB file
/// was read and sha256'd here, then read and sha256'd AGAIN inside
/// [`irlume_auth::Engine::load`] (#346). Handing the checked artifact over is
/// also the stronger guarantee, because what reaches the ONNX session is then
/// what this digest was taken from, with no window for a swap in between.
fn verify_models(paths: &[&str], keep: Option<&str>) -> Option<irlume_common::HashedModel> {
    let known: std::collections::HashSet<&str> = MODEL_MANIFEST
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    let strict = std::env::var("IRLUME_MODELS_STRICT")
        .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"));
    let mut kept = None;
    for path in paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                // Strict must also catch a *deleted* model: silently skipping
                // would let removal (not just tampering) downgrade liveness.
                if strict {
                    eprintln!(
                        "irlumed: IRLUME_MODELS_STRICT: cannot read model {path} ({e}); refusing to start"
                    );
                    std::process::exit(1);
                }
                // Without strict, the loader reports missing/optional models.
                continue;
            }
        };
        // Hashed once, here: the digest checked below is the same one the
        // engine tags the embedding space with (#346).
        let model = irlume_common::HashedModel::new(bytes);
        let digest = model.sha256();
        if !known.contains(digest) {
            eprintln!(
                "irlumed: WARNING: {path} does not match any release model checksum (sha256 {digest})"
            );
            if strict {
                eprintln!(
                    "irlumed: IRLUME_MODELS_STRICT=1: refusing to start with unverified models"
                );
                std::process::exit(1);
            }
            eprintln!(
                "irlumed: continuing with unverified weights (expected for custom or \
                 self-trained models; set IRLUME_MODELS_STRICT=1 to refuse instead)"
            );
        }
        // After the checks, so what is handed back is what this loop hashed
        // and (in strict mode) accepted.
        if keep == Some(*path) {
            kept = Some(model);
        }
    }
    kept
}

/// Build the engine on the SHIPPED-recognizer path.
///
/// `verified` carries what [`verify_models`] already read and checksummed at
/// startup; handing it to the weights loader is what makes a start read and
/// sha256 the 260MB recognizer once instead of twice (#346). It is also the
/// tighter guarantee: [`irlume_auth::Engine::load`] re-opens the path, so a file
/// swapped between the check and the load would reach the session unverified.
///
/// `None` is the camera worker's post-panic rebuild, which pays the read as it
/// always has. Keeping the 260MB buffer alive for the daemon's whole life to
/// save that one re-read would cost more resident memory than the entire rest
/// of the process, so startup drops it as soon as the session owns its copy.
fn load_shipped_recognizer(
    det_path: &str,
    model_path: &str,
    verified: Option<&irlume_common::HashedModel>,
) -> irlume_common::Result<irlume_auth::Engine> {
    match verified {
        Some(weights) => irlume_auth::Engine::load_with_recognizer_weights(det_path, weights),
        None => irlume_auth::Engine::load(det_path, model_path),
    }
}

/// The model files to checksum-verify at startup. det/model/mesh/blaze ship
/// with every package, so a missing one is a broken install
/// (IRLUME_MODELS_STRICT rightly refuses). The IR adapter is optional (none
/// ships since ADR-0004; user supplies their own via IRLUME_IR_ADAPTER), so it
/// is included only when the file actually exists; otherwise strict mode would
/// refuse to start on a normal install that never had an adapter.
fn models_to_verify<'a>(shipped: [&'a str; 4], adapter: &'a str) -> Vec<&'a str> {
    let mut v: Vec<&str> = shipped.to_vec();
    if std::path::Path::new(adapter).exists() {
        v.push(adapter);
    }
    v
}

/// Resolve the opt-in third-party RECOGNIZER selection (#276 stage 4), or EXIT.
///
/// The failure policy is the opposite of the PAD cue's fall-back-to-nothing:
/// an explicit `third_party_recognizer` selection is an authentication-policy
/// choice, and silently substituting the shipped recognizer would run a
/// DIFFERENT grant-capable decision system against the templates the operator
/// kept. Any invalid explicit selection refuses to start; PAM treats an
/// unavailable daemon as password fallback, so fail-closed means "password",
/// never lockout. `None` = nothing selected, use the shipped default. The
/// returned VERIFIED WEIGHTS are what the engine must load: re-reading the path
/// later (or at a post-panic rebuild) would let a swap pair new weights with
/// the threshold measured for the old ones. They carry the digest checked here,
/// so the engine tags the embedding space without hashing them again (#346).
fn resolve_thirdparty_recognizer() -> Option<(irlume_common::HashedModel, f32, String)> {
    std::env::var("IRLUME_THIRDPARTY_RECOGNIZER")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            irlume_common::config::read_kv(
                "settings.conf",
                irlume_common::thirdparty::RECOGNIZER_SETTINGS_KEY,
            )
        })
        .map(|name| {
            let name = name.trim().to_string();
            let entry = irlume_common::thirdparty::recognizer_override(
                irlume_common::thirdparty::by_name(&name),
            )
            .unwrap_or_else(|why| {
                eprintln!(
                    "irlumed: third_party_recognizer='{name}' refused ({why:?}); refusing to start so face auth falls back to the password"
                );
                std::process::exit(1);
            });
            let path = irlume_common::thirdparty::model_path(entry);
            let bytes = std::fs::read(&path).unwrap_or_else(|e| {
                eprintln!(
                    "irlumed: third-party recognizer '{name}' selected but {} unreadable ({e}); refusing to start so face auth falls back to the password",
                    path.display()
                );
                std::process::exit(1);
            });
            let weights = irlume_common::HashedModel::new(bytes);
            if weights.sha256() != entry.sha256 {
                eprintln!(
                    "irlumed: third-party recognizer '{name}' checksum mismatch (sha256 {}); refusing to start so face auth falls back to the password",
                    weights.sha256()
                );
                std::process::exit(1);
            }
            (weights, entry.threshold, entry.name.to_string())
        })
}

/// The explicit third-party DETECTOR selection, same contract and same
/// fail-closed rule as the recognizer above: an invalid selection refuses to
/// start (PAM reads an absent daemon as password fallback), a valid one
/// returns the VERIFIED bytes plus the entry's measured threshold and name.
/// The wiring target is the RESCUE slot only; YuNet stays primary.
fn resolve_thirdparty_detector() -> Option<(Vec<u8>, f32, String)> {
    irlume_common::config::read_kv(
        "settings.conf",
        irlume_common::thirdparty::DETECTOR_SETTINGS_KEY,
    )
    .filter(|v| !v.trim().is_empty())
    .map(|name| {
        let name = name.trim().to_string();
        let entry = irlume_common::thirdparty::detector_override(
            irlume_common::thirdparty::by_name(&name),
        )
        .unwrap_or_else(|why| {
            eprintln!(
                "irlumed: third_party_detector='{name}' refused ({why:?}); refusing to start so face auth falls back to the password"
            );
            std::process::exit(1);
        });
        let path = irlume_common::thirdparty::model_path(entry);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            eprintln!(
                "irlumed: third-party detector '{name}' selected but {} unreadable ({e}); refusing to start so face auth falls back to the password",
                path.display()
            );
            std::process::exit(1);
        });
        let digest = irlume_common::thirdparty::sha256_hex(&bytes);
        if digest != entry.sha256 {
            eprintln!(
                "irlumed: third-party detector '{name}' checksum mismatch (sha256 {digest}); refusing to start so face auth falls back to the password"
            );
            std::process::exit(1);
        }
        (bytes, entry.threshold, entry.name.to_string())
    })
}

fn main() {
    // FIRST, before models load. The watchdog deadline starts ticking the moment
    // systemd execs us, and loading the ONNX sessions takes tens of seconds on a
    // cold cache; starting the pings after that made the daemon miss its own
    // deadline during startup and get killed in a restart loop (measured with
    // WatchdogSec=10s). An idle worker reports healthy, which is exactly right
    // for a daemon that is still coming up. No-op unless the unit asked for a
    // watchdog, so a hand-run daemon and the tests are unaffected (#141).
    spawn_watchdog();
    let det = env_or("IRLUME_DET_MODEL", "/etc/irlume/det.onnx");
    let model = env_or("IRLUME_MODEL", "/etc/irlume/face.onnx");
    let adapter = env_or("IRLUME_IR_ADAPTER", "/etc/irlume/ir_adapter.onnx");
    let mesh = env_or(
        "IRLUME_MESH_MODEL",
        "/etc/irlume/face_landmarks_detector.tflite",
    );
    let blaze = env_or(
        "IRLUME_BLAZE_MODEL",
        "/etc/irlume/blaze_face_short_range.onnx",
    );
    let socket = std::env::var("IRLUME_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());

    // PREFER THE SOCKET SYSTEMD ALREADY BOUND, else bind our own.
    //
    // Startup loads models and walks enrollments before this point could ever be
    // reached by a self-bind, and greeters are ordered after basic.target, well
    // before multi-user.target. Measured on a ThinkPad X13: the greeter
    // authenticated a fingerprint 8 seconds before the socket existed, so
    // pam_irlume had nothing to connect to and the login proceeded with the
    // keyring locked and nothing in any log (#244). With irlumed.socket,
    // systemd owns the socket from sockets.target onward and the request waits
    // in the backlog instead of being refused.
    //
    // Self-binding stays for anyone running the daemon directly (development,
    // a distro without the socket unit installed, IRLUME_SOCKET pointing
    // somewhere else in a test).
    let listener = match inherited_listener() {
        Some(l) => {
            eprintln!("irlumed: using the socket systemd bound (socket activation)");
            l
        }
        None => {
            let _ = std::fs::remove_file(&socket);
            match UnixListener::bind(&socket) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("irlumed: cannot bind {socket}: {e}");
                    std::process::exit(1);
                }
            }
        }
    };
    // The mode goes on with the bind, not at the accept loop: a socket that
    // exists but is 0600 refuses exactly the non-root clients this early bind
    // exists to admit. The reasoning for 0666 is at the accept loop below.
    // Only ours to set when we bound it; under socket activation the mode came
    // from SocketMode= in the unit, and chmod'ing systemd's socket behind its
    // back would drift from what the unit says.
    if !socket_activated() {
        set_mode(&socket, DAEMON_SOCKET_MODE);
    }
    eprintln!("irlumed: socket ready at {socket}; requests queue while startup finishes");

    // The engine is built OFF the startup path, so the socket is not merely
    // bound early but SERVED early.
    //
    // Loading models and walking every enrollment costs seconds (21 from exec to
    // serving on a ThinkPad X13), and a greeter authenticating inside that window
    // used to find nobody listening at all (#244). Doing it here lets `main` fall
    // straight through to the accept loop below, so early connections are read
    // and answered rather than piling up in the kernel backlog: keyring release
    // needs no engine and is served, everything else is told the daemon is
    // starting and falls through to the password.
    let engine_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let arbiter = std::sync::Arc::new(arbiter::Arbiter::<Queued>::new());
    {
        let arbiter = std::sync::Arc::clone(&arbiter);
        let engine_ready = std::sync::Arc::clone(&engine_ready);
        std::thread::Builder::new()
            .name("irlume-startup".into())
            .spawn(move || {
            eprintln!("irlumed: loading models (det={det}, model={model})…");
            // The recognizer's verified bytes come back and go straight into the
            // engine below (#346), so the 260MB file is read and hashed once per
            // start rather than once here and once again inside the loader.
            let mut verified_recognizer =
                verify_models(&models_to_verify([&det, &model, &mesh, &blaze], &adapter), Some(&model));
            // Auto-select the camera pair: explicit IRLUME_RGB_DEVICE/IR_DEVICE, else a
            // discovered Hello camera (built-in or external Brio/NexiGo), else defaults.
            let (rgb_dev, ir_dev) = irlume_auth::select_pair();
            // Log what is actually usable, not the raw (possibly fallback) selection;
            // on camera-less or RGB-only hardware the fixed default pair doesn't exist.
            {
                let ok = |d: &str| std::path::Path::new(d).exists();
                match (ok(&rgb_dev), ok(&ir_dev)) {
                    (true, true) => eprintln!("irlumed: cameras rgb={rgb_dev} ir={ir_dev} (secure tier)"),
                    (true, false) => eprintln!(
                        "irlumed: camera rgb={rgb_dev}, no IR node (convenience tier: screen unlock only)"
                    ),
                    (false, _) => eprintln!(
                        "irlumed: no camera found (face auth unavailable; password/fingerprint only)"
                    ),
                }
            }
            // Re-apply the KNOWN emitter control at startup. The emitter is camera
            // hardware state that resets on a USB/power cycle or a daemon restart, so
            // without this the first auth after a restart gets a dark IR frame (the
            // "worked at enroll, failed at the lock screen" case).
            //
            // This used to fall through to a blind search when IR came back dark, which
            // is what destroyed a reporter's camera in #159. A daemon start is not
            // consent to write guessed values to camera firmware, and darkness does not
            // even imply the emitter is the problem: an unlit room or an empty chair
            // produces exactly the same measurement. Discovery now happens only when
            // someone runs `irlume ir-setup` and accepts the warning.
            if std::path::Path::new(&ir_dev).exists() {
                match irlume_auth::apply_known_ir_emitter(&ir_dev) {
                    Ok(true) => eprintln!("irlumed: IR emitter ready"),
                    Ok(false) => eprintln!(
                        "irlumed: IR is dark (dark-mode unlock may be unavailable). If this camera needs an \
                         emitter control irlume does not know, run `sudo irlume ir-setup`."
                    ),
                    Err(e) => eprintln!("irlumed: IR emitter check skipped: {e}"),
                }
            }
            // Opt-in third-party PAD cue (`irlume models`): enabled via settings.conf,
            // weights fetched by the CLI to the state dir. Unlike the shipped models'
            // warn-first verification, a third-party file MUST match its catalog pin:
            // on any mismatch the cue is skipped (the built-in gate alone is the safe
            // default), never trusted. Env override for sandboxes.
            let tp_pad: Option<(String, f32, String)> = std::env::var("IRLUME_THIRDPARTY_PAD")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .or_else(|| {
                    irlume_common::config::read_kv("settings.conf", irlume_common::thirdparty::SETTINGS_KEY)
                })
                .and_then(|name| {
                    let Some(entry) = irlume_common::thirdparty::by_name(name.trim()) else {
                        eprintln!("irlumed: WARNING: third_party_pad='{name}' is not in the catalog; ignoring");
                        return None;
                    };
                    // The settings key names a PAD cue; wiring any other stage
                    // here would run, say, a recognizer as an anti-spoof score.
                    // The installer refuses closed stages too, but this key is
                    // root-editable text, so the daemon checks what it loads.
                    if entry.stage != irlume_common::thirdparty::Stage::Pad {
                        eprintln!(
                            "irlumed: WARNING: third_party_pad='{name}' is a {} model, not a PAD cue; ignoring",
                            entry.stage.as_str()
                        );
                        return None;
                    }
                    let path = irlume_common::thirdparty::model_path(entry);
                    let bytes = match std::fs::read(&path) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!(
                                "irlumed: WARNING: third-party PAD '{name}' enabled but {} unreadable ({e}); cue disabled (run `sudo irlume models enable {name}` to re-fetch)",
                                path.display()
                            );
                            return None;
                        }
                    };
                    let digest = irlume_common::thirdparty::sha256_hex(&bytes);
                    if digest != entry.sha256 {
                        eprintln!(
                            "irlumed: WARNING: third-party PAD '{name}' checksum mismatch (sha256 {digest}); cue DISABLED, refusing to load unpinned weights"
                        );
                        return None;
                    }
                    Some((
                        path.to_string_lossy().into_owned(),
                        entry.threshold,
                        entry.name.to_string(),
                    ))
                });
            // Opt-in third-party RECOGNIZER (#276 stage 4). Same trust chain
            // as the PAD cue — catalog entry, stage check, pinned checksum —
            // but the failure policy is the opposite of the cue's: an explicit
            // third_party_recognizer selection is an authentication-policy
            // choice, and silently substituting the shipped recognizer would
            // run a DIFFERENT grant-capable decision system against the
            // templates the operator kept. Any invalid selection refuses to
            // start; PAM treats an unavailable daemon as password fallback, so
            // fail-closed here means "password", never lockout. Absence of
            // the setting selects the shipped default as always. The VERIFIED
            // BYTES are retained and handed to the engine: re-reading the path
            // at load (or at a post-panic rebuild) would let a swap pair new
            // weights with the threshold measured for the old ones. The stage
            // gate refuses until Stage::Recognition opens, so today an
            // explicit selection always refuses.
            let tp_rec: Option<(irlume_common::HashedModel, f32, String)> =
                resolve_thirdparty_recognizer();
            let tp_det: Option<(Vec<u8>, f32, String)> = resolve_thirdparty_detector();
            // A third-party selection replaces the shipped recognizer outright,
            // so the shipped bytes are dead weight from here on; free them
            // before the load instead of carrying 260MB through it.
            if tp_rec.is_some() {
                verified_recognizer = None;
            }
            // Engine factory: (re)loads the models and rebinds devices/adapters. Used
            // once at startup and again by the camera worker to rebuild the engine after
            // a caught panic, so a fresh request never runs against ONNX sessions left in
            // an unproven state by an unwind. It owns its inputs so it can move to the
            // worker thread, and it is Fn, so startup calls it before that move.
            //
            // `recognizer` is what startup already read, hashed and verified
            // (#346); the worker's post-panic rebuild passes None and re-reads
            // the path, which is why the closure takes it as an argument instead
            // of capturing it and holding 260MB for the daemon's life.
            let build_engine = move |recognizer: Option<&irlume_common::HashedModel>| {
                match &tp_rec {
                    // The RETAINED verified bytes, not the path: a post-panic
                    // rebuild must run exactly the artifact the pin check saw.
                    Some((weights, thr, name)) => {
                        irlume_auth::Engine::load_with_recognizer_weights(&det, weights).map(|e| {
                            eprintln!(
                                "irlumed: third-party recognizer '{name}' loaded (threshold {thr}; IR matching disabled — unmeasured for this model)"
                            );
                            e.with_thirdparty_recognizer(*thr, name)
                        })
                    }
                    None => load_shipped_recognizer(&det, &model, recognizer),
                }
                    .map(|e| e.with_devices(&rgb_dev, &ir_dev))
                    .and_then(|e| e.with_ir_adapter(&adapter))
                    .and_then(|e| e.with_mesh(&mesh))
                    .and_then(|e| match &tp_det {
                        Some((bytes, thr, name)) => {
                            eprintln!(
                                "irlumed: third-party detector '{name}' loaded into the RESCUE slot (threshold {thr}; YuNet stays primary)"
                            );
                            e.with_full_range_rescue(bytes, *thr, name)
                        }
                        None => e.with_blaze_rescue(&blaze),
                    })
                    .and_then(|e| match &tp_pad {
                        Some((path, thr, name)) => e.with_thirdparty_pad(path, *thr, name),
                        None => Ok(e),
                    })
            };
            // Bits are published before the socket binds (bind happens after the
            // models load), so no connection can observe the default EngineBits.
            let mut engine = match build_engine(verified_recognizer.as_ref()) {
                Ok(e) => {
                    eprintln!(
                        "irlumed: IR adapter {}",
                        if e.has_ir_adapter() {
                            "loaded"
                        } else {
                            "absent (raw IR)"
                        }
                    );
                    eprintln!(
                        "irlumed: FaceMesh (passive liveness) {}",
                        if e.has_mesh() { "loaded" } else { "absent" }
                    );
                    // Name the occupant: since #295 the rescue slot holds
                    // either the shipped short-range model or an enabled
                    // third-party one, and a line that always says
                    // "BlazeFace" is the stale-claim shape reviewers keep
                    // finding.
                    eprintln!(
                        "irlumed: rescue detector {}",
                        match (e.has_blaze_rescue(), e.thirdparty_detector_name()) {
                            (_, Some(name)) => format!("'{name}' (third-party, full-range)"),
                            (true, None) => "BlazeFace short-range (shipped)".to_string(),
                            (false, None) => "absent".to_string(),
                        }
                    );
                    match e.thirdparty_pad_name() {
                        Some(n) => eprintln!(
                            "irlumed: third-party PAD cue '{n}' loaded (deny-only; disable with `sudo irlume models disable`)"
                        ),
                        // A gap worth naming at every start: the built-in gate accepts
                        // a life-size print of the enrolled face (docs/PAD_SELFTEST.md),
                        // and this cue is the only measured defence against one.
                        None => eprintln!(
                            "irlumed: third-party PAD cue: none. The built-in gate does NOT stop a \
                             life-size print of your face; `sudo irlume models enable flir` adds the \
                             cue that does"
                        ),
                    }
                    e
                }
                Err(e) => {
                    eprintln!("irlumed: failed to load models: {e}");
                    std::process::exit(1);
                }
            };
            // ORT copied the weights into its own session at commit time, so
            // this buffer is 260MB of dead memory from here on: release it
            // before the enrollment sweep rather than at the end of startup.
            drop(verified_recognizer);
            publish_engine_bits(&engine);

            // One-time inoculation: stamp legacy (untagged) IR scans with the current
            // embedding space while it is still the space they were captured under.
            // A later adapter swap/removal then degrades to a clear "re-enroll" for
            // dark unlock instead of silently scoring across embedding spaces.
            // Skip the whole sweep once it has completed for this embedding
            // space. Asking a user whether they need a retag costs a TPM unseal,
            // because the answer is inside the encrypted enrollment, and the TPM
            // serializes: that startup work collided with the very login it was
            // delaying, taking a keyring unseal from 2.70s to 18.97s on a
            // discrete TPM (#249). The marker only skips work; a missing or
            // stale one just runs the sweep as before.
            let retag_space = engine.ir_space().to_string();
            let sweep_needed = !irlume_core::storage::retag_done_for(&retag_space);
            if !sweep_needed {
                irlume_common::dlog!(
                    "startup: IR retag already done for '{retag_space}'; skipping the sweep"
                );
            }
            // A user whose load or save failed has NOT been swept, and marking
            // the space done would retire the migration for them permanently:
            // the marker is only written when every user was actually handled.
            let mut all_swept = true;
            for user in irlume_core::storage::list_users() {
                if !sweep_needed {
                    break;
                }
                let loaded = irlume_core::storage::load(&user);
                if let Err(ref e) = loaded {
                    eprintln!(
                        "irlumed: could not read '{user}' during the IR retag sweep ({e}); \
                         leaving the sweep owed"
                    );
                    all_swept = false;
                }
                if let Ok(Some(mut enr)) = loaded {
                    let n = enr.retag_untagged_ir(engine.ir_space(), engine.ir_dim());
                    if n > 0 {
                        match irlume_core::storage::save(&enr) {
                            Ok(()) => eprintln!(
                                "irlumed: tagged {n} legacy IR scan(s) for '{user}' as '{}'",
                                engine.ir_space()
                            ),
                            Err(e) => {
                                eprintln!(
                                    "irlumed: could not retag IR scans for '{user}': {e}"
                                );
                                all_swept = false;
                            }
                        }
                    }
                    // Upgrade notice: IR scans enrolled under a now-absent adapter (e.g.
                    // 0.1.x -> 0.2.0, where the research-only IR adapter was removed) are
                    // in a foreign embedding space and cannot match. Bright-light RGB
                    // login still works; dark/dim login needs a re-enroll. Surfaced here
                    // (journal, and `irlume logs`) because the daemon restarts on upgrade.
                    // Only an OUTAGE gets the notice: once the user re-enrolls, the fresh
                    // usable scans coexist with the stale ones (whose RGB templates still
                    // help), and nagging them to re-run the remedy they already ran is
                    // noise on every restart.
                    let stale = enr.stale_ir_scans(engine.ir_space());
                    if stale > 0 && enr.usable_ir_scans(engine.ir_space()) == 0 {
                        eprintln!(
                            "irlumed: NOTE for '{user}': {stale} IR template(s) were enrolled under a \
                             removed IR adapter and no longer match. Bright-light face login still works; \
                             run `irlume enroll` to capture fresh scans into your existing profile and \
                             restore dark/dim login."
                        );
                    }
                }
            }
            // Recorded only after a sweep that actually reached every user, so a
            // TPM error or an unwritable enrollment leaves the migration owed
            // instead of silently retiring it for that user.
            if sweep_needed && all_swept {
                irlume_core::storage::mark_retag_done(&retag_space);
            } else if sweep_needed {
                eprintln!(
                    "irlumed: the IR retag sweep did not complete for every user; \
                     it will run again next start"
                );
            }

            // SO_PEERCRED is the authorization boundary, and the socket mode must not
            // pretend to be a second one.
            //
            // This was `0660 root:irlume` whenever an `irlume` group existed. That gate
            // blocked every client it was supposed to admit. The group is created by
            // packaging with no members, and nothing adds any: the KDE lock screen runs
            // `kscreenlocker_greet` (not setuid) as the user, so its `pam_irlume.so`
            // got `connect() = EACCES` and face unlock silently fell through to the
            // password. `irlume detect` exited 10 (partial) as a user and 0 (ready) as
            // root on the same healthy box. A gate that stops every intended non-root
            // client is not defence in depth.
            //
            // Membership cannot fix it either: supplementary GIDs are process
            // credentials set at login, so adding a uid to the group does not reach an
            // already-running desktop (see newgrp(1)).
            //
            // Note what the affected surface actually is, because it is not the login
            // greeters. SDDM authenticates in `sddm-helper`, GDM in
            // `gdm-session-worker`, LightDM in `lightdm --session-child`, and greetd in
            // its session worker; all four keep uid 0 through `pam_authenticate` and
            // drop privileges only when starting the session, so a dedicated `sddm` or
            // `gdm` account never reached this socket in the first place. The surfaces
            // that broke are the ones where the user's own process drives PAM: the KDE
            // lock screen, and the CLI.
            //
            // 0666 plus connect-time peer credentials is the ordinary Linux pattern for
            // this: it is systemd's own documented default for filesystem sockets
            // (`SocketMode=` in systemd.socket(5)), pcscd ships the same, and the D-Bus
            // system bus is world-connectable with authorization done in the service.
            // `SO_PEERCRED` is supplied by the kernel at connect() time and a client
            // cannot forge it through protocol input (unix(7)). fprintd, the closest
            // analogue, likewise keeps its endpoint reachable and authorizes per method.
            //
            // What this widens is reachability, not authority: every request still
            // requires peer uid 0 or `target == peer`, root-only operations stay
            // root-only, requests are bounded to MAX_REQUEST_BYTES with read/write
            // deadlines, each connection is isolated behind catch_unwind, and camera
            // work carries a per-uid throttle. On Fedora the SELinux module remains the
            // mandatory-access layer.
            eprintln!("irlumed: serving on {socket} (0666; SO_PEERCRED authorizes every request)");
            if irlume_common::dbglog::on() {
                eprintln!("irlumed: diagnostic tracing ON (IRLUME_LOG=debug): per-stage pipeline lines follow; numbers only, never frames/embeddings");
            }

            // Socket watchdog: if our socket file is deleted/replaced out from under us
            // (a stale-runtime cleanup, a botched reinstall), the bound fd keeps working
            // but no client can ever connect again: a silent outage. Detect it and exit
            // so systemd (Restart=on-failure) re-binds a fresh socket. Self-heals what
            // the Repair tab otherwise needs a manual restart for.
            {
                let socket = socket.clone();
                std::thread::spawn(move || loop {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    if !std::path::Path::new(&socket).exists() {
                        eprintln!("irlumed: socket {socket} vanished; exiting for a clean re-bind");
                        std::process::exit(1);
                    }
                });
            }

            // One worker owns the engine, and every camera operation happens on it, so
            // nothing changes about V4L2 and ONNX being driven from a single thread.
            // What changed is that connections are read elsewhere, which is the only way
            // an authentication can overtake work already queued: a request nobody has
            // read yet cannot be prioritised.
            let _worker = {
                let arbiter = std::sync::Arc::clone(&arbiter);
                std::thread::Builder::new()
                    .name("irlume-camera".into())
                    .spawn(move || {
                        // The engine asks this between whole captures, so a long
                        // enrolment yields the camera to an authentication instead of
                        // making it wait for ten scans.
                        let token = arbiter.cancel_token();
                        // The engine polls this between whole captures, which makes it
                        // the one place that distinguishes a long-but-healthy job from a
                        // capture stuck inside a driver call. The watchdog (#141) reads
                        // the same signal, so both agree on what "still working" means.
                        engine.set_stop_signal(std::sync::Arc::new(move || {
                            note_worker_progress();
                            token.stop_requested()
                        }));
                        while let Some(job) = arbiter.take() {
                            note_worker_progress();
                            let Queued { req, peer, reply } = job.payload;
                            // Isolate each request behind catch_unwind. A panic deep in
                            // frame decode or inference (e.g. a V4L2 driver echoing back
                            // a 0-dimension or short-buffered frame) must deny THIS one
                            // request and let PAM fall back to the password, never
                            // unwind out of the worker and take down all face auth for
                            // every user.
                            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                dispatch(req, &peer, &mut engine)
                            }));
                            // Release the slot before anything else can fail, so a
                            // panicking request cannot lock its uid out of the camera
                            // until the daemon restarts.
                            arbiter.finish(job.class, job.uid);
                            let resp = match outcome {
                                Ok(resp) => resp,
                                Err(_) => {
                                    eprintln!(
                                        "irlumed: request handler PANICKED; this request was denied \
                                         (PAM falls back to the password). Rebuilding the engine for a \
                                         clean state; please report this with the backtrace above."
                                    );
                                    // AssertUnwindSafe only silences the compiler, it
                                    // does not prove the ONNX sessions are in a
                                    // supported state after an unwind, so a fresh engine
                                    // removes that doubt. Chosen over exiting and
                                    // letting systemd restart because a reproducible
                                    // panic would become a restart loop that takes the
                                    // login path down entirely. If the rebuild fails,
                                    // the old engine is kept: still better than a dead
                                    // daemon.
                                    // No bytes in hand here: the startup buffer
                                    // was released once the first session owned
                                    // its copy, so this rebuild re-reads the
                                    // recognizer from disk (#346).
                                    match build_engine(None) {
                                        Ok(fresh) => {
                                            engine = fresh;
                                            publish_engine_bits(&engine);
                                            eprintln!("irlumed: engine rebuilt after panic");
                                        }
                                        Err(e) => eprintln!(
                                            "irlumed: engine rebuild after panic FAILED ({e}); continuing \
                                             with the existing engine"
                                        ),
                                    }
                                    Response::Error("request failed".into())
                                }
                            };
                            // The client may already be gone; its thread owns that.
                            let _ = reply.send(resp);
                            // Back to waiting for work: idle is healthy, and leaving the
                            // last job's timestamp behind would read as a wedge (#141).
                            note_worker_idle();
                        }
                    })
                    .unwrap_or_else(|e| {
                        // Without the worker nothing can be served, and a daemon that
                        // accepts connections it can never answer is worse than one that
                        // exits and lets systemd restart it.
                        eprintln!("irlumed: could not start the camera worker: {e}");
                        std::process::exit(1);
                    })
            };
                // Published LAST: until this flips, `serve` answers from the
                // engine-free path. Release pairs with the Acquire load there,
                // so a thread that sees `true` also sees the worker it needs.
                engine_ready.store(true, std::sync::atomic::Ordering::Release);
            })
            .unwrap_or_else(|e| {
                eprintln!("irlumed: could not start the startup thread: {e}");
                std::process::exit(1);
            });
    }

    // A cap on connection threads, so a peer that opens sockets faster than it
    // sends requests cannot exhaust memory. Well above any real client: the
    // greeter, the lock screen, a TUI and sudo together are a handful.
    const MAX_CONNECTION_THREADS: usize = 64;
    /// Slots an unprivileged peer may not take. The greeter, the lock screen
    /// and a sudo stack together are a handful, so a small reserve is enough to
    /// keep the login path answerable while an unprivileged peer floods.
    const ROOT_RESERVED_SLOTS: usize = 16;
    let live_threads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // How long a throttled connection is held before being closed, and how many
    // may be held at once. The hold is what actually paces an abusive peer: its
    // request never gets a reply, so its own loop waits. The cap bounds the file
    // descriptors one peer can pin; past it, connections are closed immediately.
    const REFUSAL_PENALTY: std::time::Duration = std::time::Duration::from_millis(250);
    const MAX_PENALTY_BOX: usize = 64;
    // Shared with a janitor thread, because draining only when the NEXT
    // connection arrives is wrong in exactly the case that matters. `accept`
    // blocks, so if the last connection to arrive is the one being held, nothing
    // wakes to release it: a throttled uid's own lock screen would sit until
    // some other client happened to connect, and PAM would wait out its whole
    // read timeout instead of the 250ms this is supposed to cost. One thread for
    // the daemon's lifetime, not one per held connection.
    let penalty_box: std::sync::Arc<std::sync::Mutex<Vec<(UnixStream, std::time::Instant)>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let box_ref = std::sync::Arc::clone(&penalty_box);
        let _ = std::thread::Builder::new()
            .name("irlume-penalty".into())
            .spawn(move || loop {
                std::thread::sleep(REFUSAL_PENALTY / 2);
                let now = std::time::Instant::now();
                let mut held = match box_ref.lock() {
                    Ok(h) => h,
                    Err(e) => e.into_inner(),
                };
                // Dropping the stream closes it, which is the moment the
                // client's blocked read returns.
                held.retain(|(_, until)| now < *until);
            });
    }

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // A peer spinning on refusals is HELD, not answered and not
                // dropped: its read blocks until the penalty expires, which
                // paces it. Dropping was measured to be worse than useless, as
                // an instant EOF just let the client reconnect sooner: 10,501
                // refusals/s became 15k connection attempts a second and the
                // daemon still burned 206% of a core. Holding costs a file
                // descriptor and no thread, no parse and no arbiter round trip.
                if peer_cred(&stream).is_ok_and(|p| refusal_throttled(p.uid)) {
                    let mut held = match penalty_box.lock() {
                        Ok(h) => h,
                        Err(e) => e.into_inner(),
                    };
                    if held.len() < MAX_PENALTY_BOX {
                        held.push((stream, std::time::Instant::now() + REFUSAL_PENALTY));
                    }
                    // Over the cap the stream is dropped here, bounding the
                    // descriptors one abusive peer can pin.
                    continue;
                }
                // Reserve the top of the pool for root.
                //
                // The cap is global, and a connection occupies a slot from
                // accept until its read times out 15 seconds later, so an
                // unprivileged peer that opens 64 sockets and sends NOTHING is
                // never charged by `refusal_throttled` (which only counts
                // arbiter refusals) and locks the socket for everyone: measured,
                // a root peer's Ping got "daemon busy" for as long as the
                // attacker held them. Root is where the login path lives, so it
                // keeps slots an ordinary uid cannot take. The fallback when the
                // peer cannot be identified is to treat it as unprivileged.
                let peer_is_root = peer_cred(&stream).is_ok_and(|p| p.uid == 0);
                let ceiling = if peer_is_root {
                    MAX_CONNECTION_THREADS
                } else {
                    MAX_CONNECTION_THREADS - ROOT_RESERVED_SLOTS
                };
                let live = std::sync::Arc::clone(&live_threads);
                if live.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= ceiling {
                    live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = respond(
                        stream,
                        &Response::Error("daemon busy: too many open connections".into()),
                    );
                    continue;
                }
                let arbiter = std::sync::Arc::clone(&arbiter);
                let engine_ready = std::sync::Arc::clone(&engine_ready);
                // A connection thread reads, parses and writes; it never touches
                // the engine, so a panic in it is contained by the thread itself
                // and the queued job (if any) is still completed and released by
                // the worker.
                if let Err(e) = std::thread::Builder::new()
                    .name("irlume-conn".into())
                    .spawn(move || {
                        if let Err(e) = serve(stream, &arbiter, &engine_ready) {
                            eprintln!("irlumed: connection error: {e}");
                        }
                        live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    })
                {
                    eprintln!("irlumed: could not start a connection thread: {e}");
                    live_threads.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            Err(e) => eprintln!("irlumed: accept error: {e}"),
        }
    }
    arbiter.close();
    // The accept loop above only ends if the listener dies; nothing to join.
}

// ---------------------------------------------------------------------------
// Consecutive-failure throttle (NIST SP 800-63B-4 s3.2.3 intent).
//
// After a run of failed face attempts, stop firing the camera on the gesture
// for a short cooldown and let PAM fall straight to the password. Deliberately
// a THROTTLE, not a hard biometric-disable: irlume's password is always the
// fallback and there is no account lockout, so the standard's disable-and-
// offer-another-factor tier would only add friction (the "other factor" that
// re-enables face IS the password the throttled user is already typing). Every
// platform (Face ID, Android, Windows Hello) also uses ~5 fails then falls to a
// non-biometric factor. State is per-user and in-memory only; a daemon restart
// clears it (there is nothing to protect on disk since the password is the
// floor). Tunable/testable via env; 0 strikes disables the throttle.
// ---------------------------------------------------------------------------
#[derive(Default)]
struct FailState {
    strikes: u32,
    cooldown_until: Option<std::time::Instant>,
}

fn rate_state() -> &'static std::sync::Mutex<std::collections::HashMap<String, FailState>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, FailState>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn rate_max_strikes() -> u32 {
    env_or("IRLUME_RATE_LIMIT", "5").parse().unwrap_or(5)
}

fn rate_cooldown() -> std::time::Duration {
    std::time::Duration::from_secs(
        env_or("IRLUME_RATE_COOLDOWN_SECS", "30")
            .parse()
            .unwrap_or(30),
    )
}

/// True when `user` is in a cooldown window: skip the camera and fall to the
/// password. Clears an expired window as a side effect.
fn rate_limited(user: &str) -> bool {
    if rate_max_strikes() == 0 {
        return false;
    }
    let mut map = rate_state().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = map.get_mut(user) {
        if let Some(until) = s.cooldown_until {
            if std::time::Instant::now() < until {
                return true;
            }
            s.cooldown_until = None;
            s.strikes = 0;
        }
    }
    false
}

/// Record a face attempt's outcome. A grant resets the user; a rejected real
/// presentation is a strike, and `rate_max_strikes()` of them starts a cooldown.
/// `faced` is the *strike-worthy* signal: it must be true for a genuine failed
/// presentation, which includes a hard spoof rejection (those return
/// `live=false, score=0`, so an earlier `live || score>0` test never struck on
/// the actual attack it is meant to throttle). Callers pass
/// `!presence_retryable(&outcome)`: false only for the retryable no-face /
/// uncertain-liveness outcomes (nobody in frame, walk-away, transient
/// uncertainty), which must never count against the user.
fn rate_record(user: &str, granted: bool, faced: bool) {
    if rate_max_strikes() == 0 {
        return;
    }
    let mut map = rate_state().lock().unwrap_or_else(|e| e.into_inner());
    let s = map.entry(user.to_string()).or_default();
    if granted {
        s.strikes = 0;
        s.cooldown_until = None;
        return;
    }
    if !faced {
        return;
    }
    s.strikes += 1;
    if s.strikes >= rate_max_strikes() {
        s.cooldown_until = Some(std::time::Instant::now() + rate_cooldown());
        s.strikes = 0;
        eprintln!(
            "irlumed: '{user}' hit {} consecutive face failures; face throttled for {}s (password still works)",
            rate_max_strikes(),
            rate_cooldown().as_secs()
        );
    }
}

/// Minimum interval in seconds between unprivileged camera probes. Two seconds
/// bounds how often one local peer can occupy the camera pipeline without
/// affecting a real login.
const CAMERA_PROBE_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

// Keep this separate from the failure throttle: these probes have no
// authentication outcome to strike or reset, and their caller identity is the
// peer uid.
type CameraProbeRateState = std::sync::Mutex<std::collections::HashMap<u32, std::time::Instant>>;

fn camera_probe_rate_state() -> &'static CameraProbeRateState {
    static S: std::sync::OnceLock<CameraProbeRateState> = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Admit and record one unprivileged camera probe atomically. Root is the
/// PAM/greeter trust boundary and must never be delayed by an unprivileged
/// convenience request.
///
/// Covers `Identify` and the dry-run emitter probe: both open the shared camera
/// node, neither has an interactive frame-rate requirement, and both are now
/// reachable by any local uid. Deliberately NOT applied to `Authenticate` (the
/// real login path, throttled instead by consecutive-failure strikes) or to
/// `PositionSample` (the framing guide needs continuous samples to give live
/// feedback, so an interval here would break enrollment).
fn camera_probe_rate_limited(uid: u32) -> bool {
    if uid == 0 {
        return false;
    }
    let now = std::time::Instant::now();
    let mut map = camera_probe_rate_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if map
        .get(&uid)
        .is_some_and(|last| now.duration_since(*last) < CAMERA_PROBE_MIN_INTERVAL)
    {
        return true;
    }
    map.insert(uid, now);
    false
}

/// Forget every recorded probe. The state is process-global, so one test's
/// dispatch would otherwise throttle the next test that uses the same uid.
#[cfg(test)]
fn clear_camera_probe_rate_state() {
    camera_probe_rate_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

/// Whether opt-in biopolicy operation-class gating is enabled. Off by default;
/// turn on via `IRLUME_ENFORCE_BIOPOLICY=1` or `enforce_biopolicy=1` in
/// `/etc/irlume/settings.conf`. When off, behaviour is unchanged.
fn biopolicy_enforced() -> bool {
    let truthy = |s: &str| matches!(s.trim(), "1" | "true" | "yes" | "on");
    if let Ok(v) = std::env::var("IRLUME_ENFORCE_BIOPOLICY") {
        return truthy(&v);
    }
    irlume_common::config::read_kv("settings.conf", "enforce_biopolicy")
        .map(|v| truthy(&v))
        .unwrap_or(false)
}

/// Peer identity from SO_PEERCRED.
#[derive(Clone)]
struct Peer {
    uid: u32,
    // gid/pid are unread today; kept for future audit logging, since
    // SO_PEERCRED delivers all three fields in the same getsockopt call.
    #[allow(dead_code)]
    gid: u32,
    #[allow(dead_code)]
    pid: i32,
}

fn peer_cred(stream: &UnixStream) -> std::io::Result<Peer> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid fd; ucred/len out-params are correctly sized.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Peer {
        uid: ucred.uid,
        gid: ucred.gid,
        pid: ucred.pid,
    })
}

/// Only root or the target user themselves may enroll/delete that user's data.
fn authorized_for(peer: &Peer, target_user: &str) -> bool {
    peer.uid == 0 || uid_of(target_user).is_some_and(|u| u == peer.uid)
}

/// The daemon's OWN AppArmor confinement label (e.g. "irlumed (enforce)",
/// "irlumed (complain)", "unconfined") from /proc/self/attr, or None when
/// AppArmor is not enabled on this boot. Reported in Health so the TUI shows the
/// real confinement of the running daemon instead of inferring it from the
/// on-disk profile file, which stays present even if `apparmor_parser` failed to
/// load it and the daemon is actually unconfined.
fn apparmor_confinement() -> Option<String> {
    // The attr node exists whenever the kernel built AppArmor; only trust it when
    // AppArmor is actually live this boot.
    let enabled = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .map(|s| s.trim() == "Y")
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    // Newer kernels expose the label at attr/apparmor/current, older ones at
    // attr/current; the value is "profile (mode)\n" or "unconfined\n".
    let raw = std::fs::read_to_string("/proc/self/attr/apparmor/current")
        .or_else(|_| std::fs::read_to_string("/proc/self/attr/current"))
        .ok()?;
    let label = raw.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    (!label.is_empty()).then(|| label.to_string())
}

// libxcrypt's one-way hash (glibc moved `crypt` out of libc into libcrypt).
#[link(name = "crypt")]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Verify `password` against `user`'s `/etc/shadow` hash so `keyring arm` can
/// reject a password that is not the current LOGIN password (the cause of the
/// later "-9" wallet-key-derive failure: the face path jumps over pam_unix, so a
/// wrong seal is never caught at auth time, only when ksecretd tries to open the
/// wallet). Returns `Some(true/false)` on a verifiable hash, or `None` when it
/// cannot verify (no `/etc/shadow` access, no such user, or a locked / empty /
/// non-password field), in which case the caller does NOT block, since absence
/// of proof is not proof of a wrong password. Root-only (`/etc/shadow`).
fn password_matches_login(user: &str, password: &[u8]) -> Option<bool> {
    // The whole shadow file (every user's hash), the target hash, and the
    // plaintext password are wrapped in Zeroizing so they are scrubbed on drop
    // rather than left in freed heap that could page to swap or a core dump.
    // The rest of the daemon keeps this discipline via SecretBytes; this path
    // (a raw /etc/shadow read + a crypt() call) is the one place that bypassed
    // it.
    let shadow = zeroize::Zeroizing::new(std::fs::read_to_string("/etc/shadow").ok()?);
    let stored = zeroize::Zeroizing::new(verifiable_shadow_hash(&shadow, user)?);
    // An interior NUL can't be a shadow password; treat as unverifiable.
    if password.contains(&0) {
        return None;
    }
    // A NUL-terminated, zeroizing copy of the password for crypt(): scrubbed on
    // drop, unlike the CString this replaces.
    let mut key = zeroize::Zeroizing::new(Vec::with_capacity(password.len() + 1));
    key.extend_from_slice(password);
    key.push(0);
    let setting = std::ffi::CString::new(stored.as_str()).ok()?;
    // SAFETY: `crypt` returns a pointer into a STATIC buffer, so concurrent calls
    // would race. The daemon is NOT single-threaded, which an earlier version of
    // this comment claimed: it runs up to 64 connection threads plus a watchdog
    // and a penalty-box janitor. The invariant that actually holds is narrower
    // and must be preserved: this is reached only from `dispatch`, and `dispatch`
    // runs only on the one camera worker thread. Calling it from a connection
    // thread would be a data race. The pointers are valid NUL-terminated C
    // strings for the call's duration.
    let out = unsafe { crypt(key.as_ptr() as *const libc::c_char, setting.as_ptr()) };
    if out.is_null() {
        return None; // unsupported hash format on this libcrypt
    }
    let computed = unsafe { std::ffi::CStr::from_ptr(out) };
    Some(computed.to_bytes() == stored.as_bytes())
}

/// The user's VERIFIABLE `/etc/shadow` hash, or `None` when there is nothing to
/// verify against: the user is absent, or the field is empty / locked (`!`,
/// `!!`) / disabled (`*`). Pure (takes the shadow text) so the "don't block on
/// an unverifiable account" rule is unit-tested.
fn verifiable_shadow_hash(shadow: &str, user: &str) -> Option<String> {
    let stored = shadow.lines().find_map(|line| {
        let mut f = line.split(':');
        (f.next()? == user).then(|| f.next().map(str::to_string))?
    })?;
    (!stored.is_empty() && !stored.starts_with('!') && !stored.starts_with('*')).then_some(stored)
}

/// Resolve a username to its uid via NSS (covers LDAP/SSSD/systemd-homed, not
/// just `/etc/passwd`).
fn uid_of(user: &str) -> Option<u32> {
    users::uid_for_name(user)
}

/// One request line may not exceed this. A face embedding or sealed password is
/// a few KB of base64; 64 KiB is generous and bounds a slow-loris / memory DoS
/// from a peer that never sends a newline.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// One parsed request waiting for the camera worker, and where to send the
/// answer. The reply travels back over a channel rather than being written by
/// the worker, so a client that stops reading stalls its own connection thread
/// instead of the one thread every login needs.
struct Queued {
    req: Request,
    peer: Peer,
    reply: std::sync::mpsc::Sender<Response>,
}

/// How long a connection thread waits for the worker before giving up.
///
/// Generous, because it bounds the whole operation: a ten-scan enrollment with
/// retries is minutes of legitimate work. This is a backstop against a wedged
/// worker leaving connection threads parked forever, not a latency control.
const WORKER_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// True the first time this uid is refused an unseal for not being root.
///
/// The explanatory line is worth printing once per surface, not once per screen
/// unlock: it describes why a user-context greeter gets verification instead of
/// a credential, which does not change. Keeping it to once per uid also means a
/// local process cannot fill the journal by spinning on a request it knows will
/// be refused.
fn first_nonroot_unseal(uid: u32) -> bool {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u32>>> =
        std::sync::OnceLock::new();
    let mut seen = match SEEN.get_or_init(Default::default).lock() {
        Ok(s) => s,
        Err(e) => e.into_inner(),
    };
    seen.insert(uid)
}

// ---------------------------------------------------------------------------
// Wedged-capture watchdog (issue #141).
//
// Cooperative cancellation (#117 stage 2) checks a stop signal before opening
// the device and between whole captures, which covers everything that reaches a
// yield point. A capture already inside a V4L2 call or an inference session has
// no such point: if the driver never returns, the worker never comes back, and
// an authentication queued behind it waits indefinitely. No amount of scheduling
// fixes that, because there is nothing to schedule against.
//
// systemd is already supervising this process, so the deadline lives there
// rather than in a bespoke watchdog: `WatchdogSec` in the unit, and a ping from
// here while the worker is healthy. Stopping the ping is what asks for the
// restart, so a wedge ends as a bounded restart instead of an indefinite hang.
// PAM already treats a missing daemon as "fall back to the password", so the
// failure mode is one the login path handles.
//
// Health is about the WORKER, not the process. A process that is alive while its
// camera thread is stuck in the kernel is exactly the case this exists for, so
// pinging from a bare timer would report a wedged daemon as healthy.

/// When the worker last made progress, or `None` when it is idle.
///
/// Idle is healthy: a worker blocked waiting for the next job is doing its job.
/// Only a job that has been in flight without progress is a wedge candidate.
fn worker_progress() -> &'static std::sync::Mutex<Option<std::time::Instant>> {
    static P: std::sync::OnceLock<std::sync::Mutex<Option<std::time::Instant>>> =
        std::sync::OnceLock::new();
    P.get_or_init(Default::default)
}

/// Mark forward progress: a job was picked up, or a capture boundary was
/// reached. Called from the same points cooperative cancellation is polled at,
/// so long-but-healthy work (an enrolment capturing ten scans) keeps reporting
/// while a capture stuck inside one driver call does not.
fn note_worker_progress() {
    let mut p = match worker_progress().lock() {
        Ok(p) => p,
        Err(e) => e.into_inner(),
    };
    *p = Some(std::time::Instant::now());
}

/// Mark the worker idle again; it is healthy until it takes the next job.
fn note_worker_idle() {
    let mut p = match worker_progress().lock() {
        Ok(p) => p,
        Err(e) => e.into_inner(),
    };
    *p = None;
}

/// Whether a job has been in flight with no progress for longer than `limit`.
fn worker_wedged(limit: std::time::Duration) -> bool {
    let p = match worker_progress().lock() {
        Ok(p) => p,
        Err(e) => e.into_inner(),
    };
    p.is_some_and(|since| since.elapsed() > limit)
}

/// Send one `WATCHDOG=1` to the notify socket systemd handed us.
///
/// Written directly rather than pulling in a crate: it is one datagram. An
/// abstract socket (the usual case) arrives with a leading `@`.
fn notify_watchdog(socket: &str) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let sock = UnixDatagram::unbound()?;
    let addr = match socket.strip_prefix('@') {
        Some(name) => SocketAddr::from_abstract_name(name.as_bytes())?,
        None => SocketAddr::from_pathname(socket)?,
    };
    sock.send_to_addr(b"WATCHDOG=1", &addr)?;
    Ok(())
}

/// Ping systemd while the worker is healthy, and stop when it is not.
///
/// Does nothing unless systemd asked for a watchdog (`WATCHDOG_USEC`), so a
/// hand-run daemon and the test suite are unaffected. The no-progress deadline
/// is half the watchdog period, so a wedge is reported after one missed ping
/// rather than sitting until the period expires twice.
fn spawn_watchdog() {
    let (Ok(socket), Ok(usec)) = (
        std::env::var("NOTIFY_SOCKET"),
        std::env::var("WATCHDOG_USEC"),
    ) else {
        return;
    };
    let Ok(usec) = usec.parse::<u64>() else {
        return;
    };
    if socket.is_empty() || usec == 0 {
        return;
    }
    let period = std::time::Duration::from_micros(usec);
    let interval = period / 2;
    std::thread::Builder::new()
        .name("irlume-watchdog".into())
        .spawn(move || {
            let mut complained = false;
            loop {
                std::thread::sleep(interval);
                if worker_wedged(interval) {
                    if !complained {
                        eprintln!(
                            "irlumed: the camera worker has made no progress for {}s; \
                             withholding the systemd watchdog ping so this is restarted \
                             rather than left hung (face auth falls back to the password \
                             meanwhile)",
                            interval.as_secs()
                        );
                        complained = true;
                    }
                    continue;
                }
                complained = false;
                if let Err(e) = notify_watchdog(&socket) {
                    eprintln!("irlumed: watchdog ping failed: {e}");
                }
            }
        })
        .ok();
}

// ---------------------------------------------------------------------------
// Per-uid refusal throttle (issue #142).
//
// #117 capped CONCURRENCY at MAX_CONNECTION_THREADS but not the RATE. Measured
// 2026-07-27 with one client holding a uid's camera slot and 8 spinning behind
// it: 10,501 refusals a second, the daemon burning 305% of one core, and an
// ordinary `ListProfiles` going from 903ms to 4146ms. Connection threads peaked
// at 44 against a cap of 64, so exhaustion was never the mechanism; CPU was, and
// the cost is paid per CONNECTION, before the request is even parsed.
//
// So the throttle is enforced in the accept loop, where a throttled connection
// costs no thread, no parse and no arbiter round trip. It is HELD there briefly
// rather than dropped: measured, dropping was worse than useless, because an
// instant EOF let the client reconnect sooner and CPU barely moved. A delay
// before ANSWERING, the other obvious shape, would also have been worse: it
// holds a connection thread for its whole duration and does nothing about CPU.
//
// It is fed ONLY by requests the arbiter actually refused, so a peer doing
// ordinary work is never throttled no matter how busy it is. Root is exempt:
// every privileged PAM stack (greeter, sudo, polkit helper) runs as uid 0, and
// starving those is worse than any flood.
//
// HONEST LIMIT: an unprivileged uid that floods itself into the throttle also
// delays its OWN user-context authentications, the KDE lock screen being the
// one that runs as the user rather than root. The window is deliberately short
// so this self-heals in well under a second, and the password remains the
// fallback throughout. A different uid can never cause it.
// ---------------------------------------------------------------------------

/// Refusals per second a single non-root uid may generate before its new
/// connections are held. Set from `IRLUME_REFUSAL_RATE`; 0 disables the
/// throttle. Well above any real client: a refusal means the camera was busy,
/// and a legitimate caller retries on a human timescale, not thousands of times
/// a second.
fn refusal_rate_limit() -> f64 {
    env_or("IRLUME_REFUSAL_RATE", "100")
        .parse()
        .unwrap_or(100.0)
}

/// A token bucket per uid, refilled at [`refusal_rate_limit`] per second.
#[derive(Default)]
struct RefusalBucket {
    tokens: f64,
    last: Option<std::time::Instant>,
}

fn refusal_state() -> &'static std::sync::Mutex<std::collections::HashMap<u32, RefusalBucket>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u32, RefusalBucket>>> =
        std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// Charge one refusal to `uid`.
fn record_refusal(uid: u32) {
    let rate = refusal_rate_limit();
    if rate <= 0.0 || uid == 0 {
        return;
    }
    let now = std::time::Instant::now();
    let mut map = match refusal_state().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    let b = map.entry(uid).or_insert(RefusalBucket {
        tokens: rate,
        last: Some(now),
    });
    refill(b, rate, now);
    b.tokens = (b.tokens - 1.0).max(-rate);
}

/// Refill a bucket for the time elapsed, capped at one second's worth.
fn refill(b: &mut RefusalBucket, rate: f64, now: std::time::Instant) {
    if let Some(last) = b.last {
        let dt = now.saturating_duration_since(last).as_secs_f64();
        b.tokens = (b.tokens + dt * rate).min(rate);
    }
    b.last = Some(now);
}

/// Whether this peer has spent its refusal budget, so the connection should be
/// dropped without spawning a thread. Root and a disabled limit are never
/// throttled.
fn refusal_throttled(uid: u32) -> bool {
    let rate = refusal_rate_limit();
    if rate <= 0.0 || uid == 0 {
        return false;
    }
    let now = std::time::Instant::now();
    let mut map = match refusal_state().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    let Some(b) = map.get_mut(&uid) else {
        return false;
    };
    refill(b, rate, now);
    b.tokens < 0.0
}

/// Read and parse one connection, hand the request to the arbiter, write back
/// what the worker answers.
///
/// Everything here runs on the connection's own thread. The only work that
/// reaches the camera worker is a parsed, authorized-shaped request, which is
/// what lets an authentication overtake a queue of preview work: before this,
/// a request nobody had read yet was invisible to the daemon.
/// The listening socket systemd passed us, if we were socket-activated.
///
/// Implements the sd_listen_fds protocol directly rather than pulling in
/// libsystemd: `LISTEN_PID` must name this process (so an fd inherited by a
/// child is not mistaken for ours) and `LISTEN_FDS` counts descriptors starting
/// at 3. We ask for exactly one, because the unit lists exactly one
/// `ListenStream=`.
fn inherited_listener() -> Option<UnixListener> {
    use std::os::fd::FromRawFd;
    const SD_LISTEN_FDS_START: i32 = 3;
    if !socket_activated() {
        return None;
    }
    let n: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if n != 1 {
        eprintln!("irlumed: LISTEN_FDS={n}, expected exactly 1; binding our own socket instead");
        return None;
    }
    // The environment must not outlive this: a child that inherits it would
    // believe the descriptors are its own.
    SOCKET_ACTIVATED.store(true, std::sync::atomic::Ordering::Relaxed);
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_PID");
    // SAFETY: systemd guarantees fd 3 is an open listening socket when
    // LISTEN_PID names us and LISTEN_FDS is 1, and nothing else in this process
    // has taken it: this runs before any other socket is opened.
    Some(unsafe { UnixListener::from_raw_fd(SD_LISTEN_FDS_START) })
}

/// Whether systemd handed us the socket. Checked separately from taking the fd
/// because the socket's MODE is systemd's business in that case, and that
/// question outlives the one call that consumes the descriptor.
fn socket_activated() -> bool {
    std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        == Some(std::process::id())
        || SOCKET_ACTIVATED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Latched at the moment the descriptor is taken, because `inherited_listener`
/// clears `LISTEN_PID` and later callers would otherwise see "not activated".
static SOCKET_ACTIVATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Release the TPM-sealed login password after another factor has authenticated.
///
/// Free-standing, and deliberately takes no engine: nothing here touches the
/// camera, the models or the matcher, only `irlume_core::keyring` and the peer's
/// credentials. That is what lets the daemon answer it while the engine is still
/// loading (#244). Every authorization check below is a property of the REQUEST,
/// never of startup state, so answering early cannot weaken any of them.
fn unseal_keyring(user: &str, service: Option<&str>, have_password: bool, peer: &Peer) -> Response {
    let user = user.to_string();
    let service = service.map(str::to_string);

    // Fingerprint keyring unlock. pam_fprintd has ALREADY authenticated
    // the user in this PAM transaction (pam_irlume `keyring` only runs at
    // the post-auth landing). The daemon can't re-verify a fingerprint
    // (fprintd owns the sensor), so the trust is: root peer + a login /
    // unlock service class. Releases the sealed login password so
    // pam_gnome_keyring can open the wallet, matching Windows Hello's
    // functional model. SECURITY (ADR-0003 / THREAT_MODEL): preserves
    // at-rest protection (a stolen disk still can't unseal; it needs the
    // live TPM), but a live root attacker in a login context can obtain
    // it; root stays the trust boundary. For daemon-verified biometric
    // release resistant to live root, use the face/IR path.
    if peer.uid != 0 {
        return Response::Error(format!(
            "unseal_keyring requires root (peer uid {})",
            peer.uid
        ));
    }
    if !irlume_core::keyring::has_sealed_password(&user) {
        return Response::Error(format!(
            "no sealed password for '{user}': run `irlume keyring arm`"
        ));
    }
    // Only a login / greeter / lock-screen context; never sudo,
    // elevation, remote, or unknown. Defence-in-depth: a direct caller
    // can forge the service string (root can call us directly), so this
    // does not stop a root attacker; it does stop the keyring line being
    // (mis)wired into a non-login stack from releasing the credential.
    {
        use irlume_core::biopolicy::{classify, OperationClass, SessionState};
        let class = classify(service.as_deref().unwrap_or(""), SessionState::Warm);
        if !matches!(class, OperationClass::ScreenUnlock | OperationClass::Login) {
            eprintln!(
                "irlumed: UnsealKeyring refused for service '{}' ({class:?})",
                service.as_deref().unwrap_or("?")
            );
            return Response::Error(format!("keyring unseal not allowed for {class:?}"));
        }
    }
    // A typed password already opens a password-keyed keyring, so touching the
    // TPM would spend an unseal (up to seconds on a discrete TPM) to release a
    // secret the caller then discards. For a token envelope the typed password
    // opens nothing, so the release must proceed. The kind read here is a
    // cheap envelope-file read, not an unseal; the release below re-reads
    // atomically, so a concurrent re-arm at worst turns this into the old
    // always-unseal behaviour.
    if have_password
        && irlume_core::keyring::sealed_kind(&user)
            == Some(irlume_core::envelope::SecretKind::LoginPassword)
    {
        return Response::KeyringUnlockNotNeeded;
    }
    // One load yields both the bytes and their kind, so a concurrent re-arm
    // cannot tag one envelope's secret with another's kind.
    match irlume_core::keyring::unseal_secret(&user) {
        Ok(unsealed) => {
            eprintln!(
                "irlumed: UnsealKeyring: OK for '{user}' (fingerprint-authenticated), {} unsealed",
                unsealed.kind.describe()
            );
            Response::PasswordUnsealed {
                kind: crate::users::core_to_wire_kind(unsealed.kind),
                secret: irlume_common::SecretBytes::new(unsealed.secret.to_vec()),
            }
        }
        Err(e) => {
            eprintln!("irlumed: UnsealKeyring: TPM unseal FAILED for '{user}': {e}");
            Response::Error(e.to_string())
        }
    }
}

/// What the daemon can answer before its engine exists.
///
/// Keyring release touches `irlume_core::keyring` and the peer's credentials and
/// nothing else, so it is served here: that is the difference between a
/// fingerprint login after a reboot unlocking the keyring and meeting a password
/// prompt (#244). Every other request is REFUSED rather than queued, so a face
/// attempt falls through to the password at once instead of waiting out startup,
/// and no early caller occupies a slot for the length of it.
fn dispatch_before_engine(req: Request, peer: &Peer) -> Response {
    match req {
        Request::UnsealKeyring {
            user,
            service,
            have_password,
        } => unseal_keyring(&user, service.as_deref(), have_password, peer),
        Request::Ping => Response::Ok("starting".into()),
        _ => Response::Error(
            "irlumed is still starting (loading models); retry, or use your password".into(),
        ),
    }
}

fn serve(
    stream: UnixStream,
    arbiter: &arbiter::Arbiter<Queued>,
    engine_ready: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    let peer = peer_cred(&stream)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
    match read_request(&stream)? {
        ReadOutcome::Closed => Ok(()),
        ReadOutcome::Bad => respond(stream, &Response::Error("bad request".into())),
        ReadOutcome::Req(req) => {
            // No engine yet means no worker to queue for.
            if !engine_ready.load(std::sync::atomic::Ordering::Acquire) {
                return respond(stream, &dispatch_before_engine(req, &peer));
            }
            let class = arbiter::classify(&req);
            // Status is answered HERE, on the connection's own thread: it is
            // read-only, engine-free, and possibly slow (ListProfiles is a
            // TPM unseal), so it must neither wait behind the worker nor make
            // an authentication wait behind it (#212).
            // A Status request is answered here ONLY if dispatch_status can
            // answer it from memory. `None` means it cannot (an unpublished
            // enrollment summary), and the request must then take the normal
            // queue path so the worker does the real load and publishes it.
            // Answering the None with an error instead made every listing
            // fail: the miss never reached the worker, so nothing ever
            // published, so every later listing missed too.
            if class == arbiter::Class::Status {
                if let Some(resp) = dispatch_status(&req, &peer) {
                    return respond(stream, &resp);
                }
            }
            let (reply, answer) = std::sync::mpsc::channel();
            let queued = Queued {
                req,
                peer: peer.clone(),
                reply,
            };
            if let Err(refusal) = arbiter.submit(class, peer.uid, queued) {
                // Refused, not queued: answer now so the client can retry rather
                // than hold a slot the login path may want. Charged to the peer,
                // so a client that spins on refusals throttles itself at accept
                // time rather than costing a thread per attempt (#142).
                record_refusal(peer.uid);
                return respond(stream, &Response::Error(refusal.message().into()));
            }
            let resp = match answer.recv_timeout(WORKER_REPLY_TIMEOUT) {
                Ok(resp) => resp,
                // The worker dropped the sender (it panicked and the reply never
                // came) or took longer than the backstop. Either way this
                // request has no answer, and a client that gets an error falls
                // back to the password.
                Err(_) => Response::Error("request did not complete".into()),
            };
            respond(stream, &resp)
        }
    }
}

/// One parsed request line off the wire (see [`read_request`]).
#[cfg_attr(test, derive(Debug))] // tests unwrap_err() around it; not needed at runtime
enum ReadOutcome {
    /// Peer closed without sending a line.
    Closed,
    /// The line did not parse; the caller answers a generic "bad request"
    /// (never echoing the peer's raw bytes / parser internals back).
    Bad,
    Req(Request),
}

/// Read one request line (bounded by [`MAX_REQUEST_BYTES`]) and parse it.
/// Called by [`serve`] on the connection's own thread (test seam: exercised
/// over a socketpair without an [`irlume_auth::Engine`]).
fn read_request(stream: &UnixStream) -> std::io::Result<ReadOutcome> {
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_REQUEST_BYTES);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(ReadOutcome::Closed);
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(_) => {
            line.zeroize();
            return Ok(ReadOutcome::Bad);
        }
    };
    // The line may hold a plaintext secret (SealPassword/RecoverySetup); wipe it
    // now that it's parsed into the zeroizing SecretBytes.
    line.zeroize();
    Ok(ReadOutcome::Req(req))
}

/// A username is interpolated into `<user>.json` paths (enrollment, sealed key,
/// keyring). Reject anything that could traverse or escape the state dir before
/// any path is built; defence-in-depth on top of the NSS `authorized_for` check.
fn valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with(['-', '.'])
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
}

/// The `user` field of a request, if it carries one (for the traversal guard).
fn request_user(req: &Request) -> Option<&str> {
    use Request::*;
    match req {
        Authenticate { user, .. }
        | Enroll { user, .. }
        | ListProfiles { user, .. }
        | DeleteProfile { user, .. }
        | DeleteScan { user, .. }
        | ForgetRecognizer { user, .. }
        | RenameProfile { user, .. }
        | RenameScan { user, .. }
        | AddScan { user, .. }
        | SetRequireEyesOpen { user, .. }
        | SetRequireChallenge { user, .. }
        | CaptureEarMedian { user }
        | SetClosureCalibration { user, .. }
        | SealPassword { user, .. }
        | UnsealPassword { user, .. }
        | UnsealKeyring { user, .. }
        | HasSealedPassword { user }
        | KeyringInfo { user }
        | ForgetPassword { user }
        | ResealPassword { user, .. }
        | RecoveryStatus { user }
        | RecoverySetup { user, .. }
        | RecoveryRestore { user, .. }
        | RecoveryForget { user } => Some(user.as_str()),
        // Framing guide: the (optional) user only tunes the pitch band, but it's
        // still interpolated into a state path, so validate it like the rest.
        PositionSample { user: Some(u) } => Some(u.as_str()),
        _ => None,
    }
}

/// The engine-derived facts `Health` reports, published once the engine is
/// built (and again after a panic rebuild) so status requests can answer on
/// the connection thread without touching the engine. The socket binds only
/// after the first publish, so no connection can observe the empty state.
#[derive(Clone, Default)]
struct EngineBits {
    mesh: bool,
    adapter: bool,
    third_party_pad: Option<String>,
    third_party_recognizer: Option<String>,
    third_party_detector: Option<String>,
    /// The camera facts as the ENGINE observed them when it loaded, so
    /// `Health` can answer from memory. Probing them per request opened
    /// video nodes on a connection thread, outside the camera worker's
    /// serialization, which is a second opener racing the worker's own
    /// stream (#187 review) and contradicted the Status class's documented
    /// "touches no camera" contract.
    tier: String,
    rgb_dev: Option<String>,
    ir_dev: Option<String>,
}

fn engine_bits() -> &'static std::sync::Mutex<EngineBits> {
    static BITS: std::sync::OnceLock<std::sync::Mutex<EngineBits>> = std::sync::OnceLock::new();
    BITS.get_or_init(|| std::sync::Mutex::new(EngineBits::default()))
}

fn publish_engine_bits_raw(bits: EngineBits) {
    *engine_bits().lock().unwrap_or_else(|e| e.into_inner()) = bits;
}

fn publish_engine_bits(engine: &irlume_auth::Engine) {
    // One probe, at load, on the thread that owns the engine. Every later
    // Health answer reads this copy.
    let caps = irlume_auth::capabilities();
    let (rgb, ir) = irlume_auth::select_pair();
    let rgb_dev = (caps.rgb && std::path::Path::new(&rgb).exists()).then_some(rgb);
    let ir_dev = (caps.ir_pair && std::path::Path::new(&ir).exists()).then_some(ir);
    let tier = if ir_dev.is_some() {
        "secure"
    } else if rgb_dev.is_some() {
        "convenience"
    } else {
        "none"
    };
    publish_engine_bits_raw(EngineBits {
        mesh: engine.has_mesh(),
        adapter: engine.has_ir_adapter(),
        third_party_pad: engine.thirdparty_pad_name().map(String::from),
        third_party_recognizer: engine.thirdparty_recognizer_name().map(String::from),
        third_party_detector: engine.thirdparty_detector_name().map(String::from),
        tier: tier.into(),
        rgb_dev,
        ir_dev,
    });
}

/// One user's enrollment as the status path may report it, published by the
/// WORKER after it loads or mutates that enrollment and read (cloned) by the
/// connection threads. The real `storage::load` both unseals under the TPM
/// (one command at a time on the physical chip, so it contends with a
/// login's own TPM work) and can WRITE: `load_key`'s best-effort tier
/// upgrade re-seals the template-key envelope. Neither belongs on a
/// connection thread, so the status path serves only this snapshot and a
/// miss falls through to the worker queue.
#[derive(Clone)]
struct EnrollmentSummary {
    profiles: Vec<irlume_common::ProfileSummary>,
    require_eyes_open: bool,
    require_challenge: bool,
    closure_calibrated: bool,
    ir_ratio_calibrated: bool,
}

#[allow(clippy::type_complexity)]
fn enrollment_summaries(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, EnrollmentSummary>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, EnrollmentSummary>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn summarize_enrollment(
    enr: Option<&irlume_core::storage::Enrollment>,
    live_recognizer: &str,
) -> EnrollmentSummary {
    match enr {
        Some(enr) => EnrollmentSummary {
            profiles: enr
                .profiles
                .iter()
                .map(|p| {
                    let mut scans_by_recognizer = std::collections::BTreeMap::new();
                    for s in &p.scans {
                        // Untagged scans belong to the recognizer that
                        // predates tagging, the same rule matching applies.
                        let space = s.embed_space.clone().unwrap_or_else(|| {
                            irlume_core::storage::LEGACY_RECOGNIZER_SPACE.to_string()
                        });
                        *scans_by_recognizer.entry(space).or_insert(0) += 1;
                    }
                    irlume_common::ProfileSummary {
                        name: p.name.clone(),
                        scans: p.scans.iter().map(|s| s.name.clone()).collect(),
                        scans_by_recognizer,
                        live_recognizer: Some(live_recognizer.to_string()),
                    }
                })
                .collect(),
            require_eyes_open: enr.require_eyes_open,
            require_challenge: enr.require_challenge,
            closure_calibrated: enr
                .closure_calibration
                .map(|(o, c)| {
                    irlume_liveness::ClosureCalibration {
                        ear_open: o,
                        ear_closed: c,
                    }
                    .is_usable()
                })
                .unwrap_or(false),
            ir_ratio_calibrated: enr.ir_center_edge_ratio_floor().is_some(),
        },
        // A successful load that found nothing IS an observation: publishing
        // the empty summary keeps an unenrolled machine's status pollers off
        // the worker instead of missing on every tick.
        None => EnrollmentSummary {
            profiles: Vec::new(),
            require_eyes_open: false,
            require_challenge: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
    }
}

fn publish_enrollment_summary(user: &str, summary: EnrollmentSummary) {
    enrollment_summaries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(user.to_string(), summary);
}

/// Dropped BEFORE the mutation runs, so the window where the cache could
/// disagree with disk is "empty", never "stale": a concurrent status read
/// misses and queues behind the mutation it would otherwise have raced.
fn invalidate_enrollment_summary(user: &str) {
    enrollment_summaries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(user);
}

/// Drops every published summary. The cache is keyed by user alone, but a
/// test sandbox swaps `IRLUME_STATE_DIR` underneath it, so a summary another
/// test published describes an enrollment that no longer exists on disk.
/// `dispatch` answers a listing from that cache before it ever reads storage
/// (see `dispatch_status`), so without this a listing can report a profile
/// from a dead sandbox. Production never moves its state dir, so this has no
/// caller outside tests.
#[cfg(test)]
fn clear_enrollment_summaries() {
    enrollment_summaries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

fn cached_enrollment_summary(user: &str) -> Option<EnrollmentSummary> {
    enrollment_summaries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(user)
        .cloned()
}

/// The requests after which the published summary for `user` may no longer
/// describe the enrollment on disk. The worker invalidates before running
/// them. Recovery operations are included because they change the key
/// material the enrollment is sealed under; re-publishing happens on the
/// next worker-side listing.
fn enrollment_mutating_user(req: &Request) -> Option<&str> {
    use Request::*;
    match req {
        Enroll { user, .. }
        | AddScan { user, .. }
        | DeleteProfile { user, .. }
        | DeleteScan { user, .. }
        | ForgetRecognizer { user, .. }
        | RenameProfile { user, .. }
        | RenameScan { user, .. }
        | SetRequireEyesOpen { user, .. }
        | SetRequireChallenge { user, .. }
        | SetClosureCalibration { user, .. }
        | RecoverySetup { user, .. }
        | RecoveryRestore { user, .. }
        | RecoveryForget { user, .. } => Some(user),
        _ => None,
    }
}

/// The username-validity pregate every request passes before any arm runs,
/// shared by the worker dispatch and the connection-thread status dispatch.
fn precheck(req: &Request) -> Option<Response> {
    if let Some(u) = request_user(req) {
        if !valid_username(u) {
            return Some(Response::Error("invalid username".into()));
        }
    }
    None
}

/// Answer a [`arbiter::Class::Status`] request. Runs on the CONNECTION
/// THREAD: everything here is read-only and engine-free (`Health` reads the
/// published [`EngineBits`]), so a slow status read (`ListProfiles` is a TPM
/// unseal, 10.8s measured on one machine) cannot make an authentication
/// wait, and a wedged worker cannot make `Ping` lie about the daemon being
/// down (#212). Returns `None` for requests that are not status, which the
/// worker then serves as before.
fn dispatch_status(req: &Request, peer: &Peer) -> Option<Response> {
    if let Some(resp) = precheck(req) {
        return Some(resp);
    }
    let bits = engine_bits()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Some(match req {
        Request::Ping => Response::Pong,
        Request::Health => {
            // MEMORY ONLY. The camera facts were probed once when the engine
            // loaded and published with the rest of the bits; probing here
            // opened video nodes on a connection thread while the worker
            // might be streaming them (#187 review). A camera that appears
            // or vanishes is picked up at the next engine (re)load, which is
            // also when the daemon could act on it.
            Response::Health {
                tier: bits.tier.clone(),
                rgb_dev: bits.rgb_dev.clone(),
                ir_dev: bits.ir_dev.clone(),
                mesh: bits.mesh,
                adapter: bits.adapter,
                version: env!("CARGO_PKG_VERSION").into(),
                // Authoritative loaded-cue name so a non-root TUI can show the
                // real on/off state (settings.conf is root-only).
                third_party_pad: bits.third_party_pad.clone(),
                third_party_recognizer: bits.third_party_recognizer.clone(),
                third_party_detector: bits.third_party_detector.clone(),
                apparmor: apparmor_confinement(),
            }
        }
        // Only tune the band to a user the peer may act for (root, or their own
        // account); else ignore it. Stops a non-root peer forcing a per-poll TPM
        // unseal of another user's (e.g. root's) enrollment via the framing guide.
        Request::HasSealedPassword { user } => {
            if !authorized_for(peer, user) {
                return Some(Response::Error(format!("not authorized to query '{user}'")));
            }
            Response::HasPassword(irlume_core::keyring::has_sealed_password(user))
        }
        Request::RecoveryStatus { user } => {
            if !authorized_for(peer, user) {
                return Some(Response::Error(format!("not authorized to query '{user}'")));
            }
            Response::RecoveryStatus {
                // The store's own shape, not the key's presence: those differ
                // exactly when the key is gone, and that case has to be
                // reportable rather than collapsed into "plaintext".
                encrypted: irlume_core::storage::store_is_encrypted(user).unwrap_or(false),
                recovery_set: irlume_core::template_key::has_recovery(user),
                tpm_present: irlume_core::template_key::tpm_available(),
                key_present: irlume_core::template_key::has_key(user),
            }
        }
        Request::ListProfiles {
            user,
            structured_errors,
        } => {
            let fail = |code: irlume_common::OperationErrorCode, prose: String| {
                if *structured_errors {
                    Response::OperationError {
                        code,
                        retryable: false,
                    }
                } else {
                    Response::Error(prose)
                }
            };
            if !authorized_for(peer, user) {
                return Some(fail(
                    irlume_common::OperationErrorCode::NotAuthorized,
                    format!("not authorized to list '{user}'"),
                ));
            }
            // Cache HIT only: the summary the worker published after its
            // last load or mutation of this enrollment. A miss returns None
            // and the request queues to the worker, whose ListProfiles arm
            // does the real load (TPM unseal, possible key re-seal) and
            // publishes. Serving the real load here would put a TPM command
            // and a potential template-key WRITE on a connection thread.
            match cached_enrollment_summary(user) {
                Some(sum) => Response::Enrollment {
                    profiles: sum.profiles,
                    require_eyes_open: sum.require_eyes_open,
                    require_challenge: sum.require_challenge,
                    closure_calibrated: sum.closure_calibrated,
                    ir_ratio_calibrated: sum.ir_ratio_calibrated,
                },
                None => return None,
            }
        }
        _ => return None,
    })
}

/// Probe rounds when nobody sized the run explicitly. Enough that one unlucky
/// capture cannot decide the answer, few enough that a user waits seconds
/// rather than minutes: the measured spread was sd ~1.3 on a mean of ~117, so
/// 6 is ample.
const TUNE_DEFAULT_ROUNDS: usize = 6;
/// Upper bound on requested probe rounds.
const TUNE_MAX_ROUNDS: usize = 30;

/// Whether a capture-mode probe may persist its verdict to cameras.conf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeStore {
    /// `camera-tune`: the user asked for a measurement, so the verdict is
    /// stored even when the scene was too dim to trust it, and the summary
    /// carries the re-run caveat.
    Always,
    /// Enrollment's one-time probe (#340): automatic, so it must not persist
    /// what the scene cannot support. A clean concurrent reading in a dim
    /// room proves nothing (the NexiGo parks near mean 60 in any light, so a
    /// legitimately dim scene hides the loss completely), and storing it
    /// would re-create durably the exact trap the sequential default closes.
    ConclusiveOnly,
}

/// Whether the probe delivered every round it was asked for (#340 review):
/// `accumulate` drops errored rounds from the means, and `conclusive()` tests
/// brightness, not evidence volume, so without this check one lucky round per
/// arm and five errors each could persist durable policy. The all-error
/// concurrent arm is the one exception, backed differently: every attempt
/// must have errored (partial arms do not qualify) and
/// `measure_contention_impl`'s trailing sequential control has already proven
/// the camera still answers.
fn probe_rounds_complete(report: &irlume_auth::ContentionReport, requested: usize) -> bool {
    if report.concurrent_impossible() {
        return report.concurrent.failed == requested;
    }
    report.sequential.rounds == requested
        && report.sequential.failed == 0
        && report.concurrent.rounds == requested
        && report.concurrent.failed == 0
}

/// The persistence decision, pure so a mode-flipping mutant is caught without
/// cameras: an explicit tune always stores; the automatic probe stores only a
/// result backed by every requested round AND a scene that can carry it.
fn probe_verdict_storable(
    policy: ProbeStore,
    report: &irlume_auth::ContentionReport,
    requested_rounds: usize,
) -> bool {
    match policy {
        ProbeStore::Always => true,
        ProbeStore::ConclusiveOnly => {
            probe_rounds_complete(report, requested_rounds) && report.conclusive()
        }
    }
}

/// Run the contention probe on the engine's camera pair, persist the verdict
/// per `policy`, and summarize what was measured.
///
/// One path for both callers (`camera-tune` and the enrollment probe), so the
/// watchdog contract holds everywhere: the probe reports progress between
/// captures, without which a long but healthy run reads as a wedged driver
/// and systemd kills a working daemon (#141).
fn run_capture_mode_probe(
    rgb_dev: &str,
    ir_dev: &str,
    rounds: usize,
    policy: ProbeStore,
) -> Result<String, String> {
    // Reports between captures so a long but healthy tune is not read as a
    // wedged driver by the watchdog (#141), and per silent warm-up window
    // inside each capture (#336).
    let progress: irlume_auth::Progress = std::sync::Arc::new(note_worker_progress);
    let report = irlume_auth::measure_contention_with_progress(rgb_dev, ir_dev, rounds, &progress)
        .map_err(|e| e.to_string())?;
    let mode = report.recommended_mode();
    if !probe_verdict_storable(policy, &report, rounds) {
        // Not an error: the pair stays unmeasured, which the sequential
        // default already makes safe, and the caller's work proceeds. Name
        // the reason that actually blocked storing: thin evidence and dim
        // light are different problems with different fixes.
        let why = if probe_rounds_complete(&report, rounds) {
            format!(
                "the probe ran in a dim scene (RGB mean {:.0}), where a clean \
                 concurrent reading proves nothing",
                report.sequential.rgb_mean
            )
        } else {
            format!("the probe did not complete {rounds} clean rounds in both capture modes")
        };
        return Ok(format!(
            "capture mode left unmeasured: {why}; captures stay one at a time (the safe \
             default). Run `sudo irlume camera-tune` with the room lit to store a \
             measured verdict"
        ));
    }
    match policy {
        // The explicit tune is an instruction to re-measure: it overwrites.
        ProbeStore::Always => {
            irlume_auth::store_capture_mode(rgb_dev, ir_dev, mode).map_err(|e| e.to_string())?
        }
        // The automatic probe re-checks emptiness under the cameras.conf
        // writer lock: its first check and this write are separated by the
        // whole probe, and a verdict another process landed in that window
        // outranks the automatic result (#340 review).
        ProbeStore::ConclusiveOnly => {
            match irlume_auth::store_capture_mode_if_absent(rgb_dev, ir_dev, mode)
                .map_err(|e| e.to_string())?
            {
                irlume_auth::StoreIfAbsent::Stored => {}
                irlume_auth::StoreIfAbsent::AlreadyPresent(existing) => {
                    return Ok(format!(
                        "capture mode {} was stored by someone else while the probe ran; \
                         keeping it (the probe's own result, {}, was discarded)",
                        existing.as_str(),
                        mode.as_str()
                    ));
                }
            }
        }
    }
    // An arm that never streamed has no retention to report; percentages
    // from its empty samples would read as dimming when the finding is
    // "cannot run at all" (#192, the BRIO's EINVAL on concurrent RGB open).
    let mut msg = if report.concurrent_impossible() {
        // Observed counts, not the requested round count: a sequential arm
        // can complete fewer rounds than were asked for, and "measured fine"
        // must not overstate its evidence.
        format!(
            "capture mode {} for this camera: it cannot stream RGB and IR \
             at once (all {} concurrent attempts errored; {} sequential \
             round(s) completed, {} errored; a trailing one-at-a-time \
             control confirmed the camera still answers)",
            mode.as_str(),
            report.concurrent.failed,
            report.sequential.rounds,
            report.sequential.failed,
        )
    } else {
        format!(
            "capture mode {} for this camera: concurrent capture keeps {:.0}% of RGB \
             and {:.0}% of IR brightness and saves {:.0}ms ({rounds} rounds)",
            mode.as_str(),
            report.retained_rgb() * 100.0,
            report.retained_ir() * 100.0,
            report.saved_ms(),
        )
    };
    // Say so rather than letting a dark room read as a clean bill of health.
    if !report.conclusive() {
        msg.push_str(&format!(
            "\n     measured in a dim scene (RGB mean {:.0}); this loss only \
             shows in normal light, so re-run camera-tune with the room lit \
             to confirm",
            report.sequential.rgb_mean
        ));
    }
    Ok(msg)
}

/// Whether enrollment must measure the capture mode first: exactly when the
/// pair is unmeasured AND the verdict could persist (#340). A stored verdict
/// of EITHER value is authoritative; enrollment never re-measures or
/// overwrites one, so nothing about a measured camera changes by enrolling on
/// it again. A camera with no stable identity (no USB descriptor, e.g. a
/// v4l2loopback node) is excluded outright: cameras.conf keys verdicts by
/// identity, so its probe result could never be stored and every enrollment
/// would spend a minute re-measuring to no effect.
fn enrollment_needs_capture_probe(
    identifiable: bool,
    stored: Option<irlume_auth::CaptureMode>,
) -> bool {
    identifiable && stored.is_none()
}

/// The enrollment probe's journal note, over an injected prober so the
/// trigger rule is testable without cameras: `None` when a stored verdict
/// made the probe unnecessary. A failed probe reports instead of failing the
/// enrollment, because an unmeasured pair enrolls under the sequential
/// default, which is the shape every camera manages.
fn enroll_capture_probe_note(
    identifiable: bool,
    stored: Option<irlume_auth::CaptureMode>,
    probe: impl FnOnce() -> Result<String, String>,
) -> Option<String> {
    if !enrollment_needs_capture_probe(identifiable, stored) {
        return None;
    }
    Some(match probe() {
        Ok(msg) => msg,
        Err(e) => format!(
            "capture-mode probe failed ({e}); enrolling with one-at-a-time capture, \
             the unmeasured default"
        ),
    })
}

/// The Enroll arm's probe-then-capture order, over injected probe and enroll
/// closures so the wiring is testable without cameras (#340 review round: the
/// helper tests alone could not catch dispatch dropping the probe, running it
/// after the capture, or a probe outcome blocking enrollment). The probe note
/// goes to the journal; enrollment ALWAYS runs, whatever the probe said.
fn enroll_with_capture_probe(
    identifiable: bool,
    stored: Option<irlume_auth::CaptureMode>,
    probe: impl FnOnce() -> Result<String, String>,
    enroll: impl FnOnce() -> Response,
) -> Response {
    if let Some(note) = enroll_capture_probe_note(identifiable, stored, probe) {
        eprintln!("irlumed: {note}");
    }
    enroll()
}

fn dispatch(req: Request, peer: &Peer, engine: &mut irlume_auth::Engine) -> Response {
    // BEFORE the mutation runs, not after: a summary dropped early leaves
    // the cache empty (a concurrent status read queues here behind us),
    // never stale. Repopulated by the next worker-side listing.
    if let Some(u) = enrollment_mutating_user(&req) {
        invalidate_enrollment_summary(u);
    }
    // Status requests are normally answered on the connection thread and
    // never reach here; delegating keeps this dispatch total (and identical
    // in behavior) if one is ever submitted anyway. precheck rides inside.
    if let Some(resp) = dispatch_status(&req, peer) {
        return resp;
    }
    if let Some(resp) = precheck(&req) {
        return resp;
    }
    match req {
        // These four are answered by dispatch_status above; the arm is
        // unreachable and exists so the match stays exhaustive without a
        // second implementation to drift.
        Request::Ping
        | Request::Health
        | Request::HasSealedPassword { .. }
        | Request::RecoveryStatus { .. } => {
            Response::Error("status request routed past its handler".into())
        }
        Request::KeyringInfo { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to query '{user}'"));
            }
            let armed = irlume_core::keyring::has_sealed_password(&user);
            let path = irlume_core::keyring::envelope_path(&user);
            match irlume_core::envelope::SealedEnvelope::load(&path) {
                Ok(env) => Response::KeyringInfo {
                    armed,
                    policy: Some(env.policy.describe()),
                    pcrs: env.pcrs.clone(),
                    // None when the envelope carries no PCR snapshot or the
                    // replay failed; the CLI then just omits the drift note.
                    drifted: irlume_core::tpm::diagnose_pcrs(&env)
                        .ok()
                        .filter(|_| !env.pcr_values.is_empty())
                        .map(|d| !d.is_empty()),
                    kind: Some(crate::users::core_to_wire_kind(env.secret)),
                },
                // Not armed, or the envelope is unreadable/corrupt: report the
                // armed bit alone rather than failing the whole query.
                Err(_) => Response::KeyringInfo {
                    armed,
                    policy: None,
                    pcrs: Vec::new(),
                    drifted: None,
                    kind: None,
                },
            }
        }
        Request::ListProfiles {
            user,
            structured_errors,
        } => {
            // Only ever answer with a typed error when the request asked for
            // one. An older client cannot deserialize an unknown response
            // variant, so sending one unasked would break it across the upgrade
            // window, which is the failure class of issue #93.
            let fail = |code: irlume_common::OperationErrorCode, prose: String| {
                if structured_errors {
                    Response::OperationError {
                        code,
                        retryable: false,
                    }
                } else {
                    Response::Error(prose)
                }
            };
            if !authorized_for(peer, &user) {
                return fail(
                    irlume_common::OperationErrorCode::NotAuthorized,
                    format!("not authorized to list '{user}'"),
                );
            }
            match irlume_core::storage::load(&user) {
                Ok(enr) => {
                    // The status path serves this snapshot from now on; the
                    // load above is also the moment `load_key` may have
                    // re-sealed the template key, which is exactly why the
                    // load lives HERE on the worker and not on a connection
                    // thread.
                    let sum = summarize_enrollment(enr.as_ref(), engine.embed_space());
                    publish_enrollment_summary(&user, sum.clone());
                    Response::Enrollment {
                        profiles: sum.profiles,
                        require_eyes_open: sum.require_eyes_open,
                        require_challenge: sum.require_challenge,
                        closure_calibrated: sum.closure_calibrated,
                        ir_ratio_calibrated: sum.ir_ratio_calibrated,
                    }
                }
                Err(e) => fail(
                    irlume_common::OperationErrorCode::OperationFailed,
                    e.to_string(),
                ),
            }
        }
        Request::PositionSample { user } => {
            match engine.position_sample(user.as_deref().filter(|u| authorized_for(peer, u))) {
                Ok(r) => Response::Position(r),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::Authenticate { user, service } => {
            // Root (PAM stacks) or the account owner only. Without this gate any
            // local peer could probe Authenticate{other_user} and read the raw
            // similarity score, a hill-climbing oracle toward a match (the
            // threat model promises scores never leak to unprivileged peers).
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to authenticate '{user}'"));
            }
            // Honor the configured unlock method: if the admin chose fingerprint,
            // face must actually stand down (pam_fprintd drives; password is the
            // fallback), not just be claimed disabled by the CLI message.
            if irlume_core::policy::method().face_disabled() {
                return Response::AuthResult {
                    granted: false,
                    score: 0.0,
                    live: false,
                    reason: "face auth disabled: the configured method is fingerprint".into(),
                };
            }
            // Smart-Auto tier gate: on a CONVENIENCE (RGB-only) device, a face
            // match may ONLY satisfy a screen unlock; never login, elevation, or
            // a remote/unknown service (those keep the password). Always-on for
            // RGB-only hardware (independent of the opt-in biopolicy for IR boxes).
            if engine.tier() == irlume_core::biopolicy::Tier::Convenience {
                use irlume_core::biopolicy::{classify, OperationClass, SessionState};
                // Warm = the user already has a running session (their systemd
                // runtime dir exists); then an ambiguous greeter service (GDM
                // drives cold login AND the lock screen through gdm-password) is
                // a screen unlock, not a login. Caveat: lingering user services
                // also create /run/user/<uid>; acceptable for the convenience
                // tier where the worst case is unlocking a lock screen.
                let session = users::uid_for_name(&user)
                    .map(|uid| std::path::Path::new(&format!("/run/user/{uid}")).exists())
                    .map(|has_runtime_dir| {
                        if has_runtime_dir {
                            SessionState::Warm
                        } else {
                            SessionState::Cold
                        }
                    })
                    .unwrap_or(SessionState::Cold);
                let class = classify(service.as_deref().unwrap_or(""), session);
                if class != OperationClass::ScreenUnlock {
                    eprintln!("irlumed: convenience(RGB-only) denies face for '{}' ({class:?}) -> password", service.as_deref().unwrap_or("?"));
                    return Response::AuthResult {
                        granted: false,
                        score: 0.0,
                        live: false,
                        reason: format!(
                            "RGB-only convenience: face limited to screen unlock (not {class:?})"
                        ),
                    };
                }
            }
            // Opt-in biopolicy also gates identity VERIFICATION on IR/Secure
            // hardware (mirrors the credential-release gate); else a face grant
            // for a Remote/Unknown service would bypass the "face never satisfies
            // remote" invariant. Off by default (behaviour unchanged).
            if biopolicy_enforced() && engine.tier() != irlume_core::biopolicy::Tier::Convenience {
                use irlume_core::biopolicy::{classify, decide, Action, SessionState, Tier};
                let svc = service.as_deref().unwrap_or("");
                if decide(classify(svc, SessionState::Cold), Tier::Secure) == Action::Deny {
                    eprintln!("irlumed: biopolicy denies verify for service '{svc}' -> password");
                    return Response::AuthResult {
                        granted: false,
                        score: 0.0,
                        live: false,
                        reason: format!("biopolicy: face may not satisfy '{svc}'"),
                    };
                }
            }
            // Too many recent failures: don't fire the camera, fall to password.
            if rate_limited(&user) {
                return Response::AuthResult {
                    granted: false,
                    score: 0.0,
                    live: false,
                    reason: "too many recent face attempts; use your password".into(),
                };
            }
            let convenience = engine.tier() == irlume_core::biopolicy::Tier::Convenience;
            let t = std::time::Instant::now();
            match engine.authenticate(&user, service.as_deref()) {
                Ok(o) => {
                    rate_record(&user, o.granted, !irlume_auth::presence_retryable(&o));
                    if convenience || irlume_common::dbglog::on() {
                        // Denied score + reason measurements quantized/redacted
                        // unless tracing (anti-oracle); grants log exact.
                        let (score, reason) = if o.granted {
                            (format!("{:.3}", o.score), o.reason.clone())
                        } else {
                            (deny_score(o.score), deny_reason(&o.reason))
                        };
                        eprintln!("irlumed: face auth '{user}': granted={} live={} score={score} ({reason})",
                            o.granted, o.live);
                    }
                    irlume_common::dlog!("verify '{user}' total {}ms", t.elapsed().as_millis());
                    Response::AuthResult {
                        granted: o.granted,
                        score: o.score,
                        live: o.live,
                        reason: o.reason,
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::Identify => {
            if camera_probe_rate_limited(peer.uid) {
                return Response::Error("rate limited; try again shortly".into());
            }
            // 1:N identify returns an exact similarity score, so an ungated
            // socket peer could hill-climb it to tune a spoof or enumerate who
            // is enrolled. Root keeps the full cross-user search (admin/test);
            // a non-root peer is scoped to its OWN account; the score then only
            // concerns a face the caller already controls, not other users'.
            let scoped = match identify_scope(peer) {
                IdentifyScope::Full => engine.identify(),
                IdentifyScope::SelfOnly(name) => engine.identify_within(&name),
                IdentifyScope::NoAccount => Ok(irlume_auth::IdentifyOutcome {
                    user: None,
                    profile: None,
                    score: 0.0,
                    live: false,
                    reason: "caller has no local account".into(),
                }),
            };
            match scoped {
                Ok(o) => Response::Identified {
                    user: o.user,
                    profile: o.profile,
                    score: o.score,
                    live: o.live,
                    reason: o.reason,
                },
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::SetCameras { rgb, ir } => {
            // Persists to /etc and repoints the camera the daemon trusts; an
            // attacker who could set this to a v4l2loopback node feeds recorded
            // video into the match path (spoof) or bricks face auth (DoS). Root
            // only (a system-wide /etc setting isn't an arbitrary peer's to make).
            if peer.uid != 0 {
                return Response::Error(format!(
                    "set_cameras requires root (peer uid {})",
                    peer.uid
                ));
            }
            engine.set_devices(&rgb, &ir);
            let mut msg = format!("cameras set to rgb={rgb} ir={ir}");
            // Record each node's stable device identity (vid:pid:serial) next to
            // its path so select_pair can survive a udev renumber: after an
            // upgrade shuffles /dev/videoN, the identity re-anchors the pin to the
            // right sensor instead of trusting a now-stale number. An empty value
            // clears a stale id when the current node has no USB descriptor.
            let rgb_id = irlume_auth::device_identity(&rgb).unwrap_or_default();
            let ir_id = irlume_auth::device_identity(&ir).unwrap_or_default();
            if let Err(e) = irlume_common::config::write_kv("cameras.conf", "rgb", &rgb)
                .and_then(|_| irlume_common::config::write_kv("cameras.conf", "ir", &ir))
                .and_then(|_| irlume_common::config::write_kv("cameras.conf", "rgb_id", &rgb_id))
                .and_then(|_| irlume_common::config::write_kv("cameras.conf", "ir_id", &ir_id))
            {
                msg = format!("{msg} (live only; could not persist: {e})");
            }
            eprintln!("irlumed: {msg}");
            Response::Ok(msg)
        }
        Request::Enroll {
            user,
            profile,
            scans,
            reset,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to enroll '{user}'"));
            }
            if reset {
                // Clean slate: drop the old enrollment (and its stale camera
                // binding) before enrolling fresh.
                if let Err(e) = irlume_core::storage::delete(&user) {
                    return Response::Error(format!("reset failed: {e}"));
                }
            }
            let want = scans.unwrap_or(irlume_core::storage::DEFAULT_ENROLL_SCANS);
            // Apply the known emitter control so dark-mode scans enroll cleanly.
            // Asking to enroll a face is not consent to probe camera firmware
            // for an unknown control, so this no longer falls through to a
            // search when IR is dark (#159).
            match irlume_auth::apply_known_ir_emitter(engine.ir_device()) {
                Ok(true) => {}
                Ok(false) => eprintln!(
                    "irlumed: IR is dark; enrolling RGB (dark unlock unavailable). \
                     If this camera needs an emitter control, run `sudo irlume ir-setup`."
                ),
                Err(e) => eprintln!("irlumed: IR emitter check skipped: {e}"),
            }
            // One-time capture-mode measurement (#340): an unmeasured pair
            // defaults to sequential capture, and enrollment is the reliable
            // moment to measure the real answer: the user is present, waiting
            // is expected, and the room is usually lit well enough for a
            // concurrent reading to mean something (a lock screen in the
            // dark, the other candidate moment, is none of those). Not
            // root-gated like camera-tune: enrolling already authorizes
            // holding the camera and firing the emitter, and this write can
            // only fill an EMPTY verdict, never flip a measured one.
            let (rgb_dev, ir_dev) = (
                engine.rgb_device().to_string(),
                engine.ir_device().to_string(),
            );
            // Both nodes must identify: the verdict is keyed by the PAIR, so
            // an unidentifiable IR (a loopback feeder beside a real RGB
            // module) has nowhere to store a result either (#340 review).
            let identifiable = irlume_auth::device_identity(&rgb_dev).is_some()
                && irlume_auth::device_identity(&ir_dev).is_some();
            enroll_with_capture_probe(
                identifiable,
                irlume_auth::stored_capture_mode(&rgb_dev, &ir_dev),
                || {
                    eprintln!(
                        "irlumed: enroll: no measured capture mode for this camera pair; \
                         running the one-time contention probe before the scans (up to a \
                         minute; the IR emitter fires)"
                    );
                    run_capture_mode_probe(
                        &rgb_dev,
                        &ir_dev,
                        TUNE_DEFAULT_ROUNDS,
                        ProbeStore::ConclusiveOnly,
                    )
                },
                || match engine.enroll_profile(&user, profile, want) {
                    Ok(outcome) => enroll_response(outcome),
                    Err(e) => Response::Error(e.to_string()),
                },
            )
        }
        Request::TuneCaptureMode { rounds } => {
            // Holds the camera for tens of seconds and rewrites capture policy in
            // /etc/irlume, so it is root-only like the other camera-bearing
            // management requests.
            if peer.uid != 0 {
                return Response::Error(format!(
                    "camera-tune requires root (peer uid {})",
                    peer.uid
                ));
            }
            let rounds = rounds
                .unwrap_or(TUNE_DEFAULT_ROUNDS)
                .clamp(1, TUNE_MAX_ROUNDS);
            let (rgb_dev, ir_dev) = (
                engine.rgb_device().to_string(),
                engine.ir_device().to_string(),
            );
            match run_capture_mode_probe(&rgb_dev, &ir_dev, rounds, ProbeStore::Always) {
                Ok(msg) => {
                    eprintln!("irlumed: {msg}");
                    Response::Ok(msg)
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::SetupIrEmitter { dry_run } => {
            // Writes to the camera. It addresses only controls the camera's own
            // descriptor documents and undoes what it can, but a run that ends
            // because the camera stopped answering can leave a control changed,
            // so this is not called non-destructive.
            if dry_run {
                // Reads the camera's USB descriptors from sysfs and sends the
                // device nothing, but it still names hardware and is reachable
                // by any local uid, so it keeps the camera-probe interval.
                if camera_probe_rate_limited(peer.uid) {
                    return Response::Error("rate limited; try again shortly".into());
                }
                match irlume_auth::list_ir_controls(engine.ir_device()) {
                    Ok(c) if c.is_empty() => {
                        Response::Ok("no UVC extension-unit controls found".into())
                    }
                    Ok(c) => Response::Ok(format!("extension units: {}", c.join("; "))),
                    Err(e) => Response::Error(e.to_string()),
                }
            } else {
                // The non-dry path writes to the camera's Microsoft-XU. It no
                // longer guesses payloads (#159), but any write to camera
                // firmware stays root-only.
                if peer.uid != 0 {
                    return Response::Error(format!(
                        "setup_ir_emitter requires root (peer uid {})",
                        peer.uid
                    ));
                }
                match irlume_auth::setup_ir_emitter(engine.ir_device()) {
                    Ok(msg) => {
                        eprintln!("irlumed: {msg}");
                        Response::Ok(msg)
                    }
                    Err(e) => Response::Error(e.to_string()),
                }
            }
        }
        Request::AddScan {
            user,
            profile,
            scans,
            report_enrollment,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            match engine.add_scan(&user, &profile, scans.unwrap_or(1)) {
                // The structured reply, opted into: the TUI needs the
                // ambient-lit count of EVERY scan for the #312 completion
                // note, and AddScan carries every scan after the first.
                Ok(out) if report_enrollment => Response::Enrolled {
                    profile,
                    created: false,
                    added: out.added_scans.len(),
                    total: out.total,
                    room: Some(out.room),
                    added_scans: out.added_scans,
                    ambient_lit: Some(out.ambient_lit),
                },
                Ok(out) => Response::Ok(format!(
                    "added {} to '{profile}' ({total} scans for the loaded recognizer)",
                    out.added_scans
                        .iter()
                        .map(|s| format!("'{s}'"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    total = out.total,
                )),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        // --- keyring unlock (TPM-sealed password) ---------------------------
        Request::SealPassword {
            user,
            password,
            kind,
        } => {
            // Arming the keyring: root or the user themselves. `password`
            // zeroizes on drop, covering every return path.
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to seal password for '{user}'"));
            }
            // Refuse to seal a password that is not the user's LOGIN password:
            // it would seal cleanly but fail later at wallet key-derive ("-9").
            // Only a POSITIVE mismatch blocks; an unverifiable hash proceeds.
            if password_matches_login(&user, password.expose()) == Some(false) {
                return Response::Error(format!(
                    "that is not '{user}'s current login password; the keyring is unlocked with \
                     the login password, so arming a different one would leave the wallet locked"
                ));
            }
            // On KDE, seal the wallet key derived from this password rather
            // than the password itself. The wallet is keyed to exactly those
            // bytes already, so nothing is re-keyed and a typed password still
            // opens it through pam_kwallet5; what changes is that the envelope
            // stops being a Unix password. See #250 and irlume_core::kwallet.
            // Resolve the kind from what the user actually has when the client
            // did not force one, so a KDE-only machine gets the wallet key
            // without the client needing to know to ask.
            let home = crate::users::home_for_name(&user);
            let core_kind = match kind {
                Some(k) => crate::users::wire_to_core_kind(k),
                None => match home.as_deref() {
                    Some(h) => irlume_core::kwallet::detect_kind(h),
                    None => irlume_core::envelope::SecretKind::LoginPassword,
                },
            };
            // A token arm returns the token: the re-key of the login keyring
            // can only happen in the user's session (the control socket
            // authenticates the peer uid), so the caller finishes the job.
            // Envelope-before-re-key ordering is inside arm_gnome_token. A
            // RE-arm must reuse the existing token, not mint: the keyring's
            // live credential is the old token, and overwriting its only copy
            // with a fresh one would strand the keyring permanently.
            if core_kind == irlume_core::envelope::SecretKind::GnomeKeyringToken {
                // The re-key that completes a token arm CREATES the login
                // keyring when none exists, keyed to the token, rather than
                // failing (`change_or_create_login()` in gnome-keyring's
                // gkd-login.c never checks the old password in that case). The
                // user would end up with a keyring whose password is 64 random
                // characters they have never seen. Detection already declines
                // a home with no login keyring; this catches a client that
                // asked for the kind explicitly.
                let keyring_present = home
                    .as_deref()
                    .map(|h| h.join(".local/share/keyrings/login.keyring").exists())
                    .unwrap_or(false);
                if !keyring_present {
                    return Response::Error(format!(
                        "'{user}' has no GNOME login keyring, so there is nothing to re-key; \
                         arming a token would create one keyed to a random secret. Log into \
                         GNOME once to create the keyring, or arm without forcing a kind."
                    ));
                }
                let already_token = irlume_core::keyring::sealed_kind(&user)
                    == Some(irlume_core::envelope::SecretKind::GnomeKeyringToken);
                let armed = if already_token {
                    irlume_core::keyring::rearm_gnome_token(&user, password.expose())
                } else {
                    irlume_core::keyring::arm_gnome_token(&user, password.expose())
                        .map(|t| zeroize::Zeroizing::new(t.as_bytes().to_vec()))
                };
                return match armed {
                    Ok(token) => {
                        eprintln!(
                            "irlumed: SealPassword: sealed a GNOME keyring token for '{user}' \
                             ({}); caller must now re-key the login keyring",
                            if already_token {
                                "reused from the existing envelope"
                            } else {
                                "freshly minted"
                            }
                        );
                        Response::TokenSealed {
                            token: irlume_common::SecretBytes::new(token.to_vec()),
                            minted: !already_token,
                        }
                    }
                    Err(e) => Response::Error(e.to_string()),
                };
            }
            let secret = match core_kind {
                irlume_core::envelope::SecretKind::LoginPassword => {
                    Ok(zeroize::Zeroizing::new(password.expose().to_vec()))
                }
                irlume_core::envelope::SecretKind::KdeWalletKey
                | irlume_core::envelope::SecretKind::GnomeKeyringToken => {
                    irlume_core::keyring::derive_secret(
                        core_kind,
                        password.expose(),
                        home.as_deref(),
                    )
                }
            };
            let secret = match secret {
                Ok(s) => s,
                Err(e) => return Response::Error(e.to_string()),
            };
            match irlume_core::keyring::seal_secret(&user, &secret, core_kind) {
                Ok(()) => {
                    eprintln!(
                        "irlumed: SealPassword: armed keyring unlock for '{user}' ({})",
                        core_kind.describe()
                    );
                    Response::PasswordSealed
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::UnsealPassword { user, service } => {
            // The sealed LOGIN password is released ONLY to a root peer. A
            // non-root caller never gets it, even with a matching face.
            //
            // NOT every login surface is root, and the comment here used to say
            // it was. Greeters are (SDDM, GDM, plasmalogin, greetd all run PAM
            // in a privileged helper), and so are sudo and the polkit helper.
            // The KDE LOCK SCREEN is not: `kscreenlocker_greet` is not setuid
            // and runs as the user, so its `unseal` is refused here every time
            // and `pam_irlume`'s `ondemand` fallback then verifies identity
            // instead. That is working as intended, and it is why a warm screen
            // unlock never releases a credential.
            //
            // Refusing SILENTLY is what was wrong. This returns before
            // `do_unseal_password` logs its `attempt` line, so the whole
            // exchange left no trace: a field investigation into "face unlocked
            // the screen but the keyring still asked for a password" reads an
            // empty journal and concludes the daemon was never contacted, which
            // is exactly the wrong conclusion. Measured 2026-07-27, that cost
            // hours.
            //
            // Logged once per uid per daemon lifetime, not once per unlock: the
            // line exists to explain a surface, not to narrate every lock
            // screen, and a local process could otherwise flood the journal by
            // spinning on a request it knows will be refused.
            if peer.uid != 0 {
                if first_nonroot_unseal(peer.uid) {
                    eprintln!(
                        "irlumed: UnsealPassword refused for uid {} (not root): no sealed \
                         credential is released to a user-context caller. A greeter that runs \
                         PAM as the user, notably the KDE lock screen, gets identity \
                         verification only; this is expected and is logged once per uid.",
                        peer.uid
                    );
                } else {
                    irlume_common::dlog!("UnsealPassword refused for uid {} (not root)", peer.uid);
                }
                return Response::Error(format!(
                    "unseal_password requires root (peer uid {})",
                    peer.uid
                ));
            }
            // Same method gate as Authenticate: fingerprint-configured means no
            // face-driven credential release either.
            if irlume_core::policy::method().face_disabled() {
                return Response::Error(
                    "face auth disabled: the configured method is fingerprint".into(),
                );
            }
            // ALWAYS-ON: a polkit prompt never releases the sealed credential,
            // independent of the tier and the opt-in biopolicy below. The
            // polkit agent runs its PAM conversation with no user gesture, so a
            // `unseal`-arg line (mis)wired into polkit-1 must not be able to
            // pull the login password out of the TPM; polkit gets verify-only
            // (Authenticate).
            {
                use irlume_core::biopolicy::{classify, OperationClass, SessionState};
                let svc = service.as_deref().unwrap_or("");
                if classify(svc, SessionState::Cold) == OperationClass::AppConsent {
                    eprintln!("irlumed: UnsealPassword refused for polkit service '{svc}' (verify-only class)");
                    return Response::Error(format!(
                        "'{svc}' is verify-only: a polkit prompt never releases the credential"
                    ));
                }
            }
            // Smart-Auto: an RGB-only (convenience) device NEVER releases the
            // sealed credential: no cold-login / keyring unlock by RGB-only face.
            if engine.tier() == irlume_core::biopolicy::Tier::Convenience {
                eprintln!("irlumed: convenience(RGB-only) refuses credential release for '{user}' -> password");
                return Response::Error(
                    "RGB-only convenience: face cannot release the login credential".into(),
                );
            }
            // Opt-in biopolicy: when enforcement is enabled, gate credential
            // release by the PAM service's operation class (e.g. refuse a remote
            // / unknown service). Default off → unchanged behaviour.
            if biopolicy_enforced() {
                use irlume_core::biopolicy::{classify, decide, Action, SessionState, Tier};
                let svc = service.as_deref().unwrap_or("");
                // UnsealPassword is the cold-login path, so Cold. Not because
                // the lock screen asks for something different: `/etc/pam.d/kde`
                // is wired `unseal ondemand` like the greeters. It is because a
                // lock-screen unseal is refused above for running as the user,
                // so what reaches here is the cold path in practice. irlume's
                // liveness already requires IR for any grant, so a granted match
                // is Secure tier.
                let action = decide(classify(svc, SessionState::Cold), Tier::Secure);
                if action != Action::Unseal {
                    eprintln!("irlumed: biopolicy denies unseal for service '{svc}' ({action:?}) -> password");
                    return Response::Error(format!(
                        "biopolicy: '{svc}' may not release the credential"
                    ));
                }
            }
            do_unseal_password(&user, service.as_deref(), engine)
        }
        Request::UnsealKeyring {
            user,
            service,
            have_password,
        } => unseal_keyring(&user, service.as_deref(), have_password, peer),
        Request::ForgetPassword { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to forget password for '{user}'"));
            }
            match irlume_core::keyring::forget_password(&user) {
                Ok(()) => Response::PasswordForgotten,
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::ReleaseTokenForDisarm { user, password } => {
            // Same authz as arming; the password check inside (the token's own
            // AES-GCM wrap) is what actually gates the release, so a root
            // caller still has to present the user's password. `password`
            // zeroizes on drop.
            if !authorized_for(peer, &user) {
                return Response::Error(format!(
                    "not authorized to release the keyring token for '{user}'"
                ));
            }
            match irlume_core::keyring::release_token_with_password(&user, password.expose()) {
                Ok(token) => {
                    eprintln!(
                        "irlumed: ReleaseTokenForDisarm: released '{user}'s keyring token \
                         (password verified against the recovery wrap)"
                    );
                    Response::PasswordUnsealed {
                        kind: irlume_common::KeyringSecretKind::GnomeKeyringToken,
                        secret: irlume_common::SecretBytes::new(token.to_vec()),
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::ResealPassword { user, password } => {
            // Self-heal hook from the login SESSION phase (runs only after auth
            // succeeded, so `password` is verified-correct). Same authz as arming
            // (root or the user), but it can only ever *re-seal an already armed*
            // password against today's PCRs; it never arms a fresh user, so a
            // self-peer cannot use it to plant a sealed password they didn't set.
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to reseal password for '{user}'"));
            }
            // The home directory is where the KDE wallet salt lives; a
            // login-password envelope ignores it, so an unresolvable home is
            // only fatal for the wallet kind and reseal decides that itself.
            let home = crate::users::home_for_name(&user);
            match irlume_core::keyring::reseal_password(&user, password.expose(), home.as_deref()) {
                Ok(outcome) => {
                    use irlume_core::keyring::Reseal;
                    if outcome == Reseal::Resealed {
                        eprintln!(
                            "irlumed: ResealPassword: re-bound '{user}' to current PCRs (self-heal after PCR/password change)"
                        );
                    } else if outcome == Reseal::Upgraded {
                        eprintln!(
                            "irlumed: ResealPassword: upgraded '{user}' keyring seal to a stronger TPM policy tier (no re-arm needed)"
                        );
                    }
                    Response::PasswordResealed {
                        // Both Resealed (self-heal) and Upgraded (tier climb)
                        // changed the on-disk envelope.
                        armed: outcome != Reseal::NotArmed,
                        changed: outcome == Reseal::Resealed || outcome == Reseal::Upgraded,
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        // --- template-key recovery passphrase -------------------------------
        Request::RecoverySetup { user, passphrase } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to set recovery for '{user}'"));
            }
            // If templates are still plaintext (pre-encryption enrollment), mint
            // and seal a template key now by re-saving; encryption takes effect
            // and there's a key for the recovery passphrase to wrap. A no-op when
            // already encrypted or when the user isn't enrolled.
            if !irlume_core::template_key::has_key(&user) {
                if let Ok(Some(enr)) = irlume_core::storage::load(&user) {
                    if let Err(e) = irlume_core::storage::save(&enr) {
                        return Response::Error(format!(
                            "could not encrypt existing templates: {e}"
                        ));
                    }
                    eprintln!("irlumed: RecoverySetup: encrypted existing templates for '{user}'");
                }
            }
            match irlume_core::template_key::setup_recovery(&user, passphrase.expose()) {
                Ok(()) => {
                    eprintln!("irlumed: RecoverySetup: recovery passphrase set for '{user}'");
                    Response::Ok(format!("recovery passphrase set for '{user}'"))
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::RecoveryRestore { user, passphrase } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to restore recovery for '{user}'"));
            }
            match irlume_core::template_key::restore_from_recovery(&user, passphrase.expose()) {
                Ok(()) => {
                    eprintln!(
                        "irlumed: RecoveryRestore: re-sealed '{user}' template key to current PCRs"
                    );
                    Response::Ok(format!("template key restored and re-sealed for '{user}'"))
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::RecoveryForget { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to forget recovery for '{user}'"));
            }
            match irlume_core::template_key::forget_recovery(&user) {
                Ok(()) => Response::Ok(format!("recovery passphrase erased for '{user}'")),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::ListCameras => Response::Cameras(
            irlume_auth::list_pairs()
                .into_iter()
                .map(|p| irlume_common::CameraPairInfo {
                    // Privacy is read HERE, on the camera worker, for the
                    // same reason the enumeration is: the control read opens
                    // the node (#187).
                    privacy: irlume_auth::privacy_engaged(&p.rgb)
                        || irlume_auth::privacy_engaged(&p.ir),
                    rgb: p.rgb,
                    ir: p.ir,
                    id: p.id,
                    fixed: p.fixed,
                })
                .collect(),
        ),
        Request::DeleteProfile { user, profile } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let before = enr.profiles.len();
                enr.profiles.retain(|p| p.name != profile);
                if enr.profiles.len() == before {
                    Err(format!("no face profile '{profile}'"))
                } else {
                    Ok(format!("deleted profile '{profile}'"))
                }
            })
        }
        Request::DeleteScan {
            user,
            profile,
            scan,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let p = enr
                    .profiles
                    .iter_mut()
                    .find(|p| p.name == profile)
                    .ok_or(format!("no face profile '{profile}'"))?;
                let before = p.scans.len();
                p.scans.retain(|s| s.name != scan);
                if p.scans.len() == before {
                    Err(format!("no scan '{scan}' in '{profile}'"))
                } else if p.scans.is_empty() {
                    Err("a profile must keep at least one scan; delete the profile instead".into())
                } else {
                    Ok(format!("deleted scan '{scan}' from '{profile}'"))
                }
            })
        }
        Request::ForgetRecognizer { user, space } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            // Read before mutating: is the loaded recognizer the one being
            // forgotten? Decided here because the closure below has no engine.
            let forgetting_live = space == engine.embed_space();
            mutate_enrollment(&user, |enr| {
                let mut scans_removed = 0usize;
                let mut calibs_removed = 0usize;
                for p in &mut enr.profiles {
                    let before = p.scans.len();
                    p.scans.retain(|s| {
                        !irlume_core::storage::recognizer_space_matches(
                            s.embed_space.as_deref(),
                            &space,
                        )
                    });
                    scans_removed += before - p.scans.len();
                    // The calibration for this space was fitted from the scans
                    // just removed; it is derived biometric material and goes
                    // with them. Cleared even when the scans are already gone
                    // (deleted one by one), because a stale fit can outlive
                    // its scans.
                    if p.calib_for(&space).is_some() {
                        calibs_removed += 1;
                        p.set_calib_for(&space, None);
                    }
                }
                if scans_removed == 0 && calibs_removed == 0 {
                    return Err(format!("no enrollment data from recognizer {space}"));
                }
                // Same rule as DeleteScan: a profile is never left empty. A
                // profile whose only scans were this recognizer's goes with
                // them, and when the last profile goes, mutate_enrollment
                // erases the file.
                let emptied: Vec<String> = enr
                    .profiles
                    .iter()
                    .filter(|p| p.scans.is_empty())
                    .map(|p| p.name.clone())
                    .collect();
                enr.profiles.retain(|p| !p.scans.is_empty());
                let mut msg = format!("forgot recognizer {space}: {scans_removed} scan(s) removed");
                if !emptied.is_empty() {
                    msg.push_str(&format!(
                        " (profile(s) {} deleted: no scans left)",
                        emptied
                            .iter()
                            .map(|n| format!("'{n}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if forgetting_live && scans_removed > 0 {
                    msg.push_str(
                        "; these were the LOADED recognizer's templates, so face \
                         authentication needs a re-enroll or an add-scan",
                    );
                }
                Ok(msg)
            })
        }
        Request::RenameProfile {
            user,
            profile,
            new_name,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                if enr.profiles.iter().any(|p| p.name == new_name) {
                    return Err(format!("'{new_name}' already exists"));
                }
                let p = enr
                    .profiles
                    .iter_mut()
                    .find(|p| p.name == profile)
                    .ok_or(format!("no face profile '{profile}'"))?;
                p.name = new_name.clone();
                Ok(format!("renamed profile to '{new_name}'"))
            })
        }
        Request::RenameScan {
            user,
            profile,
            scan,
            new_name,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let p = enr
                    .profiles
                    .iter_mut()
                    .find(|p| p.name == profile)
                    .ok_or(format!("no face profile '{profile}'"))?;
                if p.scans.iter().any(|s| s.name == new_name) {
                    return Err(format!("'{new_name}' already exists in '{profile}'"));
                }
                let s = p
                    .scans
                    .iter_mut()
                    .find(|s| s.name == scan)
                    .ok_or(format!("no scan '{scan}' in '{profile}'"))?;
                s.name = new_name.clone();
                Ok(format!("renamed scan to '{new_name}'"))
            })
        }
        Request::SetRequireEyesOpen { user, on } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                enr.require_eyes_open = on;
                Ok(format!(
                    "require-eyes-open {}",
                    if on { "ENABLED" } else { "disabled" }
                ))
            })
        }
        Request::SetRequireChallenge { user, on } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                enr.require_challenge = on;
                Ok(format!(
                    "require-challenge {}",
                    if on { "ENABLED" } else { "disabled" }
                ))
            })
        }
        Request::CaptureEarMedian { user: _ } => {
            // Fires the camera; root-gate like the other camera-bearing requests.
            // The socket is world-connectable, so this gate is what keeps other
            // uids out.
            if peer.uid != 0 {
                return Response::Error(format!(
                    "capture_ear_median requires root (peer uid {})",
                    peer.uid
                ));
            }
            // ~3s window: enough frames for a stable median of the current eye
            // state (open or closed, whichever the caller is prompting).
            const CAL_FRAMES: usize = 45;
            match engine.capture_ear_samples(CAL_FRAMES) {
                Ok(samples) => Response::EarMedian(irlume_liveness::calibrate_open_ear(&samples)),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::SetClosureCalibration {
            user,
            ear_open,
            ear_closed,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                enr.closure_calibration = Some((ear_open, ear_closed));
                Ok(format!(
                    "closure calibration stored (open {ear_open:.3}, closed {ear_closed:.3})"
                ))
            })
        }
        Request::SelfTest { kind } => {
            // Fires the camera and returns raw liveness/alignment measurements
            // (IR brightness, center/edge, glint), which are a spoof-tuning oracle and
            // a way to tie up the single-threaded daemon. Gate to root, like the
            // other camera-bearing requests. The socket is world-connectable, so
            // this gate is the only thing keeping an arbitrary local uid out.
            if peer.uid != 0 {
                return Response::Error(format!("self_test requires root (peer uid {})", peer.uid));
            }
            use irlume_common::SelfTestKind;
            let r = match kind {
                SelfTestKind::Liveness => engine.liveness_selftest(),
                SelfTestKind::AlignmentIdentity => engine.alignment_selftest(),
            };
            match r {
                Ok((passed, detail)) => Response::SelfTest { passed, detail },
                Err(e) => Response::Error(e.to_string()),
            }
        }
    }
}

/// How a peer's 1:N Identify is scoped. Root keeps the full cross-user search;
/// any other peer is confined to its own account (or to nothing at all), so
/// the returned similarity score never concerns a face the caller does not
/// already control.
#[derive(Debug, PartialEq, Eq)]
enum IdentifyScope {
    /// Full cross-user search (root only).
    Full,
    /// Scoped to the peer's own username.
    SelfOnly(String),
    /// The peer resolves to no local account; identify matches no one.
    NoAccount,
}

fn identify_scope(peer: &Peer) -> IdentifyScope {
    if peer.uid == 0 {
        return IdentifyScope::Full;
    }
    match users::name_for_uid(peer.uid) {
        Some(name) => IdentifyScope::SelfOnly(name),
        None => IdentifyScope::NoAccount,
    }
}

/// Map an engine enroll outcome onto the wire response. A merge into an
/// existing profile MUST report `created: false`: the TUI's split-capture
/// worker keys off it to stop and confirm, instead of sending the remaining
/// AddScans to a profile that was never created.
fn enroll_response(outcome: irlume_auth::EnrollOutcome) -> Response {
    match outcome {
        irlume_auth::EnrollOutcome::New {
            name,
            scans,
            ambient_lit,
        } => Response::Enrolled {
            profile: name,
            created: true,
            added: scans,
            total: scans,
            // A brand-new profile holds only this recognizer's scans, so the
            // per-recognizer room is the plain remainder.
            room: Some(irlume_core::storage::MAX_SCANS_PER_PROFILE.saturating_sub(scans)),
            added_scans: Vec::new(),
            ambient_lit: Some(ambient_lit),
        },
        irlume_auth::EnrollOutcome::Merged {
            name,
            added,
            total,
            room,
            added_scans,
            ambient_lit,
        } => Response::Enrolled {
            profile: name,
            created: false,
            added,
            total,
            room: Some(room),
            added_scans,
            ambient_lit: Some(ambient_lit),
        },
    }
}

/// Load `user`'s enrollment, apply `f`, and save. `f` returns an Ok message or an
/// error string. Used by the storage-only management operations.
fn mutate_enrollment(
    user: &str,
    f: impl FnOnce(&mut irlume_core::storage::Enrollment) -> Result<String, String>,
) -> Response {
    let mut enr = match irlume_core::storage::load(user) {
        Ok(Some(e)) => e,
        Ok(None) => return Response::Error(format!("'{user}' is not enrolled")),
        Err(e) => return Response::Error(e.to_string()),
    };
    match f(&mut enr) {
        Ok(msg) => {
            // If no profiles remain, remove the file entirely.
            let save = if enr.profiles.is_empty() {
                irlume_core::storage::delete(user).map(|_| ())
            } else {
                irlume_core::storage::save(&enr)
            };
            match save {
                Ok(()) => Response::Ok(msg),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Err(e) => Response::Error(e),
    }
}

/// Face-verify `user` and, on a passing match, release the TPM-sealed password.
/// The biometric check happens HERE (inside unseal), so a caller cannot get the
/// password without a capture that clears the liveness gate and matches the
/// enrolled templates. Clearing the gate is evidence, not proof, that a live
/// person is present: the single-frame IR cues are defeatable by a good print
/// (docs/PAD_SELFTEST.md), which is why this path additionally requires the
/// temporal consent gesture by default. We log the decision + cosine score, but
/// never the password or its length.
/// Deny-line score display: exact under IRLUME_LOG=debug tracing, else
/// quantized to one decimal (anti-oracle; see comment at the deny log).
fn deny_score(s: f32) -> String {
    if irlume_common::dbglog::on() {
        format!("{s:.4}")
    } else {
        format!("~{s:.1}")
    }
}

/// Prose tokens that legitimately contain digits and must survive redaction:
/// dimension labels and the emitter wavelength. FAIL-CLOSED: the redactor keeps
/// ONLY these exact tokens; every other number (including a future unit-suffixed
/// measurement like `12ms` or `3px`) is stripped by default, so adding a new
/// numeric cue to a deny reason can't silently defeat the redaction.
const REASON_PROSE_KEEP: &[&str] = &["2D", "3D", "850nm"];

/// Journal-side deny-reason display. Deny reasons embed measured values
/// ("IR too flat (1.02)", "rgb 0.35") as coaching for a genuine false reject,
/// but in the JOURNAL those same numbers are per-attempt feedback a spoofer
/// could tune against. The exact reason still goes back over IPC to the
/// session's own TUI/CLI; here we strip every numeric payload unless tracing is
/// on, keeping only the [`REASON_PROSE_KEEP`] tokens.
fn deny_reason(r: &str) -> String {
    if irlume_common::dbglog::on() {
        return r.to_string();
    }
    let cs: Vec<char> = r.chars().collect();
    let mut out = String::with_capacity(r.len());
    let mut i = 0;
    while i < cs.len() {
        if cs[i].is_ascii_digit() {
            // Grab the number, then any glued alpha suffix (a unit or a prose
            // tail like the "D" in "2D") so we can test the whole token.
            let start = i;
            while i < cs.len() && (cs[i].is_ascii_digit() || cs[i] == '.') {
                i += 1;
            }
            let mut num_end = i;
            while num_end > start && cs[num_end - 1] == '.' {
                num_end -= 1;
            } // sentence period, not a decimal
            let mut tok_end = num_end;
            while tok_end < cs.len() && cs[tok_end].is_ascii_alphabetic() {
                tok_end += 1;
            }
            let token: String = cs[start..tok_end].iter().collect();
            // An identifier (digits glued AFTER letters, e.g. "PCR7") is a name,
            // not a measurement; keep it. Otherwise keep only allowlisted prose.
            let is_ident = start > 0 && cs[start - 1].is_ascii_alphabetic();
            if is_ident || REASON_PROSE_KEEP.contains(&token.as_str()) {
                out.extend(&cs[start..tok_end]);
                i = tok_end;
            } else {
                out.push('…');
                out.extend(&cs[num_end..i]); // keep a trailing '.' that was a sentence period
            }
        } else {
            out.push(cs[i]);
            i += 1;
        }
    }
    out
}

/// The purpose every credential release runs under. Releasing the sealed password
/// hands over a REUSABLE secret rather than one session, so by default the face
/// match must be followed by a deliberate gesture (a nod, or a calibrated eye
/// closure).
///
/// The setting is read here, per request, so `irlume credential-release-challenge
/// off` takes effect without a daemon restart; the engine receives the decision,
/// not the policy lookup.
fn credential_release_purpose() -> irlume_auth::AuthenticationPurpose {
    irlume_auth::AuthenticationPurpose::CredentialRelease {
        temporal_challenge: irlume_common::config::credential_release_challenge(),
    }
}

fn do_unseal_password(
    user: &str,
    service: Option<&str>,
    engine: &mut irlume_auth::Engine,
) -> Response {
    eprintln!("irlumed: UnsealPassword: attempt for '{user}'");
    let t = std::time::Instant::now();
    if !irlume_core::keyring::has_sealed_password(user) {
        return Response::Error(format!(
            "no sealed password for '{user}': run `irlume keyring arm`"
        ));
    }
    // Same failure throttle as the login/sudo path: after a run of failures,
    // skip the camera and let PAM fall to the password.
    if rate_limited(user) {
        return Response::Error("too many recent face attempts; use your password".into());
    }
    let outcome = match engine.authenticate_for(user, service, credential_release_purpose()) {
        Ok(o) => o,
        Err(e) => {
            // A PCR-drift here is the ENROLLED-TEMPLATE key failing to unseal (it
            // is TPM-sealed to the same PCRs), so the daemon can't decrypt the face
            // to match at all: face auth is locked until the template key is
            // re-bound. `keyring arm` won't fix it (that only re-seals the
            // password); the user must re-enroll or run `irlume recovery restore`.
            let hint = if is_pcr_drift(&e) {
                " -- a firmware/Secure Boot change locked your enrolled face; re-enroll or run `irlume recovery restore`"
            } else {
                ""
            };
            eprintln!("irlumed: UnsealPassword: capture/auth failed for '{user}': {e}{hint}");
            return Response::Error(e.to_string());
        }
    };
    rate_record(
        user,
        outcome.granted,
        !irlume_auth::presence_retryable(&outcome),
    );
    if !outcome.granted {
        // Denied-attempt scores are QUANTIZED to one decimal unless tracing is
        // on: a 4-decimal score after every try is a gradient a journal-reading
        // attacker could climb to tune a spoof. One decimal still separates
        // "borderline" from "not even close" for false-reject diagnosis.
        eprintln!(
            "irlumed: UnsealPassword: denied for '{user}' (live={}, score {}: {}) -> password",
            outcome.live,
            deny_score(outcome.score),
            deny_reason(&outcome.reason)
        );
        return Response::Error(format!("face not granted: {}", outcome.reason));
    }
    // See the UnsealKeyring path: one load, so the bytes and their kind always
    // come from the same envelope.
    match irlume_core::keyring::unseal_secret(user) {
        Ok(unsealed) => {
            eprintln!(
                "irlumed: UnsealPassword: OK for '{user}' (score {:.4}), {} unsealed",
                outcome.score,
                unsealed.kind.describe()
            );
            irlume_common::dlog!(
                "unseal '{user}' total {}ms (face + TPM)",
                t.elapsed().as_millis()
            );
            Response::PasswordUnsealed {
                kind: crate::users::core_to_wire_kind(unsealed.kind),
                secret: irlume_common::SecretBytes::new(unsealed.secret.to_vec()),
            }
        }
        // Face matched but the TPM could not release the secret (e.g. PCR drift
        // after a Secure Boot config change). This is the line that explains a
        // face login that nonetheless leaves the keyring locked.
        Err(e) => {
            // Here the template key unsealed (face matched) but the PASSWORD seal
            // did not. A PCR drift on this path is fixed by re-binding the password
            // with `irlume keyring arm` (the enrolled face still works).
            let hint = if is_pcr_drift(&e) {
                " -- re-run `irlume keyring arm` to re-bind the password to the current PCRs"
            } else {
                ""
            };
            eprintln!(
                "irlumed: UnsealPassword: face matched for '{user}' (score {:.4}) but TPM unseal FAILED: {e}{hint}",
                outcome.score
            );
            Response::Error(e.to_string())
        }
    }
}

/// A PCR-drift unseal failure (Secure Boot / firmware / dbx change moved a bound
/// PCR). [`irlume_core::tpm`] tags these where the error is built, so the
/// daemon can print the right remedy without re-reading the TPM.
fn is_pcr_drift(e: &irlume_common::Error) -> bool {
    irlume_core::tpm::is_pcr_mismatch(e)
}

fn respond(mut stream: UnixStream, resp: &Response) -> std::io::Result<()> {
    let mut json = serde_json::to_vec(resp)?;
    json.push(b'\n');
    stream.write_all(&json)?;
    let r = stream.flush();
    // The response may carry an unsealed secret (PasswordUnsealed); wipe the
    // serialized line, same hygiene as the request path and the client side.
    json.zeroize();
    r
}

/// Mode for the control socket. Every local uid may connect; `SO_PEERCRED`
/// decides what each one may then do. See the note at the bind site for why a
/// group-restricted mode was removed rather than repaired.
const DAEMON_SOCKET_MODE: u32 = 0o666;

fn set_mode(path: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The #340 trigger rule: enrollment probes exactly the unmeasured pair.
    /// A stored verdict of either value suppresses the probe entirely, which
    /// is also the fail-closed half: enrolling again can never re-measure or
    /// overwrite a measured camera.
    #[test]
    fn enrollment_probes_exactly_when_no_verdict_is_stored() {
        use std::cell::Cell;
        let ran = Cell::new(false);
        let note = enroll_capture_probe_note(true, None, || {
            ran.set(true);
            Ok("capture mode sequential for this camera: probed".into())
        });
        assert!(ran.get(), "an unmeasured pair must be probed");
        assert_eq!(
            note.as_deref(),
            Some("capture mode sequential for this camera: probed")
        );
        for stored in [
            irlume_auth::CaptureMode::Concurrent,
            irlume_auth::CaptureMode::Sequential,
        ] {
            let ran = Cell::new(false);
            let note = enroll_capture_probe_note(true, Some(stored), || {
                ran.set(true);
                Ok("must not run".into())
            });
            assert!(
                !ran.get(),
                "a stored {stored:?} verdict must suppress the probe"
            );
            assert_eq!(note, None, "{stored:?}");
        }
    }

    /// A camera without a stable identity (a v4l2loopback node, the CI
    /// feeder) is never probed: its verdict cannot be keyed into
    /// cameras.conf, so the probe would re-run on every enrollment and store
    /// nothing.
    #[test]
    fn an_unidentifiable_camera_is_never_probed_at_enrollment() {
        use std::cell::Cell;
        let ran = Cell::new(false);
        let note = enroll_capture_probe_note(false, None, || {
            ran.set(true);
            Ok("must not run".into())
        });
        assert!(!ran.get());
        assert_eq!(note, None);
    }

    /// A failed probe reports and lets the enrollment proceed under the
    /// sequential default; it must not surface as an enrollment error.
    #[test]
    fn a_failed_enrollment_probe_reports_instead_of_blocking() {
        let note =
            enroll_capture_probe_note(true, None, || Err("the camera stopped answering".into()))
                .expect("a probe that ran always leaves a note");
        assert!(note.contains("the camera stopped answering"), "{note}");
        assert!(note.contains("one-at-a-time capture"), "{note}");
    }

    /// A ContentionReport whose arms carry exactly these observations.
    fn contention_report(
        seq: (usize, usize, f32, f32),
        conc: (usize, usize, f32, f32),
    ) -> irlume_auth::ContentionReport {
        let sample = |(rounds, failed, rgb_mean, ir_mean): (usize, usize, f32, f32)| {
            irlume_auth::PairSample {
                rgb_mean,
                ir_mean,
                total_ms: 100.0,
                rounds,
                failed,
            }
        };
        irlume_auth::ContentionReport {
            sequential: sample(seq),
            concurrent: sample(conc),
        }
    }

    /// Store policy (#340 plus its review round): an explicit `camera-tune`
    /// persists any verdict (its summary carries the caveats), while the
    /// automatic enrollment probe persists only a verdict backed by every
    /// requested round in both arms AND a conclusive scene. One lucky round
    /// per arm with five errors each is the review's exact scenario: bright
    /// enough to read conclusive, far too thin to become durable policy.
    #[test]
    fn only_a_conclusive_fully_backed_verdict_is_storable_from_the_enrollment_probe() {
        use ProbeStore::{Always, ConclusiveOnly};
        // Every requested round completed, lit scene: storable everywhere.
        let full = contention_report((6, 0, 120.0, 100.0), (6, 0, 118.0, 98.0));
        assert!(probe_verdict_storable(ConclusiveOnly, &full, 6));
        assert!(probe_verdict_storable(Always, &full, 6));
        // One good round and five errors per arm, same brightness:
        // conclusive() says yes, the evidence bar says no.
        let thin = contention_report((1, 5, 120.0, 100.0), (1, 5, 118.0, 98.0));
        assert!(thin.conclusive(), "precondition: brightness alone passes");
        assert!(!probe_verdict_storable(ConclusiveOnly, &thin, 6));
        assert!(probe_verdict_storable(Always, &thin, 6));
        // Complete rounds in a dim room: inconclusive, not storable.
        let dim = contention_report((6, 0, 50.0, 100.0), (6, 0, 49.0, 98.0));
        assert!(!probe_verdict_storable(ConclusiveOnly, &dim, 6));
        assert!(probe_verdict_storable(Always, &dim, 6));
        // Concurrent impossible with EVERY attempt errored: the trailing
        // control already vouched, storable.
        let impossible = contention_report((6, 0, 120.0, 100.0), (0, 6, 0.0, 0.0));
        assert!(impossible.concurrent_impossible(), "precondition");
        assert!(probe_verdict_storable(ConclusiveOnly, &impossible, 6));
        // Concurrent impossible but only half the attempts on record: thin
        // evidence again, not storable automatically.
        let partial_impossible = contention_report((6, 0, 120.0, 100.0), (0, 3, 0.0, 0.0));
        assert!(!probe_verdict_storable(
            ConclusiveOnly,
            &partial_impossible,
            6
        ));
        assert!(probe_verdict_storable(Always, &partial_impossible, 6));
    }

    /// The Enroll arm's wiring (#340 review): on an unmeasured pair the probe
    /// runs BEFORE the capture, and enrollment runs whatever the probe said;
    /// on a measured pair only the capture runs.
    #[test]
    fn enroll_orchestration_probes_before_capture_and_always_enrolls() {
        let events = std::sync::Mutex::new(Vec::new());
        let resp = enroll_with_capture_probe(
            true,
            None,
            || {
                events.lock().unwrap().push("probe");
                Ok("probed".into())
            },
            || {
                events.lock().unwrap().push("enroll");
                Response::Ok("enrolled".into())
            },
        );
        assert!(matches!(resp, Response::Ok(ref m) if m == "enrolled"));
        assert_eq!(*events.lock().unwrap(), ["probe", "enroll"]);
        // A failing probe still enrolls.
        let events = std::sync::Mutex::new(Vec::new());
        let resp = enroll_with_capture_probe(
            true,
            None,
            || Err("probe broke".into()),
            || {
                events.lock().unwrap().push("enroll");
                Response::Ok("enrolled".into())
            },
        );
        assert!(matches!(resp, Response::Ok(_)));
        assert_eq!(*events.lock().unwrap(), ["enroll"]);
        // A measured pair goes straight to capture.
        let events = std::sync::Mutex::new(Vec::new());
        let resp = enroll_with_capture_probe(
            true,
            Some(irlume_auth::CaptureMode::Concurrent),
            || {
                events.lock().unwrap().push("probe");
                Ok("must not run".into())
            },
            || {
                events.lock().unwrap().push("enroll");
                Response::Ok("enrolled".into())
            },
        );
        assert!(matches!(resp, Response::Ok(_)));
        assert_eq!(*events.lock().unwrap(), ["enroll"]);
    }

    #[test]
    fn verifiable_shadow_hash_extracts_and_skips_unverifiable() {
        let shadow = "root:$6$abc$hash:19000:0:99999:7:::\n\
                      alice:$y$j9T$salt$realhash:19000::::::\n\
                      locked:!$6$x$y:19000::::::\n\
                      disabled:*:19000::::::\n\
                      nopw::19000::::::\n";
        // A real hash comes back for verification.
        assert_eq!(
            verifiable_shadow_hash(shadow, "alice").as_deref(),
            Some("$y$j9T$salt$realhash")
        );
        // Locked / disabled / empty / absent all read None → the caller must NOT
        // block the seal (absence of proof is not proof of a wrong password).
        for u in ["locked", "disabled", "nopw", "ghost"] {
            assert_eq!(verifiable_shadow_hash(shadow, u), None, "{u}");
        }
    }

    #[test]
    fn is_pcr_drift_matches_the_real_error_shape() {
        use irlume_common::Error;
        // The exact message tpm::policy_aware_err produces on a PCR move.
        let drift = Error::Policy(
            "a policy check failed (associated with session number 1): PCR mismatch: [7] changed since seal".into(),
        );
        assert!(is_pcr_drift(&drift));
        // A generic policy error (e.g. no signed policy) is NOT a drift.
        assert!(!is_pcr_drift(&Error::Policy(
            "no signed PCR policy matches".into()
        )));
        // A non-policy TPM error (corrupt blob, TPM cleared) is not a drift either.
        assert!(!is_pcr_drift(&Error::Tpm(
            "structure is the wrong size".into()
        )));
    }

    #[test]
    fn root_and_self_authorized_others_denied() {
        let root = Peer {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        // uid_of relies on /etc/passwd; just exercise the root path deterministically.
        assert!(authorized_for(&root, "nonexistent-user"));
    }

    // Regression: d793a27. Request::Identify was an unauthenticated 1:N
    // similarity oracle: any local peer got a cross-user search plus the exact
    // score. Root keeps the full search; a non-root peer is scoped to its own
    // account; a peer with no local account gets no search at all.
    #[test]
    fn identify_scope_confines_non_root_peers_to_their_own_account() {
        let peer = |uid| Peer {
            uid,
            gid: uid,
            pid: 1,
        };
        assert_eq!(identify_scope(&peer(0)), IdentifyScope::Full);
        // The uid running this test resolves to a real account; its scope must
        // be exactly that username, never Full.
        let me = unsafe { libc::geteuid() };
        if me != 0 {
            let name = users::name_for_uid(me).expect("test uid has an account");
            assert_eq!(identify_scope(&peer(me)), IdentifyScope::SelfOnly(name));
        }
        // A uid outside the account database is denied any scope.
        assert_eq!(identify_scope(&peer(0xfffe_fffe)), IdentifyScope::NoAccount);
        // Ground the reverse lookup itself (added by the same fix).
        assert_eq!(users::name_for_uid(0).as_deref(), Some("root"));
    }

    #[test]
    fn dry_run_emitter_probe_shares_the_camera_interval() {
        let _g = env_lock();
        let mut e = engine();
        clear_camera_probe_rate_state();
        // The probe opens the shared camera node, is unauthenticated, and is
        // reachable by any local uid now that the socket admits them, so a
        // second immediate attempt from the same uid must be refused.
        let first = dispatch(
            Request::SetupIrEmitter { dry_run: true },
            &peer(NOBODY),
            &mut e,
        );
        let Response::Error(first) = first else {
            panic!("expected the absent-camera error, got {first:?}");
        };
        assert!(!first.contains("rate limited"), "first attempt: {first}");

        match dispatch(
            Request::SetupIrEmitter { dry_run: true },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("rate limited"), "{msg}"),
            other => panic!("second immediate probe must be throttled, got {other:?}"),
        }

        // Root is the PAM/greeter path and is never delayed.
        clear_camera_probe_rate_state();
        for _ in 0..2 {
            match dispatch(Request::SetupIrEmitter { dry_run: true }, &peer(0), &mut e) {
                Response::Error(msg) => assert!(!msg.contains("rate limited"), "{msg}"),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn identify_rate_limit_is_per_uid_and_exempts_root() {
        let uid = 0xfffe_fffd;
        let other_uid = 0xfffe_fffc;

        assert!(!camera_probe_rate_limited(uid));
        assert!(camera_probe_rate_limited(uid));
        assert!(!camera_probe_rate_limited(other_uid));
        assert!(!camera_probe_rate_limited(0));
        assert!(!camera_probe_rate_limited(0));
    }

    // Regression: 834c71e. IRLUME_MODELS_STRICT=1 refused to start because the
    // daemon still verified the OPTIONAL IR adapter at its default path even
    // though none ships since ADR-0004. A missing adapter must be excluded
    // from verification; a present one is still verified.
    #[test]
    fn missing_optional_adapter_is_not_verified() {
        let shipped = [
            "/etc/irlume/det.onnx",
            "/etc/irlume/face.onnx",
            "/etc/irlume/face_landmarks_detector.tflite",
            "/etc/irlume/blaze_face_short_range.onnx",
        ];
        assert_eq!(
            models_to_verify(shipped, "/nonexistent/irlume-test/ir_adapter.onnx"),
            shipped.to_vec(),
            "a missing optional adapter must not reach verify_models"
        );
        // An adapter that actually exists is still checked.
        let dir =
            std::env::temp_dir().join(format!("irlume-daemon-adapter-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let adapter = dir.join("ir_adapter.onnx");
        std::fs::write(&adapter, b"weights").unwrap();
        let ap = adapter.to_string_lossy().into_owned();
        let v = models_to_verify(shipped, &ap);
        assert_eq!(v.len(), 5);
        assert_eq!(v[4], ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Startup asks for one model and gets back exactly that file's bytes with
    // exactly the digest this loop checked; every other path is verified and
    // dropped as before (#346). A mutant that hands back the wrong file, or one
    // that keeps something it never verified, fails below.
    #[test]
    fn verify_models_hands_back_the_model_it_was_asked_for_with_its_digest() {
        let dir = std::env::temp_dir().join(format!("irlume-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let wanted = dir.join("recognizer.onnx");
        let other = dir.join("other.onnx");
        std::fs::write(&wanted, b"recognizer weights").unwrap();
        std::fs::write(&other, b"some other model").unwrap();
        let (w, o) = (
            wanted.to_str().unwrap().to_string(),
            other.to_str().unwrap().to_string(),
        );

        let kept = verify_models(&[&o, &w], Some(&w)).expect("the asked-for model comes back");
        assert_eq!(
            kept.bytes(),
            b"recognizer weights",
            "the requested model's own bytes must come back"
        );
        // The digest travels WITH those bytes, which is what lets the engine
        // tag the embedding space without hashing 260MB a second time.
        assert_eq!(
            kept.sha256(),
            irlume_common::sha256_hex(b"recognizer weights"),
            "the digest must be of the bytes handed back"
        );
        assert!(
            verify_models(&[&o, &w], None).is_none(),
            "asking for nothing keeps nothing"
        );
        assert!(
            verify_models(&[&o], Some(&w)).is_none(),
            "a model that was never verified must not be handed back"
        );
        // Non-strict, unreadable: the loader reports it, and nothing invented
        // is handed over in the meantime.
        assert!(
            verify_models(&[&o], Some("/nonexistent/irlume-test/face.onnx")).is_none(),
            "an unread model must not produce bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The verified bytes must reach the ONNX session WITHOUT the recognizer
    // path being opened again (#346). Both halves matter: the first proves the
    // byte path never touches the file, the second proves the assertion has
    // teeth, because reintroducing a read is exactly what makes the missing
    // path show up in the error.
    #[test]
    fn the_verified_recognizer_bytes_load_without_reading_the_path() {
        let det = "/nonexistent/irlume-test/det.onnx";
        let model = "/nonexistent/irlume-test/face.onnx";
        // `Engine` is not Debug, so unwrap the Result by hand.
        let why = |r: irlume_common::Result<irlume_auth::Engine>| match r {
            Ok(_) => panic!("no model file exists here, so a load cannot succeed"),
            Err(e) => e.to_string(),
        };
        let weights = irlume_common::HashedModel::new(b"pinned recognizer weights".to_vec());
        let err = why(load_shipped_recognizer(det, model, Some(&weights)));
        assert!(
            !err.contains(model),
            "the recognizer path was read despite bytes in hand: {err}"
        );
        // No bytes: the post-panic rebuild, which does read the path.
        let err = why(load_shipped_recognizer(det, model, None));
        assert!(
            err.contains(model),
            "the rebuild must read the recognizer path: {err}"
        );
    }

    // An invalid explicit third_party_recognizer selection must REFUSE TO
    // START, never silently substitute the shipped recognizer: that would run
    // a different grant-capable decision system than the operator selected
    // (#279 review). resolve_thirdparty_recognizer exits the process, so
    // re-exec this test binary as the child that makes the call.
    #[test]
    fn recognizer_selection_failures_refuse_to_start() {
        if std::env::var("IRLUME_TEST_RECOGNIZER_CHILD").is_ok() {
            // Child: resolution of the env-selected name must exit(1) inside
            // this call for both an unknown name and a wrong-stage name.
            let _ = resolve_thirdparty_recognizer();
            return; // reaching this line means the selection was NOT refused
        }
        let exe = std::env::current_exe().unwrap();
        let run = |selection: &str| {
            std::process::Command::new(&exe)
                .args([
                    "tests::recognizer_selection_failures_refuse_to_start",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("IRLUME_TEST_RECOGNIZER_CHILD", "1")
                .env("IRLUME_THIRDPARTY_RECOGNIZER", selection)
                .output()
                .unwrap()
        };
        // Not in the catalog at all.
        let out = run("ghost");
        assert!(!out.status.success(), "an unknown selection must refuse");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("refused (NotInCatalog)") && err.contains("falls back to the password"),
            "stderr was: {err}"
        );
        // In the catalog, but a PAD model: naming it as THE recognizer is
        // nonsense the daemon must refuse, not reinterpret.
        let out = run("flir");
        assert!(!out.status.success(), "a wrong-stage selection must refuse");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("refused (WrongStage(\"pad\"))"),
            "stderr was: {err}"
        );
        // StageClosed is unreachable until a Recognition entry exists in the
        // catalog; the decision itself is pinned in irlume-common's tests.
    }

    // Regression: 834c71e (companion guard). Excluding the optional adapter
    // must not soften strict mode for the SHIPPED models: under
    // IRLUME_MODELS_STRICT=1 an unreadable/deleted shipped model still refuses
    // to start. verify_models exits the process, so re-exec this test binary
    // as the child that makes the call.
    #[test]
    fn strict_verify_still_refuses_a_missing_shipped_model() {
        if std::env::var("IRLUME_TEST_VERIFY_CHILD").is_ok() {
            // Child: strict verify of an unreadable model must exit(1) here.
            verify_models(&["/nonexistent/irlume-test/det.onnx"], None);
            return; // reaching this line means strict did NOT refuse
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "tests::strict_verify_still_refuses_a_missing_shipped_model",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("IRLUME_TEST_VERIFY_CHILD", "1")
            .env("IRLUME_MODELS_STRICT", "1")
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "strict verify of a missing shipped model must refuse to start"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("refusing to start"), "stderr was: {err}");
    }

    // Regression: 965d64e. The daemon collapsed EnrollOutcome::New and
    // ::Merged into Response::Ok(String), so the TUI could not tell a merge
    // from a new profile and aborted with "no face profile". The engine itself
    // needs camera + models, so the response-construction seam is what a unit
    // test can pin: Merged maps to Enrolled with created:false and the exact
    // appended scan names (the undo handle), New to created:true.
    #[test]
    fn the_enrollment_summary_counts_scans_per_recognizer() {
        // #288: a profile can hold several recognizers' templates and only
        // the loaded one's can match, so the summary carries the per-space
        // counts and which space is live. A bare total would let a profile
        // look usable when none of its scans belong to the loaded model.
        use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};
        let scan = |name: &str, space: Option<&str>| FaceScan {
            name: name.into(),
            rgb: vec![0.0; 4],
            ir: None,
            ir_space: None,
            embed_space: space.map(str::to_string),
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        };
        let enr = Enrollment {
            user: "u".into(),
            profiles: vec![FaceProfile {
                name: "P".into(),
                ir_calib: None,
                ir_calibs: Default::default(),
                scans: vec![
                    scan("a", Some("embed:model-a")),
                    scan("b", Some("embed:model-a")),
                    scan("c", Some("embed:model-b")),
                    // Untagged: belongs to the recognizer that predates
                    // tagging, the same rule matching applies.
                    scan("legacy", None),
                ],
            }],
            ..Default::default()
        };
        let sum = summarize_enrollment(Some(&enr), "embed:model-b");
        let p = &sum.profiles[0];
        assert_eq!(p.scans.len(), 4, "the flat list is unchanged");
        assert_eq!(p.scans_by_recognizer.get("embed:model-a"), Some(&2));
        assert_eq!(p.scans_by_recognizer.get("embed:model-b"), Some(&1));
        assert_eq!(
            p.scans_by_recognizer
                .get(irlume_core::storage::LEGACY_RECOGNIZER_SPACE),
            Some(&1),
            "untagged scans count under the recognizer that predates tagging"
        );
        assert_eq!(p.live_recognizer.as_deref(), Some("embed:model-b"));
    }

    #[test]
    fn enroll_merge_reports_created_false_with_the_added_scans() {
        let merged = enroll_response(irlume_auth::EnrollOutcome::Merged {
            name: "Face Profile 1".into(),
            added: 1,
            total: 8,
            room: 22,
            added_scans: vec!["Face Scan 8".into()],
            ambient_lit: 1,
        });
        match merged {
            Response::Enrolled {
                profile,
                created,
                added,
                total,
                room,
                added_scans,
                ambient_lit,
            } => {
                assert_eq!(profile, "Face Profile 1");
                assert_eq!(
                    ambient_lit,
                    Some(1),
                    "the ambient-lit count must reach the client as Some, so \
                     an older daemon's silence (None) stays distinguishable"
                );
                assert!(!created, "a merge must not claim a new profile was created");
                assert_eq!((added, total), (1, 8));
                assert_eq!(
                    room,
                    Some(22),
                    "the daemon's per-recognizer room must reach the client, not \
                     be recomputed there from the profile-wide total"
                );
                assert_eq!(added_scans, vec!["Face Scan 8".to_string()]);
            }
            other => panic!("merge must answer Enrolled, got {other:?}"),
        }
        let new = enroll_response(irlume_auth::EnrollOutcome::New {
            name: "Face Profile 2".into(),
            scans: 3,
            ambient_lit: 0,
        });
        match new {
            Response::Enrolled {
                created,
                added,
                total,
                added_scans,
                ..
            } => {
                assert!(created);
                assert_eq!((added, total), (3, 3));
                assert!(added_scans.is_empty());
            }
            other => panic!("new enroll must answer Enrolled, got {other:?}"),
        }
    }

    #[test]
    fn deny_reason_strips_measurements_keeps_prose() {
        // (tracing is off in tests; IRLUME_LOG unset)
        assert_eq!(
            deny_reason("IR too flat (center/edge 1.02); looks 2D, not a 3D face"),
            "IR too flat (center/edge …); looks 2D, not a 3D face"
        );
        assert_eq!(deny_reason("IR face too dark (42)"), "IR face too dark (…)");
        assert_eq!(
            deny_reason("below threshold (rgb 0.35, fusion+ir-fallback miss)"),
            "below threshold (rgb …, fusion+ir-fallback miss)"
        );
        // allowlisted prose (dimension labels, wavelength) survives
        assert_eq!(
            deny_reason("a real face reflects 850nm"),
            "a real face reflects 850nm"
        );
        assert_eq!(deny_reason("looks 2D not 3D"), "looks 2D not 3D");
        // identifiers (digits glued after letters) survive as names
        assert_eq!(deny_reason("PCR7 drift"), "PCR7 drift");
        // FAIL-CLOSED: a future unit-suffixed measurement is still redacted
        assert_eq!(deny_reason("gap 3px wide"), "gap …px wide");
        assert_eq!(deny_reason("took 12ms"), "took …ms");
        assert_eq!(deny_reason("margin 0.5x"), "margin …x");
        // trailing sentence period survives a float at end of sentence
        assert_eq!(deny_reason("floor 1.12."), "floor ….");
        // no numbers -> unchanged
        assert_eq!(
            deny_reason("'ghost' is not enrolled"),
            "'ghost' is not enrolled"
        );
    }

    /// Tests that mutate process env vars serialize here (setenv/getenv are
    /// process-global and the harness runs tests concurrently).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn deny_score_is_quantized_to_one_decimal_without_tracing() {
        // IRLUME_LOG is unset in the test env, so the anti-oracle quantization
        // applies: one decimal, ~-prefixed, never the 4-decimal exact score.
        assert_eq!(deny_score(0.4321), "~0.4");
        assert_eq!(deny_score(0.06), "~0.1"); // rounds, still one decimal
        assert_eq!(deny_score(0.0), "~0.0");
    }

    #[test]
    fn valid_username_rejects_traversal_and_junk() {
        // Accepted: ordinary local, NSS, and samba-machine account shapes.
        for ok in ["alice", "u", "user_1", "web-svc", "a.b-c", "host$", "x1.y2"] {
            assert!(valid_username(ok), "{ok:?} must be accepted");
        }
        // Rejected: empty, oversized, leading '-'/'.', separators, traversal.
        let long = "a".repeat(65);
        for bad in [
            "",
            long.as_str(),
            "-flag",
            ".hidden",
            "..",
            "../root",
            "a/b",
            "a b",
            "tab\tname",
            "new\nline",
            "nul\0byte",
            "café",
            "semi;colon",
        ] {
            assert!(!valid_username(bad), "{bad:?} must be rejected");
        }
        // Boundary: exactly 64 bytes is still legal.
        assert!(valid_username(&"a".repeat(64)));
    }

    #[test]
    fn request_user_extracts_the_user_from_every_user_bearing_variant() {
        use irlume_common::SecretBytes;
        let u = || "carol".to_string();
        let secret = || SecretBytes::new(b"pw".to_vec());
        let carrying: Vec<Request> = vec![
            Request::Authenticate {
                user: u(),
                service: Some("sudo".into()),
            },
            Request::Enroll {
                user: u(),
                profile: None,
                scans: None,
                reset: false,
            },
            Request::ListProfiles {
                user: u(),
                structured_errors: false,
            },
            Request::DeleteProfile {
                user: u(),
                profile: "p".into(),
            },
            Request::DeleteScan {
                user: u(),
                profile: "p".into(),
                scan: "s".into(),
            },
            Request::RenameProfile {
                user: u(),
                profile: "p".into(),
                new_name: "q".into(),
            },
            Request::RenameScan {
                user: u(),
                profile: "p".into(),
                scan: "s".into(),
                new_name: "t".into(),
            },
            Request::AddScan {
                user: u(),
                profile: "p".into(),
                scans: None,
                report_enrollment: false,
            },
            Request::SetRequireEyesOpen {
                user: u(),
                on: true,
            },
            Request::SetRequireChallenge {
                user: u(),
                on: false,
            },
            Request::SealPassword {
                kind: None,
                user: u(),
                password: secret(),
            },
            Request::UnsealPassword {
                user: u(),
                service: None,
            },
            Request::UnsealKeyring {
                user: u(),
                service: None,
                have_password: false,
            },
            Request::HasSealedPassword { user: u() },
            Request::KeyringInfo { user: u() },
            Request::ForgetPassword { user: u() },
            Request::ResealPassword {
                user: u(),
                password: secret(),
            },
            Request::RecoveryStatus { user: u() },
            Request::RecoverySetup {
                user: u(),
                passphrase: secret(),
            },
            Request::RecoveryRestore {
                user: u(),
                passphrase: secret(),
            },
            Request::RecoveryForget { user: u() },
            Request::PositionSample { user: Some(u()) },
        ];
        for req in &carrying {
            assert_eq!(
                request_user(req),
                Some("carol"),
                "variant must expose its user for the traversal guard: {req:?}"
            );
        }
        // Variants with no user field must not invent one.
        let userless: Vec<Request> = vec![
            Request::Ping,
            Request::Health,
            Request::Identify,
            Request::SetCameras {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
            },
            Request::SetupIrEmitter { dry_run: true },
            Request::SelfTest {
                kind: irlume_common::SelfTestKind::Liveness,
            },
            Request::PositionSample { user: None },
        ];
        for req in &userless {
            assert_eq!(request_user(req), None, "no user in {req:?}");
        }
    }

    #[test]
    fn peer_cred_reports_our_own_identity_on_a_socketpair() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = peer_cred(&a).unwrap();
        assert_eq!(peer.uid, unsafe { libc::geteuid() });
        assert_eq!(peer.gid, unsafe { libc::getegid() });
        assert_eq!(peer.pid, std::process::id() as i32);
    }

    /// Serialize the tests that mutate the process-global enrollment-summary
    /// cache for the same username. libtest runs tests in parallel, so
    /// without this one test's `publish` lands inside another's miss window
    /// and turns a real pass into an intermittent failure (or worse, a false
    /// pass in a mutation run, which is how a flake becomes a lie about
    /// coverage).
    ///
    /// This is `env_lock()` and not a lock of its own: `sandbox()` clears the
    /// whole cache, so a sandbox test would otherwise be free to wipe the map
    /// between a cache test's `publish` and its read, turning the hit these
    /// tests assert into a miss. One lock covers both kinds of shared state.
    /// No test acquires both helpers, so this cannot recurse.
    fn enrollment_summary_test_lock() -> std::sync::MutexGuard<'static, ()> {
        env_lock()
    }

    /// While the engine loads, a request that needs it is REFUSED, not queued.
    ///
    /// Queueing would make a greeter's face attempt wait out model loading (14.26s
    /// measured on a ThinkPad X13) instead of falling through to the password, and
    /// an early caller would hold a slot for the length of startup. The refusal has
    /// to name the cause, because it reaches the user through PAM (#244).
    #[test]
    fn a_request_needing_the_engine_is_refused_while_it_loads() {
        use std::io::{BufRead, BufReader, Write};
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let arbiter = std::sync::Arc::new(arbiter::Arbiter::<Queued>::new());
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        (&ours)
            .write_all(
                format!("{{\"ListProfiles\":{{\"user\":\"{me}\",\"structured_errors\":false}}}}\n")
                    .as_bytes(),
            )
            .unwrap();
        let a = std::sync::Arc::clone(&arbiter);
        // The engine has NOT been published yet: exactly the startup window.
        let ready = std::sync::atomic::AtomicBool::new(false);
        std::thread::spawn(move || serve(theirs, &a, &ready).unwrap());

        let mut line = String::new();
        BufReader::new(&ours)
            .read_line(&mut line)
            .expect("a refusal within the deadline, not a wait for the engine");
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        match resp {
            Response::Error(e) => assert!(
                e.contains("still starting"),
                "the refusal must say why, it reaches the user through PAM: {e}"
            ),
            other => panic!("a request needing the engine must be refused, got {other:?}"),
        }
    }

    /// A Status request the connection thread CANNOT answer from memory must
    /// reach the worker, not be answered with an error.
    ///
    /// Shipped broken once: `serve` turned `dispatch_status`'s `None` (an
    /// unpublished enrollment summary) into `Error("not a status request")`,
    /// so the miss never reached the worker, nothing ever published, and
    /// every listing on the machine failed. The bug survived a hardware
    /// check that compared two response BODIES for equality without
    /// asserting their type: both were the same error.
    #[test]
    fn an_unpublished_listing_reaches_the_worker_instead_of_erroring() {
        let _summary_guard = enrollment_summary_test_lock();
        let me = users::name_for_uid(unsafe { libc::getuid() }).unwrap_or_else(|| "root".into());
        invalidate_enrollment_summary(&me);

        let arbiter = std::sync::Arc::new(arbiter::Arbiter::<Queued>::new());
        let worker = {
            let arbiter = std::sync::Arc::clone(&arbiter);
            std::thread::spawn(move || {
                while let Some(job) = arbiter.take() {
                    let Queued { req, reply, .. } = job.payload;
                    arbiter.finish(job.class, job.uid);
                    // Stand in for the real load: the worker is what answers
                    // a miss, and what publishes the summary afterwards.
                    let resp = match req {
                        Request::ListProfiles { .. } => Response::Enrollment {
                            profiles: vec![irlume_common::ProfileSummary {
                                name: "FromWorker".into(),
                                scans: vec!["s1".into()],
                                scans_by_recognizer: Default::default(),
                                live_recognizer: None,
                            }],
                            require_eyes_open: false,
                            require_challenge: false,
                            closure_calibrated: false,
                            ir_ratio_calibrated: false,
                        },
                        _ => Response::Pong,
                    };
                    let _ = reply.send(resp);
                }
            })
        };

        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        (&ours)
            .write_all(
                format!("{{\"ListProfiles\":{{\"user\":\"{me}\",\"structured_errors\":false}}}}\n")
                    .as_bytes(),
            )
            .unwrap();
        let a = std::sync::Arc::clone(&arbiter);
        // These cover the SERVING daemon; the not-ready path has its own test.
        let ready = std::sync::atomic::AtomicBool::new(true);
        std::thread::spawn(move || serve(theirs, &a, &ready).unwrap());

        let mut line = String::new();
        BufReader::new(&ours)
            .read_line(&mut line)
            .expect("an answer within the deadline");
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        match resp {
            Response::Enrollment { profiles, .. } => {
                assert_eq!(
                    profiles.first().map(|p| p.name.as_str()),
                    Some("FromWorker")
                )
            }
            other => panic!("a cache miss must be served by the worker, got {other:?}"),
        }

        arbiter.close();
        worker.join().unwrap();
    }

    #[test]
    fn serve_routes_a_request_through_the_arbiter_and_answers_the_client() {
        // The whole path a client sees, minus the engine: parse, queue, worker,
        // reply. A fake worker stands in for the camera so this stays a test of
        // the wiring rather than of inference.
        let arbiter = std::sync::Arc::new(arbiter::Arbiter::<Queued>::new());
        let worker = {
            let arbiter = std::sync::Arc::clone(&arbiter);
            std::thread::spawn(move || {
                while let Some(job) = arbiter.take() {
                    let Queued { reply, .. } = job.payload;
                    arbiter.finish(job.class, job.uid);
                    let _ = reply.send(Response::Pong);
                }
            })
        };

        let (ours, theirs) = UnixStream::pair().unwrap();
        (&ours).write_all(b"\"Ping\"\n").unwrap();
        let a = std::sync::Arc::clone(&arbiter);
        // These cover the SERVING daemon; the not-ready path has its own test.
        let ready = std::sync::atomic::AtomicBool::new(true);
        std::thread::spawn(move || serve(theirs, &a, &ready).unwrap());

        let mut line = String::new();
        BufReader::new(&ours).read_line(&mut line).unwrap();
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(resp, Response::Pong), "got {resp:?}");

        arbiter.close();
        worker.join().unwrap();
    }

    /// The #212 invariant, both directions, with NO WORKER AT ALL: a status
    /// request must answer on the connection thread even while an
    /// authentication is queued and nobody drains the queue. Before this
    /// class existed, Ping sat in the queue behind whatever the worker was
    /// grinding (a 10.8s TPM-bound ListProfiles, measured), clients timed
    /// out, and short-budget pollers read a working daemon as down. If this
    /// test only passed because a worker drained the queue, it would hang.
    #[test]
    fn a_status_request_answers_while_the_queue_is_wedged_and_workerless() {
        let arbiter = std::sync::Arc::new(arbiter::Arbiter::<Queued>::new());
        // Wedge: an authentication sits queued forever (no worker exists).
        let (dead_reply, _keep) = std::sync::mpsc::channel();
        arbiter
            .submit(
                arbiter::Class::Auth,
                0,
                Queued {
                    req: Request::Ping,
                    peer: Peer {
                        uid: 0,
                        gid: 0,
                        pid: 0,
                    },
                    reply: dead_reply,
                },
            )
            .unwrap();

        for (wire, check) in [
            (
                "\"Ping\"\n".to_string(),
                Box::new(|r: &Response| matches!(r, Response::Pong))
                    as Box<dyn Fn(&Response) -> bool>,
            ),
            (
                // Own-uid query: authorized, answered from files, no engine.
                format!(
                    "{{\"HasSealedPassword\":{{\"user\":\"{}\"}}}}\n",
                    users::name_for_uid(unsafe { libc::getuid() }).unwrap_or_else(|| "root".into())
                ),
                Box::new(|r: &Response| matches!(r, Response::HasPassword(_))),
            ),
        ] {
            let (ours, theirs) = UnixStream::pair().unwrap();
            // A status answer comes from the connection thread in
            // microseconds; a regression queues it behind the wedge for the
            // full 300s worker budget. The client-side deadline turns that
            // hang into a fast, attributable failure.
            ours.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            (&ours).write_all(wire.as_bytes()).unwrap();
            let a = std::sync::Arc::clone(&arbiter);
            // These cover the SERVING daemon; the not-ready path has its own test.
            let ready = std::sync::atomic::AtomicBool::new(true);
            std::thread::spawn(move || serve(theirs, &a, &ready).unwrap());
            let mut line = String::new();
            BufReader::new(&ours)
                .read_line(&mut line)
                .expect("a status answer within the deadline");
            let resp: Response = serde_json::from_str(line.trim()).unwrap();
            assert!(check(&resp), "wedged queue must not delay status: {resp:?}");
        }
    }

    #[test]
    fn status_requests_classify_as_status_and_writers_stay_plain() {
        use arbiter::{classify, Class};
        let u = || "carol".to_string();
        for req in [
            Request::Ping,
            Request::Health,
            Request::HasSealedPassword { user: u() },
            Request::RecoveryStatus { user: u() },
            Request::ListProfiles {
                user: u(),
                structured_errors: false,
            },
        ] {
            assert_eq!(classify(&req), Class::Status, "{req:?}");
        }
        // KeyringInfo diagnoses PCRs, a TPM command; the physical TPM runs
        // one command at a time, so it serves from the worker with the
        // other TPM users, not from a connection thread.
        assert_eq!(classify(&Request::KeyringInfo { user: u() }), Class::Plain);
        // Mutating requests stay serialized on the worker: reclassifying one
        // as Status would let it race captures and other writers.
        for req in [
            Request::ForgetPassword { user: u() },
            Request::DeleteProfile {
                user: u(),
                profile: "p".into(),
            },
            Request::SetRequireEyesOpen {
                user: u(),
                on: true,
            },
        ] {
            assert_eq!(classify(&req), Class::Plain, "{req:?}");
        }
    }

    #[test]
    fn a_listing_serves_the_published_summary_and_misses_queue_to_the_worker() {
        let _summary_guard = enrollment_summary_test_lock();
        let me = users::name_for_uid(unsafe { libc::getuid() }).unwrap_or_else(|| "root".into());
        let peer = Peer {
            uid: unsafe { libc::getuid() },
            gid: 0,
            pid: 1,
        };
        let req = Request::ListProfiles {
            user: me.clone(),
            structured_errors: false,
        };
        invalidate_enrollment_summary(&me);
        // MISS: the status path must NOT answer (None queues it to the
        // worker, where the real load with its TPM unseal and possible
        // template-key re-seal stays serialized).
        assert!(
            dispatch_status(&req, &peer).is_none(),
            "an unpublished summary must route to the worker"
        );
        // HIT: the worker-published snapshot answers without the worker.
        publish_enrollment_summary(
            &me,
            EnrollmentSummary {
                profiles: vec![irlume_common::ProfileSummary {
                    name: "Alice".into(),
                    scans: vec!["s1".into()],
                    scans_by_recognizer: Default::default(),
                    live_recognizer: None,
                }],
                require_eyes_open: true,
                require_challenge: false,
                closure_calibrated: false,
                ir_ratio_calibrated: true,
            },
        );
        match dispatch_status(&req, &peer) {
            Some(Response::Enrollment {
                profiles,
                require_eyes_open,
                ir_ratio_calibrated,
                ..
            }) => {
                assert_eq!(profiles.len(), 1);
                assert!(require_eyes_open);
                assert!(ir_ratio_calibrated);
            }
            other => panic!("expected the cached enrollment, got {other:?}"),
        }
        // A mutation invalidates BEFORE it runs: the next status read
        // misses and queues behind it instead of racing it.
        assert!(enrollment_mutating_user(&Request::DeleteProfile {
            user: me.clone(),
            profile: "Alice".into(),
        })
        .is_some());
        invalidate_enrollment_summary(&me);
        assert!(dispatch_status(&req, &peer).is_none());
    }

    #[test]
    fn every_enrollment_mutation_is_on_the_invalidation_list() {
        let u = || "carol".to_string();
        let mutating: Vec<Request> = vec![
            Request::Enroll {
                user: u(),
                profile: None,
                scans: None,
                reset: false,
            },
            Request::AddScan {
                user: u(),
                profile: "p".into(),
                scans: None,
                report_enrollment: false,
            },
            Request::DeleteProfile {
                user: u(),
                profile: "p".into(),
            },
            Request::DeleteScan {
                user: u(),
                profile: "p".into(),
                scan: "s".into(),
            },
            Request::RenameProfile {
                user: u(),
                profile: "a".into(),
                new_name: "b".into(),
            },
            Request::RenameScan {
                user: u(),
                profile: "p".into(),
                scan: "a".into(),
                new_name: "b".into(),
            },
            Request::SetRequireEyesOpen {
                user: u(),
                on: true,
            },
            Request::SetRequireChallenge {
                user: u(),
                on: true,
            },
        ];
        for req in &mutating {
            assert_eq!(
                enrollment_mutating_user(req),
                Some("carol"),
                "a mutation missing from the invalidation list serves stale \
                 summaries forever: {req:?}"
            );
        }
        // Reads must NOT invalidate: an Authenticate loads the enrollment
        // but changes nothing the summary reports.
        assert!(enrollment_mutating_user(&Request::Authenticate {
            user: u(),
            service: None,
        })
        .is_none());
        assert!(enrollment_mutating_user(&Request::Ping).is_none());
    }

    #[test]
    fn dispatch_status_keeps_the_authorization_gate() {
        // A non-root peer asking about another user is refused on the
        // connection thread exactly as the worker refused it: moving the
        // arms must not have moved the gate.
        let peer = Peer {
            uid: 65534,
            gid: 65534,
            pid: 1,
        };
        let resp = dispatch_status(
            &Request::HasSealedPassword {
                user: "root".into(),
            },
            &peer,
        )
        .expect("status request");
        match resp {
            Response::Error(m) => assert!(m.contains("not authorized"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn health_reports_the_published_engine_bits() {
        publish_engine_bits_raw(EngineBits {
            mesh: true,
            adapter: true,
            third_party_pad: Some("flir".into()),
            third_party_recognizer: None,
            third_party_detector: None,
            tier: "none".into(),
            rgb_dev: None,
            ir_dev: None,
        });
        let peer = Peer {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        let resp = dispatch_status(&Request::Health, &peer).expect("status request");
        match resp {
            Response::Health {
                mesh,
                adapter,
                third_party_pad,
                ..
            } => {
                assert!(mesh && adapter);
                assert_eq!(third_party_pad.as_deref(), Some("flir"));
            }
            other => panic!("expected Health, got {other:?}"),
        }
        publish_engine_bits_raw(EngineBits::default());
    }

    #[test]
    fn a_camera_request_is_refused_while_an_authentication_is_queued() {
        // No worker: the refusal must be answered by the connection thread
        // itself, without the request ever reaching the camera. If this only
        // worked because a worker drained the queue, the test would hang here.
        let arbiter = std::sync::Arc::new(arbiter::Arbiter::<Queued>::new());
        let (_dead_reply, _) = std::sync::mpsc::channel();
        arbiter
            .submit(
                arbiter::Class::Auth,
                0,
                Queued {
                    req: Request::Ping,
                    peer: Peer {
                        uid: 0,
                        gid: 0,
                        pid: 0,
                    },
                    reply: _dead_reply,
                },
            )
            .unwrap();

        let (ours, theirs) = UnixStream::pair().unwrap();
        (&ours)
            .write_all(b"{\"PositionSample\":{\"user\":null}}\n")
            .unwrap();
        let a = std::sync::Arc::clone(&arbiter);
        // These cover the SERVING daemon; the not-ready path has its own test.
        let ready = std::sync::atomic::AtomicBool::new(true);
        std::thread::spawn(move || serve(theirs, &a, &ready).unwrap());

        let mut line = String::new();
        BufReader::new(&ours).read_line(&mut line).unwrap();
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        match resp {
            Response::Error(msg) => assert!(
                msg.contains("authentication has priority"),
                "the client must be told why: {msg}"
            ),
            other => panic!("a queued authentication must refuse preview work, got {other:?}"),
        }
    }

    #[test]
    fn read_request_parses_one_line_and_rejects_garbage() {
        // A valid newline-terminated request.
        let (ours, theirs) = UnixStream::pair().unwrap();
        (&theirs).write_all(b"\"Ping\"\n").unwrap();
        match read_request(&ours).unwrap() {
            ReadOutcome::Req(Request::Ping) => {}
            _ => panic!("a Ping line must parse to Request::Ping"),
        }
        // Unparsable bytes -> Bad (generic error, never an echo).
        let (ours, theirs) = UnixStream::pair().unwrap();
        (&theirs).write_all(b"{not json}\n").unwrap();
        assert!(matches!(read_request(&ours).unwrap(), ReadOutcome::Bad));
        // Peer closing without a byte -> Closed.
        let (ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        assert!(matches!(read_request(&ours).unwrap(), ReadOutcome::Closed));
    }

    #[test]
    fn read_request_caps_an_oversized_payload_at_max_request_bytes() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // 128 KiB with no newline: a slow-loris / memory-DoS shape. The writer
        // runs on its own thread in case the kernel buffers fill up.
        let writer = std::thread::spawn(move || {
            let payload = vec![b'a'; 2 * MAX_REQUEST_BYTES as usize];
            let _ = (&theirs).write_all(&payload);
            let _ = (&theirs).write_all(b"\n\"Ping\"\n");
        });
        // The reader must stop at the 64 KiB cap and answer Bad; it must not
        // buffer the whole flood or hang waiting for the newline.
        assert!(matches!(read_request(&ours).unwrap(), ReadOutcome::Bad));
        writer.join().unwrap();
    }

    #[test]
    fn read_request_honours_the_read_deadline_against_a_silent_peer() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // Same mechanism handle() arms (shorter here to keep the test quick).
        ours.set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .unwrap();
        let t = std::time::Instant::now();
        let err = read_request(&ours).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "a silent peer must trip the deadline, got {err:?}"
        );
        assert!(t.elapsed() >= std::time::Duration::from_millis(250));
        drop(theirs);
    }

    #[test]
    fn respond_writes_one_newline_terminated_json_line() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        respond(ours, &Response::Pong).unwrap();
        let mut line = String::new();
        BufReader::new(&theirs).read_line(&mut line).unwrap();
        assert!(line.ends_with('\n'));
        assert!(matches!(
            serde_json::from_str::<Response>(line.trim()).unwrap(),
            Response::Pong
        ));
        // A secret-carrying response survives the wire intact (the zeroize of
        // the serialization buffer must not corrupt what was already sent).
        let (ours, theirs) = UnixStream::pair().unwrap();
        respond(
            ours,
            &Response::PasswordUnsealed {
                kind: irlume_common::KeyringSecretKind::LoginPassword,
                secret: irlume_common::SecretBytes::new(b"hunter2".to_vec()),
            },
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(&theirs).read_line(&mut line).unwrap();
        match serde_json::from_str::<Response>(line.trim()).unwrap() {
            Response::PasswordUnsealed { secret, .. } => {
                assert_eq!(secret.expose(), b"hunter2")
            }
            other => panic!("expected PasswordUnsealed, got {other:?}"),
        }
    }

    /// Idle is healthy, work in flight is healthy while it reports progress, and
    /// only a job that has gone quiet past the deadline counts as wedged. Getting
    /// this backwards either restarts a busy daemon or never restarts a hung one.
    #[test]
    fn worker_is_wedged_only_when_a_job_stops_reporting_progress() {
        let short = std::time::Duration::from_millis(40);

        // Idle: nothing in flight, so nothing to be wedged about. A bare timer
        // would have to invent an answer here; this one does not.
        note_worker_idle();
        assert!(!worker_wedged(short), "an idle worker is not wedged");

        // A job just picked up is healthy.
        note_worker_progress();
        assert!(!worker_wedged(short));

        // Gone quiet past the deadline: this is the wedge.
        std::thread::sleep(std::time::Duration::from_millis(70));
        assert!(
            worker_wedged(short),
            "no progress for longer than the limit"
        );

        // A long job that keeps reporting stays healthy, which is what stops an
        // enrolment capturing ten scans from being killed as a hang.
        for _ in 0..4 {
            note_worker_progress();
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(
                !worker_wedged(short),
                "progress between captures is healthy"
            );
        }

        // Finishing returns it to idle rather than leaving the last timestamp to
        // age into a false wedge.
        note_worker_idle();
        std::thread::sleep(std::time::Duration::from_millis(70));
        assert!(!worker_wedged(short), "idle after a job is still healthy");
    }

    /// The #336 arithmetic gate: the longest stretch a defined capture failure
    /// can go WITHOUT reporting progress must fit inside HALF the unit's
    /// `WatchdogSec`, with margin. Half, because that is the bound under which
    /// the watchdog can never miss a ping regardless of phase: `spawn_watchdog`
    /// ticks every `period / 2` and withholds a tick only when the worker has
    /// been quiet longer than that interval, so a stretch under it always has
    /// its tick answered, while a stretch past it can line up so the last real
    /// ping was at the stretch's start and systemd's deadline expires before
    /// the next one. A frameless camera used to produce ~82-96s of exactly
    /// such silence in one assess chain (two 40s warm-up stalls plus the grace
    /// window) and systemd killed a daemon that was working through a defined
    /// worst case. The fix reports each RETURNED dequeue window as progress
    /// (a window that returned proves the thread was never stuck; a wedged
    /// ioctl still reports nothing), so the bound here is the per-window
    /// silent stretch, not the capture chain's total.
    ///
    /// Reads the shipped unit rather than repeating "90", so retuning EITHER
    /// side (a dequeue window, the warm-up pacing, or `WatchdogSec` itself)
    /// without the other fails here instead of shipping a daemon that dies on
    /// frameless hardware. The stretch constant is derived, not free-floating:
    /// it is built from `irlume-camera`'s dequeue/warm-up constants; the
    /// per-window heartbeat WIRING it assumes is pinned by irlume-camera's
    /// `a_frameless_warm_up_reports_every_completed_silent_window`, and the CI
    /// loopback test `loopback_frameless_capture_fits_the_watchdog_budget`
    /// measures both on a real frameless capture.
    #[test]
    fn frameless_capture_worst_case_fits_inside_the_watchdog() {
        let unit_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packaging/systemd/irlumed.service"
        );
        let unit =
            std::fs::read_to_string(unit_path).unwrap_or_else(|e| panic!("read {unit_path}: {e}"));
        let secs: u64 = unit
            .lines()
            .find_map(|l| l.trim().strip_prefix("WatchdogSec="))
            .expect("irlumed.service declares WatchdogSec")
            .trim()
            .trim_end_matches('s')
            .parse()
            .expect("WatchdogSec is plain seconds (e.g. 90s)");
        let period_ms = secs * 1000;
        let never_missed_ping_ms = period_ms / 2;
        // 20% margin under the phase-safe bound, for scheduler jitter and
        // whatever the seam allowance underestimates on a loaded CPU.
        let budget_ms = never_missed_ping_ms * 8 / 10;
        assert!(
            irlume_auth::CAPTURE_MAX_SILENT_STRETCH_MS <= budget_ms,
            "a capture path can go {}ms without reporting progress, over the \
             {budget_ms}ms budget (80% of half of WatchdogSec={secs}s); shorten \
             the dequeue window, or raise WatchdogSec in \
             packaging/systemd/irlumed.service (#336)",
            irlume_auth::CAPTURE_MAX_SILENT_STRETCH_MS
        );
    }

    /// The explanatory refusal line is printed once per uid, so a local process
    /// spinning on a request it knows will be refused cannot fill the journal,
    /// while each distinct surface still gets its one explanation.
    #[test]
    fn a_non_root_unseal_is_explained_once_per_uid() {
        const A: u32 = 90001;
        const B: u32 = 90002;
        assert!(
            first_nonroot_unseal(A),
            "first refusal for a uid explains itself"
        );
        for _ in 0..1000 {
            assert!(!first_nonroot_unseal(A), "every later refusal stays quiet");
        }
        assert!(
            first_nonroot_unseal(B),
            "a different uid is a different surface"
        );
        assert!(!first_nonroot_unseal(B));
    }

    /// The refusal throttle must spend down under sustained refusals, refill on
    /// its own, and never apply to root. Serialised on the env lock because the
    /// rate is read from the environment and the buckets are process-global.
    #[test]
    fn refusal_throttle_spends_down_refills_and_exempts_root() {
        let _g = env_lock();
        std::env::set_var("IRLUME_REFUSAL_RATE", "10");
        refusal_state().lock().unwrap().clear();
        const UID: u32 = 4242;

        // A quiet peer is never throttled.
        assert!(!refusal_throttled(UID));

        // Spending the budget takes the bucket negative, which is what trips it.
        for _ in 0..12 {
            record_refusal(UID);
        }
        assert!(refusal_throttled(UID), "12 refusals against a budget of 10");

        // Root is exempt no matter how many refusals are charged to it: every
        // privileged PAM stack runs as uid 0 and starving those is worse than
        // any flood.
        for _ in 0..100 {
            record_refusal(0);
        }
        assert!(!refusal_throttled(0), "root must never be throttled");

        // It refills with time rather than needing an event to clear it.
        {
            let mut map = refusal_state().lock().unwrap();
            let b = map.get_mut(&UID).unwrap();
            b.last = Some(std::time::Instant::now() - std::time::Duration::from_secs(5));
        }
        assert!(!refusal_throttled(UID), "a five second pause must clear it");

        std::env::remove_var("IRLUME_REFUSAL_RATE");
        refusal_state().lock().unwrap().clear();
    }

    /// Zero disables the throttle outright, so an operator can turn it off and a
    /// peer is never held no matter what it does.
    #[test]
    fn refusal_rate_zero_disables_the_throttle() {
        let _g = env_lock();
        std::env::set_var("IRLUME_REFUSAL_RATE", "0");
        refusal_state().lock().unwrap().clear();
        const UID: u32 = 4343;
        for _ in 0..10_000 {
            record_refusal(UID);
        }
        assert!(!refusal_throttled(UID));
        std::env::remove_var("IRLUME_REFUSAL_RATE");
        refusal_state().lock().unwrap().clear();
    }

    #[test]
    fn rate_throttle_trips_after_the_limit_and_resets_on_grant() {
        let _g = env_lock();
        std::env::set_var("IRLUME_RATE_LIMIT", "3");
        std::env::set_var("IRLUME_RATE_COOLDOWN_SECS", "30");
        // Unique user so the process-global map does not bleed across tests.
        let u = format!("throttle-{}", std::process::id());

        // Below the limit: strikes accumulate, not yet throttled.
        assert!(!rate_limited(&u));
        rate_record(&u, false, true); // strike 1
        rate_record(&u, false, true); // strike 2
        assert!(!rate_limited(&u), "under the limit must not throttle");
        rate_record(&u, false, true); // strike 3 -> cooldown
        assert!(rate_limited(&u), "at the limit the user is throttled");

        // No-face outcomes (nobody in frame) never count: fresh user stays open
        // even after many of them.
        let u2 = format!("noface-{}", std::process::id());
        for _ in 0..10 {
            rate_record(&u2, false, false);
        }
        assert!(!rate_limited(&u2), "absence must not throttle");

        // A grant clears the throttle immediately.
        let u3 = format!("grant-{}", std::process::id());
        rate_record(&u3, false, true);
        rate_record(&u3, false, true);
        rate_record(&u3, false, true);
        assert!(rate_limited(&u3));
        rate_record(&u3, true, true);
        assert!(!rate_limited(&u3), "a grant resets the throttle");

        // Limit of 0 disables the throttle entirely.
        std::env::set_var("IRLUME_RATE_LIMIT", "0");
        let u4 = format!("disabled-{}", std::process::id());
        for _ in 0..20 {
            rate_record(&u4, false, true);
        }
        assert!(
            !rate_limited(&u4),
            "IRLUME_RATE_LIMIT=0 disables the throttle"
        );

        std::env::remove_var("IRLUME_RATE_LIMIT");
        std::env::remove_var("IRLUME_RATE_COOLDOWN_SECS");
    }

    #[test]
    fn env_or_prefers_the_env_var_over_the_default() {
        let _g = env_lock();
        std::env::remove_var("IRLUME_TEST_ENV_OR");
        assert_eq!(
            env_or("IRLUME_TEST_ENV_OR", "/etc/fallback"),
            "/etc/fallback"
        );
        std::env::set_var("IRLUME_TEST_ENV_OR", "/tmp/override");
        assert_eq!(
            env_or("IRLUME_TEST_ENV_OR", "/etc/fallback"),
            "/tmp/override"
        );
        std::env::remove_var("IRLUME_TEST_ENV_OR");
    }

    #[test]
    fn biopolicy_enforced_reads_env_then_settings_conf() {
        let _g = env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-biopol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY");

        // Default: no env, no settings.conf -> off.
        assert!(!biopolicy_enforced());
        // settings.conf truthy value turns it on; a falsy one keeps it off.
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=1\n").unwrap();
        assert!(biopolicy_enforced());
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=0\n").unwrap();
        assert!(!biopolicy_enforced());
        // The env var wins over the file, in both directions.
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=1\n").unwrap();
        std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", "0");
        assert!(!biopolicy_enforced());
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=0\n").unwrap();
        for truthy in ["1", "true", "yes", "on", " on "] {
            std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", truthy);
            assert!(biopolicy_enforced(), "{truthy:?} must enable");
        }
        std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY");
        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The POLICY read behind credential release: `temporal_challenge` tracks the
    /// live setting so a toggle needs no daemon restart, and DEFAULT ON means an
    /// absent key still requires the gesture, which is the whole point of the
    /// change.
    ///
    /// Scope, stated plainly: this covers the helper, not the dispatch. That
    /// `UnsealPassword` runs under this purpose rests on
    /// [`credential_release_purpose`] having exactly one caller,
    /// [`do_unseal_password`], which is also the only path to
    /// `keyring::unseal_password`. A camera-less test cannot observe the gesture
    /// gate itself; the engine-side proof lives in irlume-auth
    /// (`no_credential_release_failure_mode_ever_grants`) and the end-to-end proof
    /// in irlume-pam (`pamwrap_refused_challenge_falls_through_to_the_password_module`).
    #[test]
    fn credential_release_purpose_defaults_to_a_required_challenge() {
        use irlume_auth::AuthenticationPurpose::CredentialRelease;
        let _g = env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-crp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE");

        // No settings.conf at all: the challenge is REQUIRED.
        assert_eq!(
            credential_release_purpose(),
            CredentialRelease {
                temporal_challenge: true
            },
            "an absent key must still require the gesture"
        );
        // An explicit opt-out, read live, is the only way to drop it.
        std::fs::write(
            dir.join("settings.conf"),
            "credential_release_challenge=off\n",
        )
        .unwrap();
        assert_eq!(
            credential_release_purpose(),
            CredentialRelease {
                temporal_challenge: false
            }
        );
        std::fs::write(
            dir.join("settings.conf"),
            "credential_release_challenge=on\n",
        )
        .unwrap();
        assert_eq!(
            credential_release_purpose(),
            CredentialRelease {
                temporal_challenge: true
            }
        );
        // Whatever the setting says, the purpose is never Verify or AppConsent:
        // credential release can never be downgraded to a session-only gate.
        for v in ["on", "off", "garbage"] {
            std::fs::write(
                dir.join("settings.conf"),
                format!("credential_release_challenge={v}\n"),
            )
            .unwrap();
            assert!(
                matches!(credential_release_purpose(), CredentialRelease { .. }),
                "'{v}' must stay a credential release"
            );
        }

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_models_without_strict_warns_but_continues() {
        // No IRLUME_MODELS_STRICT in the test env: an unknown digest and a
        // missing file must both come back (reaching the next line at all is
        // the contract; strict mode would have exited the process).
        let dir = std::env::temp_dir().join(format!("irlume-vm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let unknown = dir.join("custom_adapter.onnx");
        std::fs::write(&unknown, b"self-trained weights").unwrap();
        verify_models(
            &[
                unknown.to_str().unwrap(),
                "/nonexistent/irlume-test/missing.onnx",
            ],
            None,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Companion to the missing-model child test: strict mode must also refuse
    // a PRESENT model whose digest is not in the release manifest (tampering),
    // and must ACCEPT a shipped model that matches it. verify_models exits the
    // process, so both run as re-exec'd children.
    #[test]
    fn strict_verify_refuses_a_tampered_model_and_accepts_a_shipped_one() {
        if let Ok(path) = std::env::var("IRLUME_TEST_VERIFY_TAMPER_CHILD") {
            verify_models(&[&path], None); // must exit(1) before the return
            return;
        }
        if let Ok(path) = std::env::var("IRLUME_TEST_VERIFY_KNOWN_CHILD") {
            verify_models(&[&path], None); // digest is in the manifest: must survive
            println!("known-model-accepted");
            std::process::exit(0);
        }
        let exe = std::env::current_exe().unwrap();
        let run = |var: &str, path: &str| {
            std::process::Command::new(&exe)
                .args([
                    "tests::strict_verify_refuses_a_tampered_model_and_accepts_a_shipped_one",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(var, path)
                .env("IRLUME_MODELS_STRICT", "1")
                .output()
                .unwrap()
        };
        // Tampered: on-disk bytes whose sha256 is not in models/SHA256SUMS.
        let dir = std::env::temp_dir().join(format!("irlume-vm-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tampered = dir.join("face.onnx");
        std::fs::write(&tampered, b"swapped weights").unwrap();
        let out = run(
            "IRLUME_TEST_VERIFY_TAMPER_CHILD",
            tampered.to_str().unwrap(),
        );
        assert!(
            !out.status.success(),
            "strict mode must refuse an unmanifested model"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("refusing to start with unverified models"),
            "stderr: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Shipped: a real release model from the repo matches its manifest
        // digest and must start even under strict.
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../models/blaze_face_short_range.onnx");
        if !shipped.exists() {
            eprintln!("skipping known-model half: repo models/ not present");
            return;
        }
        let out = run("IRLUME_TEST_VERIFY_KNOWN_CHILD", shipped.to_str().unwrap());
        assert!(
            out.status.success(),
            "strict mode must accept a manifest-matching model; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("known-model-accepted"));
    }

    #[test]
    fn mutate_enrollment_reports_a_missing_enrollment() {
        let _g = env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-mut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        let resp = mutate_enrollment("ghost", |_| Ok("never runs".into()));
        match resp {
            Response::Error(msg) => assert_eq!(msg, "'ghost' is not enrolled"),
            other => panic!("expected Error, got {other:?}"),
        }
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_mode_applies_the_requested_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("irlume-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("sock-standin");
        std::fs::write(&f, b"").unwrap();
        set_mode(f.to_str().unwrap(), 0o660);
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        // Best-effort on a missing path: must not panic.
        set_mode("/nonexistent/irlume-test/sock", 0o666);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn socket_mode_admits_every_local_uid_because_peercred_is_the_gate() {
        use std::os::unix::fs::PermissionsExt;
        // Regression: a 0660 root:irlume socket blocked the clients it was meant
        // to admit. kscreenlocker_greet is not setuid, so the KDE lock screen's
        // pam_irlume got EACCES and face unlock fell through to the password,
        // and `irlume detect` exited 10 as a user against 0 as root on the same
        // healthy box. Assert the mode a real bind produces, not just the
        // constant, so removing the set_mode call fails this test.
        let dir = std::env::temp_dir().join(format!("irlume-sockmode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("irlume.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        set_mode(path.to_str().unwrap(), DAEMON_SOCKET_MODE);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666, "every local uid must be able to connect");
        // Group-restricted modes are the exact regression; spell it out.
        assert_ne!(mode, 0o660);
        assert_ne!(mode & 0o006, 0, "other-rw is what admits a user session");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- engine-loaded dispatch arms ------------------------------------
    //
    // These drive dispatch() with a REAL irlume_auth::Engine (the same model
    // files the daemon loads in production) and a constructed Peer. The
    // engine's camera devices are nonexistent paths, so every ungated test
    // below either refuses before any capture or fails the capture cleanly;
    // nothing touches real hardware, /var/lib, or a real TPM. Tests that need
    // fake hardware are env-gated: `loopback_` (v4l2loopback feeder nodes) and
    // `tpm_` (swtpm via IRLUME_TCTI).

    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};
    use std::sync::{MutexGuard, OnceLock};

    const NO_RGB: &str = "/dev/irlume-daemon-test-none-rgb";
    const NO_IR: &str = "/dev/irlume-daemon-test-none-ir";
    /// A uid outside any account database (same sentinel the identify-scope
    /// test uses): authorized_for() is false for every user.
    const NOBODY: u32 = 0xfffe_fffe;

    fn peer(uid: u32) -> Peer {
        Peer {
            uid,
            gid: uid,
            pid: 1,
        }
    }

    fn model_path(name: &str) -> String {
        format!("{}/../../models/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Point `ort` (load-dynamic) at the packaged onnxruntime when the test
    /// env doesn't already provide `ORT_DYLIB_PATH`. Same fallbacks as
    /// irlume-auth's engine tests.
    fn ort_init() {
        if std::env::var_os("ORT_DYLIB_PATH").is_some() {
            return;
        }
        for cand in [
            "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
            "/usr/lib64/libonnxruntime.so",
            "/usr/lib/libonnxruntime.so",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
        ] {
            if std::path::Path::new(cand).exists() {
                std::env::set_var("ORT_DYLIB_PATH", cand);
                return;
            }
        }
    }

    /// Process-wide shared engine, loaded once (glintr100 is big). LOCK ORDER:
    /// every test takes env_lock() FIRST, then engine(); the initializer only
    /// touches env vars no other daemon test reads (IRLUME_FORCE_NO_IR,
    /// ORT_DYLIB_PATH), both left set for the whole process, so every
    /// engine-backed test sees the same deterministic convenience (RGB-only)
    /// hardware probe on any machine.
    fn engine() -> MutexGuard<'static, irlume_auth::Engine> {
        static E: OnceLock<std::sync::Mutex<irlume_auth::Engine>> = OnceLock::new();
        E.get_or_init(|| {
            ort_init();
            std::env::set_var("IRLUME_FORCE_NO_IR", "1");
            std::sync::Mutex::new(
                irlume_auth::Engine::load(
                    &model_path("face_detection_yunet_2023mar.onnx"),
                    &model_path("glintr100.onnx"),
                )
                .expect("engine load")
                .with_devices(NO_RGB, NO_IR),
            )
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    }

    /// Isolated state/config/keyring/template-key/recovery dirs plus a method
    /// conf pointing at a missing file (=> method Auto). Redirects every path
    /// the dispatch arms touch, so no test can read or write this machine's
    /// real /etc/irlume or /var/lib state. Caller must hold env_lock(); the
    /// guard must be declared BEFORE the sandbox so Drop runs under it.
    struct Sandbox {
        dir: std::path::PathBuf,
    }

    fn sandbox(tag: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("irlume-daemon-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_CONFIG_DIR", dir.join("config"));
        std::env::set_var("IRLUME_KEYRING_DIR", dir.join("keyring"));
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("template-keys"));
        std::env::set_var("IRLUME_RECOVERY_DIR", dir.join("recovery"));
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("no-method-conf"));
        // The new state dir makes every published summary stale, and a
        // listing is served from that cache before storage is read.
        clear_enrollment_summaries();
        Sandbox { dir }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            for var in [
                "IRLUME_STATE_DIR",
                "IRLUME_CONFIG_DIR",
                "IRLUME_KEYRING_DIR",
                "IRLUME_TEMPLATE_KEY_DIR",
                "IRLUME_RECOVERY_DIR",
                "IRLUME_METHOD_CONF",
            ] {
                std::env::remove_var(var);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Write a PLAINTEXT enrollment (what a no-TPM host stores) straight into
    /// the sandbox state dir; never through storage::save, which would seal a
    /// template key against this machine's real TPM.
    fn write_enrollment(dir: &std::path::Path, e: &Enrollment) {
        std::fs::write(
            dir.join(format!("{}.json", e.user)),
            serde_json::to_vec(e).unwrap(),
        )
        .unwrap();
    }

    fn unit512(seed: usize) -> Vec<f32> {
        let mut v: Vec<f32> = (0..512)
            .map(|j| (j as f32 * 0.7).sin() + 0.05 * (seed as f32 * 1.3 + j as f32).sin())
            .collect();
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-9;
        v.iter_mut().for_each(|x| *x /= n);
        v
    }

    fn rgb_scan(name: &str, seed: usize) -> FaceScan {
        FaceScan {
            name: name.into(),
            rgb: unit512(seed),
            ir: None,
            ir_space: None,
            embed_space: None,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        }
    }

    /// One-profile plaintext enrollment: "Face Profile 1" with the named scans.
    fn enrollment_with(user: &str, scans: &[&str]) -> Enrollment {
        Enrollment {
            user: user.into(),
            profiles: vec![FaceProfile {
                name: "Face Profile 1".into(),
                ir_calib: None,
                ir_calibs: Default::default(),
                scans: scans
                    .iter()
                    .enumerate()
                    .map(|(i, s)| rgb_scan(s, i + 1))
                    .collect(),
            }],
            require_eyes_open: false,
            require_challenge: false,
            camera_binding: None,
            closure_calibration: None,
        }
    }

    /// Plant a bogus sealed-password envelope file. has_sealed_password() is a
    /// pure existence check, so this drives the armed/unarmed branches without
    /// a TPM; any arm that actually unseals it must then fail on the parse.
    fn plant_fake_envelope(user: &str) {
        let path = irlume_core::keyring::envelope_path(user);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not a sealed envelope").unwrap();
    }

    #[test]
    fn dispatch_rejects_an_invalid_username_before_any_arm() {
        let _g = env_lock();
        let mut e = engine();
        for req in [
            Request::ListProfiles {
                user: "../root".into(),
                structured_errors: false,
            },
            Request::Authenticate {
                user: "a/b".into(),
                service: None,
            },
            Request::UnsealPassword {
                user: "-flag".into(),
                service: None,
            },
        ] {
            match dispatch(req, &peer(0), &mut e) {
                Response::Error(msg) => assert_eq!(msg, "invalid username"),
                other => panic!("traversal username must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn ping_answers_pong_through_dispatch() {
        let _g = env_lock();
        let mut e = engine();
        assert!(matches!(
            dispatch(Request::Ping, &peer(NOBODY), &mut e),
            Response::Pong
        ));
    }

    #[test]
    fn health_reports_version_and_never_secure_under_forced_no_ir() {
        let _g = env_lock();
        let mut e = engine();
        match dispatch(Request::Health, &peer(NOBODY), &mut e) {
            Response::Health {
                tier,
                ir_dev,
                mesh,
                adapter,
                version,
                third_party_pad,
                ..
            } => {
                // IRLUME_FORCE_NO_IR=1 (set by the shared engine init) forces
                // ir_pair=false, so no IR node may be reported and the tier can
                // never be "secure", whatever cameras this machine has.
                assert_ne!(tier, "secure");
                assert_eq!(ir_dev, None);
                // The bare shared engine loaded no optional models.
                assert!(!mesh && !adapter);
                // No opt-in PAD cue loaded -> Health reports None (the field
                // the TUI uses for the authoritative on/off state).
                assert_eq!(third_party_pad, None);
                assert_eq!(version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("Health must answer Response::Health, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_requires_root_or_the_account_owner() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-authz");
        let _ = &sb;
        match dispatch(
            Request::Authenticate {
                user: "carol".into(),
                service: None,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to authenticate 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_stands_down_when_the_method_is_fingerprint() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-fp");
        std::fs::write(sb.dir.join("method"), "fingerprint").unwrap();
        std::env::set_var("IRLUME_METHOD_CONF", sb.dir.join("method"));
        match dispatch(
            Request::Authenticate {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::AuthResult {
                granted,
                score,
                live,
                reason,
            } => {
                assert!(!granted && !live);
                assert_eq!(score, 0.0);
                assert_eq!(
                    reason,
                    "face auth disabled: the configured method is fingerprint"
                );
            }
            other => panic!("fingerprint mode must deny via AuthResult, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_on_convenience_tier_is_limited_to_screen_unlock() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-conv");
        let _ = &sb;
        // (service, the OperationClass Debug name the deny reason must carry)
        for (service, class) in [("sshd", "Remote"), ("sudo", "Elevation")] {
            match dispatch(
                Request::Authenticate {
                    user: "carol".into(),
                    service: Some(service.into()),
                },
                &peer(0),
                &mut e,
            ) {
                Response::AuthResult {
                    granted,
                    live,
                    reason,
                    ..
                } => {
                    assert!(!granted && !live, "{service} must not grant");
                    assert_eq!(
                        reason,
                        format!(
                            "RGB-only convenience: face limited to screen unlock (not {class})"
                        )
                    );
                }
                other => panic!("convenience gate must deny {service}, got {other:?}"),
            }
        }
    }

    #[test]
    fn authenticate_refuses_an_unenrolled_user_before_the_camera() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-ghost");
        let _ = &sb;
        // "kde" classifies as ScreenUnlock, so the convenience gate passes and
        // the engine itself answers; an unenrolled user is refused before any
        // capture (the devices don't exist, so reaching the camera would error).
        match dispatch(
            Request::Authenticate {
                user: "irlume-test-ghost".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::AuthResult {
                granted,
                live,
                reason,
                ..
            } => {
                assert!(!granted && !live);
                assert_eq!(reason, "'irlume-test-ghost' is not enrolled");
                // The reason must survive journal redaction unchanged (no
                // numeric payload for a spoofer to tune against).
                assert_eq!(deny_reason(&reason), reason);
            }
            other => panic!("unenrolled user must deny via AuthResult, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_surfaces_a_capture_error_for_an_enrolled_user() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-cam");
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        match dispatch(
            Request::Authenticate {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
    }

    #[test]
    fn identify_answers_a_peer_without_an_account_and_needs_a_camera_for_root() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("identify");
        let _ = &sb;
        // A peer with no local account gets an empty identify, no capture at all.
        match dispatch(Request::Identify, &peer(NOBODY), &mut e) {
            Response::Identified {
                user,
                profile,
                score,
                live,
                reason,
            } => {
                assert_eq!(user, None);
                assert_eq!(profile, None);
                assert_eq!(score, 0.0);
                assert!(!live);
                assert_eq!(reason, "caller has no local account");
            }
            other => panic!("no-account peer must get Identified, got {other:?}"),
        }
        // Root keeps the full 1:N search, which needs the (absent) camera.
        match dispatch(Request::Identify, &peer(0), &mut e) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("root identify without a camera must Error, got {other:?}"),
        }
    }

    #[test]
    fn list_profiles_reports_the_enrollment_and_gates_on_authorization() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("list");
        let mut enr = enrollment_with("carol", &["Face Scan 1", "Face Scan 2"]);
        enr.require_eyes_open = true;
        write_enrollment(&sb.dir, &enr);
        match dispatch(
            Request::ListProfiles {
                user: "carol".into(),
                structured_errors: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Enrollment {
                profiles,
                require_eyes_open,
                require_challenge,
                ..
            } => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(profiles[0].name, "Face Profile 1");
                assert_eq!(
                    profiles[0].scans,
                    vec!["Face Scan 1".to_string(), "Face Scan 2".to_string()]
                );
                assert!(require_eyes_open);
                assert!(!require_challenge);
            }
            other => panic!("expected Response::Enrollment, got {other:?}"),
        }
        // An unenrolled user lists as empty rather than erroring.
        match dispatch(
            Request::ListProfiles {
                user: "ghost".into(),
                structured_errors: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Enrollment { profiles, .. } => assert!(profiles.is_empty()),
            other => panic!("unenrolled user must list empty, got {other:?}"),
        }
        // A foreign peer may not even list.
        match dispatch(
            Request::ListProfiles {
                user: "carol".into(),
                structured_errors: false,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to list 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
    }

    /// `dispatch` answers a listing from the published summary before it
    /// reads storage, and that cache is keyed by user with no notion of which
    /// state dir the summary came from. Entering a sandbox must therefore
    /// drop it: otherwise a test inherits whatever an earlier test's
    /// enrollment happened to be called. This ran as a 15%-of-runs failure in
    /// `list_profiles_reports_the_enrollment_and_gates_on_authorization`,
    /// which reported the renamed profile from the mutation test's sandbox.
    #[test]
    fn a_sandbox_drops_the_summaries_an_earlier_one_published() {
        let _g = env_lock();
        let mut e = engine();
        publish_enrollment_summary(
            "carol",
            EnrollmentSummary {
                profiles: vec![irlume_common::ProfileSummary {
                    name: "Profile From A Dead Sandbox".into(),
                    scans: vec!["Face Scan 9".into()],
                    scans_by_recognizer: Default::default(),
                    live_recognizer: None,
                }],
                require_eyes_open: false,
                require_challenge: false,
                closure_calibrated: false,
                ir_ratio_calibrated: false,
            },
        );
        let sb = sandbox("summary-carryover");
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        match dispatch(
            Request::ListProfiles {
                user: "carol".into(),
                structured_errors: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Enrollment { profiles, .. } => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(
                    profiles[0].name, "Face Profile 1",
                    "the listing must come from this sandbox, not the cache"
                );
            }
            other => panic!("expected Response::Enrollment, got {other:?}"),
        }
    }

    #[test]
    fn profile_mutations_error_precisely_without_rewriting_state() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("mut-err");
        write_enrollment(
            &sb.dir,
            &enrollment_with("carol", &["Face Scan 1", "Face Scan 2"]),
        );
        let root = peer(0);
        // Every branch here errors BEFORE storage::save, so this runs on any
        // host (TPM or not) without sealing anything.
        let cases: Vec<(Request, &str)> = vec![
            (
                Request::DeleteProfile {
                    user: "carol".into(),
                    profile: "nope".into(),
                },
                "no face profile 'nope'",
            ),
            (
                Request::DeleteScan {
                    user: "carol".into(),
                    profile: "nope".into(),
                    scan: "Face Scan 1".into(),
                },
                "no face profile 'nope'",
            ),
            (
                Request::RenameScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "Face Scan 1".into(),
                    new_name: "Face Scan 2".into(),
                },
                "'Face Scan 2' already exists in 'Face Profile 1'",
            ),
            (
                Request::RenameScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "missing".into(),
                    new_name: "Front".into(),
                },
                "no scan 'missing' in 'Face Profile 1'",
            ),
            (
                Request::DeleteProfile {
                    user: "ghost".into(),
                    profile: "Face Profile 1".into(),
                },
                "'ghost' is not enrolled",
            ),
        ];
        for (req, want) in cases {
            match dispatch(req, &root, &mut e) {
                Response::Error(msg) => assert_eq!(msg, want),
                other => panic!("expected Error({want}), got {other:?}"),
            }
        }
        // Unauthorized peers are refused before the enrollment is even loaded.
        match dispatch(
            Request::DeleteProfile {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to modify 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        // The enrollment file is untouched by all of the above.
        let enr = irlume_core::storage::load("carol").unwrap().unwrap();
        assert_eq!(enr.profiles[0].scans.len(), 2);
    }

    #[test]
    fn delete_scan_never_orphans_a_profile_and_deleting_the_last_profile_erases_the_file() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("del-last");
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        let root = peer(0);
        // A profile must keep at least one scan (the deny path never saves).
        match dispatch(
            Request::DeleteScan {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
                scan: "Face Scan 1".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(
                msg,
                "a profile must keep at least one scan; delete the profile instead"
            ),
            other => panic!("last-scan delete must be refused, got {other:?}"),
        }
        // Deleting the only profile removes the whole enrollment file
        // (storage::delete, not save: safe on a TPM host too).
        match dispatch(
            Request::DeleteProfile {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Ok(msg) => assert_eq!(msg, "deleted profile 'Face Profile 1'"),
            other => panic!("sole-profile delete must succeed, got {other:?}"),
        }
        assert!(
            !sb.dir.join("carol.json").exists(),
            "an enrollment with zero profiles must not linger on disk"
        );
        match dispatch(
            Request::DeleteProfile {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "'carol' is not enrolled"),
            other => panic!("second delete must report unenrolled, got {other:?}"),
        }
    }

    /// A two-model enrollment for the forget-recognizer tests: 'BEN' holds two
    /// untagged (shipped-space) scans; 'Mixed' holds one shipped scan, two
    /// scans in `embed:model-b`, and calibrations for both spaces.
    fn two_model_enrollment(user: &str) -> Enrollment {
        let calib = |pairs: usize| irlume_core::calib::IrCalibration {
            m: vec![],
            n_rows: vec![],
            lambda: 0.0,
            fitted_pairs: pairs,
        };
        let tagged = |name: &str, seed: usize, space: &str| FaceScan {
            embed_space: Some(space.into()),
            ..rgb_scan(name, seed)
        };
        let mut mixed = FaceProfile {
            name: "Mixed".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: vec![
                rgb_scan("Face Scan 1", 3),
                tagged("Face Scan 2", 4, "embed:model-b"),
                tagged("Face Scan 3", 5, "embed:model-b"),
            ],
        };
        mixed.set_calib_for(
            irlume_core::storage::LEGACY_RECOGNIZER_SPACE,
            Some(calib(1)),
        );
        mixed.set_calib_for("embed:model-b", Some(calib(2)));
        let mut e = enrollment_with(user, &["Face Scan 1", "Face Scan 2"]);
        e.profiles[0].name = "BEN".into();
        e.profiles.push(mixed);
        e
    }

    #[test]
    fn forget_recognizer_refuses_a_foreign_peer_and_an_unknown_space() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("forget-deny");
        write_enrollment(&sb.dir, &two_model_enrollment("carol"));
        match dispatch(
            Request::ForgetRecognizer {
                user: "carol".into(),
                space: "embed:model-b".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to modify 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        // A space with no scans and no calibration anywhere: an error, so an
        // operator learns the name did not match rather than reading success.
        match dispatch(
            Request::ForgetRecognizer {
                user: "carol".into(),
                space: "embed:model-c".into(),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(msg, "no enrollment data from recognizer embed:model-c")
            }
            other => panic!("unknown space must be an error, got {other:?}"),
        }
        // Both deny paths left the enrollment untouched.
        let enr = irlume_core::storage::load("carol").unwrap().unwrap();
        assert_eq!(enr.profiles.len(), 2);
        assert_eq!(enr.profiles[1].scans.len(), 3);
    }

    #[test]
    fn forget_recognizer_removes_scans_and_calibs_drops_emptied_profiles_and_erases_the_file() {
        // The keep-path ends in storage::save; on a host with /dev/tpm* that
        // would seal a real template key, so this runs on no-TPM hosts (CI,
        // the container suite). Same convention as the other mutation tests.
        if irlume_core::template_key::tpm_available() {
            eprintln!("skipping: TPM present; storage::save would touch real hardware");
            return;
        }
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("forget-two-model");
        write_enrollment(&sb.dir, &two_model_enrollment("carol"));
        let root = peer(0);
        // Forget the third-party space: its scans and its calibration go, the
        // shipped-space material (including untagged scans) stays.
        match dispatch(
            Request::ForgetRecognizer {
                user: "carol".into(),
                space: "embed:model-b".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Ok(msg) => {
                assert_eq!(msg, "forgot recognizer embed:model-b: 2 scan(s) removed")
            }
            other => panic!("forget model-b must succeed, got {other:?}"),
        }
        let enr = irlume_core::storage::load("carol").unwrap().unwrap();
        assert_eq!(enr.profiles.len(), 2, "no profile was emptied yet");
        let mixed = &enr.profiles[1];
        assert_eq!(
            mixed
                .scans
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["Face Scan 1"]
        );
        assert!(
            mixed.calib_for("embed:model-b").is_none(),
            "the forgotten space's calibration is derived biometric material"
        );
        assert!(
            mixed
                .calib_for(irlume_core::storage::LEGACY_RECOGNIZER_SPACE)
                .is_some(),
            "another recognizer's calibration must survive"
        );
        // Forget the shipped space, which the test engine has loaded: every
        // remaining scan is untagged or shipped, so both profiles empty out
        // and the enrollment file goes with them, and the reply says the
        // loaded recognizer's templates are gone.
        assert_eq!(
            e.embed_space(),
            irlume_core::storage::LEGACY_RECOGNIZER_SPACE,
            "test engine is expected to hold the shipped recognizer"
        );
        match dispatch(
            Request::ForgetRecognizer {
                user: "carol".into(),
                space: irlume_core::storage::LEGACY_RECOGNIZER_SPACE.into(),
            },
            &root,
            &mut e,
        ) {
            Response::Ok(msg) => assert_eq!(
                msg,
                format!(
                    "forgot recognizer {}: 3 scan(s) removed (profile(s) 'BEN', 'Mixed' \
                     deleted: no scans left); these were the LOADED recognizer's templates, \
                     so face authentication needs a re-enroll or an add-scan",
                    irlume_core::storage::LEGACY_RECOGNIZER_SPACE
                )
            ),
            other => panic!("forget shipped must succeed, got {other:?}"),
        }
        assert!(
            !sb.dir.join("carol.json").exists(),
            "an enrollment with zero profiles must not linger on disk"
        );
    }

    #[test]
    fn forget_recognizer_clears_a_calibration_that_outlived_its_scans() {
        if irlume_core::template_key::tpm_available() {
            eprintln!("skipping: TPM present; storage::save would touch real hardware");
            return;
        }
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("forget-stale-calib");
        // Only shipped-space scans, but a stale model-b calibration left over
        // from scans deleted one by one. Forgetting model-b is a real change.
        let mut enr = enrollment_with("carol", &["Face Scan 1"]);
        enr.profiles[0].set_calib_for(
            "embed:model-b",
            Some(irlume_core::calib::IrCalibration {
                m: vec![],
                n_rows: vec![],
                lambda: 0.0,
                fitted_pairs: 7,
            }),
        );
        write_enrollment(&sb.dir, &enr);
        match dispatch(
            Request::ForgetRecognizer {
                user: "carol".into(),
                space: "embed:model-b".into(),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Ok(msg) => {
                assert_eq!(msg, "forgot recognizer embed:model-b: 0 scan(s) removed")
            }
            other => panic!("calibration-only forget must succeed, got {other:?}"),
        }
        let enr = irlume_core::storage::load("carol").unwrap().unwrap();
        assert_eq!(enr.profiles[0].scans.len(), 1, "scans are untouched");
        assert!(enr.profiles[0].calib_for("embed:model-b").is_none());
    }

    #[test]
    fn mutations_that_rewrite_the_enrollment_roundtrip_through_dispatch() {
        // These arms end in storage::save; on a host with /dev/tpm* that would
        // seal a real template key, so this test only runs on no-TPM hosts
        // (CI runners). Same convention as irlume-core's storage tests.
        if irlume_core::template_key::tpm_available() {
            eprintln!("skipping: TPM present; storage::save would touch real hardware");
            return;
        }
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("mut-save");
        let _ = &sb;
        write_enrollment(
            &sb.dir,
            &enrollment_with("carol", &["Face Scan 1", "Face Scan 2"]),
        );
        let root = peer(0);
        let expect_ok = |resp: Response, want: &str| match resp {
            Response::Ok(msg) => assert_eq!(msg, want),
            other => panic!("expected Ok({want}), got {other:?}"),
        };
        expect_ok(
            dispatch(
                Request::DeleteScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "Face Scan 2".into(),
                },
                &root,
                &mut e,
            ),
            "deleted scan 'Face Scan 2' from 'Face Profile 1'",
        );
        expect_ok(
            dispatch(
                Request::RenameScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "Face Scan 1".into(),
                    new_name: "Front".into(),
                },
                &root,
                &mut e,
            ),
            "renamed scan to 'Front'",
        );
        expect_ok(
            dispatch(
                Request::RenameProfile {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    new_name: "Work".into(),
                },
                &root,
                &mut e,
            ),
            "renamed profile to 'Work'",
        );
        // Renaming onto an existing name collides (checked before the lookup,
        // so even a self-rename is refused).
        match dispatch(
            Request::RenameProfile {
                user: "carol".into(),
                profile: "Work".into(),
                new_name: "Work".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "'Work' already exists"),
            other => panic!("rename collision must be refused, got {other:?}"),
        }
        expect_ok(
            dispatch(
                Request::SetRequireEyesOpen {
                    user: "carol".into(),
                    on: true,
                },
                &root,
                &mut e,
            ),
            "require-eyes-open ENABLED",
        );
        expect_ok(
            dispatch(
                Request::SetRequireChallenge {
                    user: "carol".into(),
                    on: false,
                },
                &root,
                &mut e,
            ),
            "require-challenge disabled",
        );
        // The saved state reflects every mutation.
        match dispatch(
            Request::ListProfiles {
                user: "carol".into(),
                structured_errors: false,
            },
            &root,
            &mut e,
        ) {
            Response::Enrollment {
                profiles,
                require_eyes_open,
                require_challenge,
                ..
            } => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(profiles[0].name, "Work");
                assert_eq!(profiles[0].scans, vec!["Front".to_string()]);
                assert!(require_eyes_open);
                assert!(!require_challenge);
            }
            other => panic!("expected Response::Enrollment, got {other:?}"),
        }
    }

    #[test]
    fn enroll_validates_authorization_and_duplicate_names_before_capture() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("enroll");
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: None,
                scans: None,
                reset: false,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to enroll 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        // An explicit duplicate profile name fails fast, before the camera
        // would open (the devices don't exist, so getting further would turn
        // this into a hardware error instead).
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: Some("Face Profile 1".into()),
                scans: None,
                reset: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(
                    msg.contains("a face profile named 'Face Profile 1' already exists"),
                    "{msg}"
                );
            }
            other => panic!("duplicate profile name must be refused, got {other:?}"),
        }
        // Past validation, the capture itself fails cleanly on this hardware.
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: Some("Second".into()),
                scans: Some(1),
                reset: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
        // reset:true wipes the old enrollment even though the capture then
        // fails: the reset half of the arm ran.
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: None,
                scans: None,
                reset: true,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
        assert!(
            !sb.dir.join("carol.json").exists(),
            "Enroll{{reset:true}} must delete the previous enrollment first"
        );
    }

    #[test]
    fn add_scan_refuses_unenrolled_users_and_full_profiles_before_capture() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("addscan");
        match dispatch(
            Request::AddScan {
                user: "ghost".into(),
                profile: "Face Profile 1".into(),
                scans: None,
                report_enrollment: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("'ghost' is not enrolled"), "{msg}"),
            other => panic!("unenrolled AddScan must Error, got {other:?}"),
        }
        // A profile at MAX_SCANS_PER_PROFILE is refused before any capture.
        let max = irlume_core::storage::MAX_SCANS_PER_PROFILE;
        let names: Vec<String> = (1..=max).map(|i| format!("Face Scan {i}")).collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        write_enrollment(&sb.dir, &enrollment_with("carol", &name_refs));
        match dispatch(
            Request::AddScan {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
                scans: None,
                report_enrollment: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(
                msg.contains(&format!("already has the max {max} scans")),
                "{msg}"
            ),
            other => panic!("full profile must be refused, got {other:?}"),
        }
    }

    #[test]
    fn seal_password_gates_authorization_and_refuses_an_empty_secret() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("seal");
        let _ = &sb;
        match dispatch(
            Request::SealPassword {
                kind: None,
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(b"pw".to_vec()),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to seal password for 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        // The empty-password refusal fires before any TPM operation, so this
        // is safe (and deterministic) on every host.
        match dispatch(
            Request::SealPassword {
                kind: None,
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(Vec::new()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(msg.contains("refusing to seal an empty password"), "{msg}")
            }
            other => panic!("empty password must be refused, got {other:?}"),
        }
    }

    #[test]
    fn unseal_password_arm_gates_peer_method_and_tier_before_the_face_check() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("unseal-gates");
        // Only a root peer (the PAM stack) may even ask.
        match dispatch(
            Request::UnsealPassword {
                user: "carol".into(),
                service: None,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("unseal_password requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root unseal must be refused, got {other:?}"),
        }
        // Fingerprint mode refuses credential release outright.
        std::fs::write(sb.dir.join("method"), "fingerprint").unwrap();
        std::env::set_var("IRLUME_METHOD_CONF", sb.dir.join("method"));
        match dispatch(
            Request::UnsealPassword {
                user: "carol".into(),
                service: Some("plasmalogin".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    "face auth disabled: the configured method is fingerprint"
                )
            }
            other => panic!("fingerprint mode must refuse unseal, got {other:?}"),
        }
        std::env::set_var("IRLUME_METHOD_CONF", sb.dir.join("no-method-conf"));
        // The convenience (RGB-only) tier never releases the credential; this
        // fires before the sealed-password lookup and the face check.
        match dispatch(
            Request::UnsealPassword {
                user: "carol".into(),
                service: Some("plasmalogin".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(
                msg,
                "RGB-only convenience: face cannot release the login credential"
            ),
            other => panic!("convenience tier must refuse unseal, got {other:?}"),
        }
        // A polkit service NEVER releases the credential, on any tier, with or
        // without the opt-in biopolicy: the polkit agent starts its PAM
        // conversation with no user gesture, so this fires before every other
        // consideration except root and method.
        for svc in ["polkit-1", "polkit"] {
            match dispatch(
                Request::UnsealPassword {
                    user: "carol".into(),
                    service: Some(svc.into()),
                },
                &peer(0),
                &mut e,
            ) {
                Response::Error(msg) => assert_eq!(
                    msg,
                    format!(
                        "'{svc}' is verify-only: a polkit prompt never releases the credential"
                    )
                ),
                other => panic!("polkit unseal must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn do_unseal_password_requires_an_armed_seal_then_a_granted_face() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("do-unseal");
        // Nothing armed: refused before any capture or TPM traffic.
        match do_unseal_password("carol", None, &mut e) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    "no sealed password for 'carol': run `irlume keyring arm`"
                )
            }
            other => panic!("unarmed unseal must be refused, got {other:?}"),
        }
        // Armed (existence check only) but the user is not enrolled: the face
        // check denies before the camera and the envelope is never opened.
        plant_fake_envelope("carol");
        match do_unseal_password("carol", None, &mut e) {
            Response::Error(msg) => {
                assert_eq!(msg, "face not granted: 'carol' is not enrolled")
            }
            other => panic!("unenrolled unseal must be refused, got {other:?}"),
        }
        // Enrolled: the capture itself fails on this hardware and maps to a
        // clean Error (the non-drift branch: no remedy hint appended).
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        match do_unseal_password("carol", None, &mut e) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
    }

    #[test]
    fn unseal_keyring_gates_peer_service_class_and_envelope_integrity() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("unseal-keyring");
        let _ = &sb;
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
                have_password: false,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("unseal_keyring requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root keyring unseal must be refused, got {other:?}"),
        }
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
                have_password: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    "no sealed password for 'carol': run `irlume keyring arm`"
                )
            }
            other => panic!("unarmed keyring unseal must be refused, got {other:?}"),
        }
        plant_fake_envelope("carol");
        // Only a login / lock-screen service class may release; sudo may not.
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("sudo".into()),
                have_password: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "keyring unseal not allowed for Elevation"),
            other => panic!("elevation keyring unseal must be refused, got {other:?}"),
        }
        // A corrupt envelope must surface as an Error, never a secret.
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
                have_password: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(!msg.is_empty()),
            other => panic!("a corrupt envelope must Error, got {other:?}"),
        }
    }

    #[test]
    fn has_sealed_password_and_forget_roundtrip_through_dispatch() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("haspw");
        let _ = &sb;
        let root = peer(0);
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to query 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(!armed),
            other => panic!("expected HasPassword(false), got {other:?}"),
        }
        plant_fake_envelope("carol");
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(armed),
            other => panic!("expected HasPassword(true), got {other:?}"),
        }
        match dispatch(
            Request::ForgetPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::PasswordForgotten => {}
            other => panic!("expected PasswordForgotten, got {other:?}"),
        }
        assert!(
            !irlume_core::keyring::envelope_path("carol").exists(),
            "ForgetPassword must remove the envelope file"
        );
    }

    #[test]
    fn keyring_info_reports_unarmed_and_unreadable_envelopes() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("krinfo");
        let _ = &sb;
        let root = peer(0);
        match dispatch(
            Request::KeyringInfo {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::KeyringInfo {
                armed,
                policy,
                pcrs,
                drifted,
                ..
            } => {
                assert!(!armed);
                assert_eq!(policy, None);
                assert!(pcrs.is_empty());
                assert_eq!(drifted, None);
            }
            other => panic!("expected KeyringInfo, got {other:?}"),
        }
        // Armed but unreadable: report the armed bit alone, don't fail.
        plant_fake_envelope("carol");
        match dispatch(
            Request::KeyringInfo {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::KeyringInfo { armed, policy, .. } => {
                assert!(armed);
                assert_eq!(policy, None);
            }
            other => panic!("expected KeyringInfo, got {other:?}"),
        }
    }

    #[test]
    fn reseal_password_reports_not_armed_and_refuses_an_empty_password() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("reseal");
        let _ = &sb;
        // Not armed short-circuits before any TPM traffic: never auto-arm.
        match dispatch(
            Request::ResealPassword {
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(b"pw".to_vec()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::PasswordResealed { armed, changed } => {
                assert!(!armed && !changed, "reseal must never arm a fresh user");
            }
            other => panic!("expected PasswordResealed, got {other:?}"),
        }
        match dispatch(
            Request::ResealPassword {
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(Vec::new()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(
                    msg.contains("refusing to reseal an empty password"),
                    "{msg}"
                )
            }
            other => panic!("empty reseal must be refused, got {other:?}"),
        }
    }

    #[test]
    fn recovery_arms_report_status_and_error_without_a_template_key() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("recovery");
        let _ = &sb;
        let root = peer(0);
        match dispatch(
            Request::RecoveryStatus {
                user: "ghost".into(),
            },
            &root,
            &mut e,
        ) {
            Response::RecoveryStatus {
                encrypted,
                recovery_set,
                ..
            } => assert!(!encrypted && !recovery_set),
            other => panic!("expected RecoveryStatus, got {other:?}"),
        }
        // No template key exists (and the user isn't enrolled, so none is
        // minted): setup has nothing to wrap.
        match dispatch(
            Request::RecoverySetup {
                user: "ghost".into(),
                passphrase: irlume_common::SecretBytes::new(b"phrase".to_vec()),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(msg.contains("no template key sealed for 'ghost'"), "{msg}")
            }
            other => panic!("setup without a key must Error, got {other:?}"),
        }
        match dispatch(
            Request::RecoveryRestore {
                user: "ghost".into(),
                passphrase: irlume_common::SecretBytes::new(b"phrase".to_vec()),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert!(
                msg.contains("no recovery passphrase set for 'ghost'"),
                "{msg}"
            ),
            other => panic!("restore without an envelope must Error, got {other:?}"),
        }
        match dispatch(
            Request::RecoveryForget {
                user: "ghost".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Ok(msg) => assert_eq!(msg, "recovery passphrase erased for 'ghost'"),
            other => panic!("forget must be idempotent Ok, got {other:?}"),
        }
        match dispatch(
            Request::RecoveryStatus {
                user: "ghost".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to query 'ghost'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
    }

    #[test]
    fn set_cameras_requires_root_then_repoints_and_persists() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("setcam");
        let _ = &sb;
        match dispatch(
            Request::SetCameras {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("set_cameras requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root SetCameras must be refused, got {other:?}"),
        }
        let (rgb, ir) = ("/dev/irlume-test-alt-rgb", "/dev/irlume-test-alt-ir");
        match dispatch(
            Request::SetCameras {
                rgb: rgb.into(),
                ir: ir.into(),
            },
            &peer(0),
            &mut e,
        ) {
            // The exact message proves the persist to cameras.conf succeeded
            // (a failed persist appends a "live only" suffix).
            Response::Ok(msg) => assert_eq!(msg, format!("cameras set to rgb={rgb} ir={ir}")),
            other => panic!("root SetCameras must succeed, got {other:?}"),
        }
        assert_eq!(e.rgb_device(), rgb);
        assert_eq!(e.ir_device(), ir);
        assert_eq!(
            irlume_common::config::read_kv("cameras.conf", "rgb").as_deref(),
            Some(rgb)
        );
        assert_eq!(
            irlume_common::config::read_kv("cameras.conf", "ir").as_deref(),
            Some(ir)
        );
        // Restore the shared engine's baseline devices.
        e.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn setup_ir_emitter_gates_root_and_surfaces_a_missing_camera() {
        let _g = env_lock();
        let mut e = engine();
        // The dry-run probe shares the per-uid camera-probe interval, and another
        // test may have just spent this uid's slot.
        clear_camera_probe_rate_state();
        // Dry-run is open to any peer but needs the (absent) IR node.
        match dispatch(
            Request::SetupIrEmitter { dry_run: true },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("dry-run without a camera must Error, got {other:?}"),
        }
        // The write path is root-only.
        match dispatch(
            Request::SetupIrEmitter { dry_run: false },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("setup_ir_emitter requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root setup must be refused, got {other:?}"),
        }
    }

    #[test]
    fn selftest_and_position_sample_surface_the_missing_camera() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("selftest");
        let _ = &sb;
        for kind in [
            irlume_common::SelfTestKind::Liveness,
            irlume_common::SelfTestKind::AlignmentIdentity,
        ] {
            match dispatch(Request::SelfTest { kind }, &peer(0), &mut e) {
                Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
                other => panic!("selftest without a camera must Error, got {other:?}"),
            }
            // A non-root peer is refused before the camera ever fires: the
            // self-test returns raw liveness measurements (a spoof oracle).
            match dispatch(Request::SelfTest { kind }, &peer(NOBODY), &mut e) {
                Response::Error(msg) => assert!(
                    msg.contains("requires root"),
                    "non-root selftest must be refused as root-only, got {msg}"
                ),
                other => panic!("non-root selftest must Error, got {other:?}"),
            }
        }
        // A non-root peer asking to tune for another user is silently scoped
        // to the anonymous band; either way the capture needs the camera.
        match dispatch(
            Request::PositionSample {
                user: Some("root".into()),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("position sample without a camera must Error, got {other:?}"),
        }
    }

    // ---- env-gated: v4l2loopback feeder nodes ---------------------------

    /// Fresh engine wired to the CI loopback nodes; None when the env is
    /// absent. The feeder holds no face, so capture arms end in clean denials.
    fn loopback_engine() -> Option<irlume_auth::Engine> {
        let (Ok(rgb), Ok(ir)) = (
            std::env::var("IRLUME_TEST_RGB_DEVICE"),
            std::env::var("IRLUME_TEST_IR_DEVICE"),
        ) else {
            return None;
        };
        ort_init();
        Some(
            irlume_auth::Engine::load(
                &model_path("face_detection_yunet_2023mar.onnx"),
                &model_path("glintr100.onnx"),
            )
            .expect("engine load")
            .with_devices(&rgb, &ir),
        )
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_authenticate_dispatches_to_a_no_face_denial() {
        let _g = env_lock();
        let Some(mut e) = loopback_engine() else {
            return;
        };
        let sb = sandbox("lb-auth");
        // One-shot capture instead of a grace window: a no-face run finishes
        // in one camera round.
        std::env::set_var("IRLUME_GRACE_MS", "0");
        write_enrollment(&sb.dir, &enrollment_with("lbuser", &["Face Scan 1"]));
        // "kde" is a ScreenUnlock in every tier, so the dispatch gates pass
        // whether or not the runner's loopback nodes register as an IR pair.
        let resp = dispatch(
            Request::Authenticate {
                user: "lbuser".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        );
        std::env::remove_var("IRLUME_GRACE_MS");
        match resp {
            Response::AuthResult {
                granted,
                live,
                reason,
                ..
            } => {
                assert!(!granted, "no face on the feed must never grant");
                assert!(!live);
                assert!(
                    reason.to_lowercase().contains("face"),
                    "denial should name the missing face, got: {reason}"
                );
            }
            other => panic!("a faceless frame is a denial, not an error: {other:?}"),
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_identify_dispatches_to_a_no_match() {
        let _g = env_lock();
        let Some(mut e) = loopback_engine() else {
            return;
        };
        let sb = sandbox("lb-identify");
        std::env::set_var("IRLUME_GRACE_MS", "0");
        write_enrollment(&sb.dir, &enrollment_with("lbuser", &["Face Scan 1"]));
        // Root keeps the full 1:N search; with no face on the feed it must
        // come back empty, not error and not name anyone.
        let resp = dispatch(Request::Identify, &peer(0), &mut e);
        std::env::remove_var("IRLUME_GRACE_MS");
        match resp {
            Response::Identified {
                user,
                profile,
                live,
                reason,
                ..
            } => {
                assert_eq!(user, None, "no face must identify nobody");
                assert_eq!(profile, None);
                assert!(!live);
                assert!(!reason.is_empty());
            }
            other => panic!("a faceless identify is a no-match, not an error: {other:?}"),
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_enroll_reaches_capture_and_fails_the_no_face_probe_cleanly() {
        let _g = env_lock();
        let Some(mut e) = loopback_engine() else {
            return;
        };
        let sb = sandbox("lb-enroll");
        std::env::set_var("IRLUME_GRACE_MS", "0");
        let resp = dispatch(
            Request::Enroll {
                user: "lbenroll".into(),
                profile: None,
                scans: Some(1),
                reset: false,
            },
            &peer(0),
            &mut e,
        );
        std::env::remove_var("IRLUME_GRACE_MS");
        match resp {
            Response::Error(msg) => assert!(
                msg.contains("check lighting and framing"),
                "a faceless enroll must coach, got: {msg}"
            ),
            other => panic!("a faceless enroll must Error, got {other:?}"),
        }
        assert!(
            !sb.dir.join("lbenroll.json").exists(),
            "a failed enroll must not leave a partial enrollment"
        );
    }

    // ---- env-gated: swtpm ------------------------------------------------

    #[test]
    #[ignore = "needs swtpm via IRLUME_TCTI (CI does this); never runs against a real TPM"]
    fn tpm_seal_and_unseal_keyring_release_the_secret_to_root_only() {
        // Only ever a software TPM: without the explicit TCTI this returns
        // rather than fall back to this machine's /dev/tpmrm0.
        if std::env::var("IRLUME_TCTI").is_err() {
            return;
        }
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("tpm-keyring");
        let _ = &sb;
        let root = peer(0);
        let secret = b"hunter2-swtpm".to_vec();
        match dispatch(
            Request::SealPassword {
                kind: None,
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(secret.clone()),
            },
            &root,
            &mut e,
        ) {
            Response::PasswordSealed => {}
            other => panic!("sealing against swtpm must succeed, got {other:?}"),
        }
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(armed),
            other => panic!("expected HasPassword(true), got {other:?}"),
        }
        // A real envelope reports its policy.
        match dispatch(
            Request::KeyringInfo {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::KeyringInfo { armed, policy, .. } => {
                assert!(armed);
                assert!(
                    policy.is_some(),
                    "a sealed envelope must describe its policy"
                );
            }
            other => panic!("expected KeyringInfo, got {other:?}"),
        }
        // The sealed login secret is released only to a root peer in a
        // login / lock-screen service class.
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
                have_password: false,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("unseal_keyring requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root peer must never get the secret, got {other:?}"),
        }
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
                have_password: false,
            },
            &root,
            &mut e,
        ) {
            Response::PasswordUnsealed { secret: got, .. } => assert_eq!(got.expose(), secret),
            other => panic!("root keyring unseal must release the secret, got {other:?}"),
        }
        match dispatch(
            Request::ForgetPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::PasswordForgotten => {}
            other => panic!("expected PasswordForgotten, got {other:?}"),
        }
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(!armed),
            other => panic!("expected HasPassword(false), got {other:?}"),
        }
    }
}
