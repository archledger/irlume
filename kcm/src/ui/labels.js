// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Client-side wording for machine-API values (docs/MACHINE-API.md). The
// contract publishes stable identifiers and leaves titles to consumers.
// Every lookup falls back to the raw value, so a doctor check added later
// (that list may grow) and a malformed or newer-contract document still
// render. Nothing here reads the theme: pages pick colours from the level
// names below.
.pragma library

// Display levels. A level is shown as an icon plus a word, never by colour
// alone.
var GOOD = "good";
var ATTENTION = "attention";
var PROBLEM = "problem";
var UNKNOWN = "unknown";
var NEUTRAL = "neutral";

function levelIcon(level) {
    switch (level) {
    case GOOD: return "emblem-success";
    case ATTENTION: return "emblem-warning";
    case PROBLEM: return "emblem-error";
    case UNKNOWN: return "emblem-question";
    default: return "emblem-information";
    }
}

function levelWord(level) {
    switch (level) {
    case GOOD: return "OK";
    case ATTENTION: return "Needs attention";
    case PROBLEM: return "Problem";
    case UNKNOWN: return "Not determined";
    default: return "Information";
    }
}

// The sealing tier in words, as the TUI's wallet page shows it: the tier
// and how it is bound, never the pcrlock NV index or other identifiers
// the policy text carries. An unrecognized policy says so rather than
// showing the raw text.
function sealTier(policy) {
    var text = String(policy);
    var tiers = ["Tier 1", "Tier 2", "Tier 3"];
    var tier = "";
    for (var i = 0; i < tiers.length; ++i) {
        if (text.indexOf(tiers[i]) >= 0) {
            tier = tiers[i];
            break;
        }
    }
    if (tier === "") {
        return "tier not recognized";
    }
    if (text.indexOf("pcrlock") >= 0) {
        return tier + " \u00b7 pcrlock";
    }
    if (text.indexOf("PolicyAuthorize") >= 0) {
        return tier + " \u00b7 signed policy";
    }
    if (text.indexOf("PolicyPCR") >= 0) {
        return tier + " \u00b7 literal PCRs";
    }
    return tier;
}

function plural(count, singular, pluralForm) {
    return count + " " + (count === 1 ? singular : pluralForm);
}

function text(value) {
    return value === undefined || value === null ? "" : String(value);
}

// Free text from the engine (an OS error, say) for a message that wraps
// only between words: shortened to `max` characters, with a line-break
// opportunity (U+200B, zero width) after path and word separators and
// inside any long run without one, so a long path cannot run past the
// edge of the message.
function breakable(value, max) {
    let s = text(value);
    if (s.length > max) {
        s = s.slice(0, max - 1) + "\u2026";
    }
    return s.replace(/([\/_.:,=-])/g, "$1\u200B")
        .replace(/([^\s\u200B]{24})(?=[^\s\u200B])/g, "$1\u200B");
}

// A list from a document, or an empty one. Document lists arrive as
// sequence wrappers, which Array.isArray does not recognise.
function list(value) {
    if (value === undefined || value === null || typeof value === "string"
        || typeof value.length !== "number") {
        return [];
    }
    const out = [];
    for (let i = 0; i < value.length; ++i) {
        out.push(value[i]);
    }
    return out;
}

// ---- Error codes (MACHINE-API.md "Error codes") ----

var errorMeanings = {
    "usage-error": "The irlume command line was not one this module expected. Updating irlume or this module may help.",
    "unsupported-contract": "The installed irlume does not speak the machine API version this module uses.",
    "daemon-unavailable": "The irlume daemon could not be reached.",
    "not-authorized": "This account may not read that information.",
    "operation-failed": "irlume could not carry out the request.",
    "camera-busy": "The camera is in use by another application. Close it, then retry.",
    "session-busy": "Another irlume operation is running. Retry when it has finished.",
    "deadline-expired": "The authentication window closed before a decision was made.",
    "protocol-error": "The irlume daemon answered with something unexpected.",
};

// A refusal envelope's error object as one sentence: the documented
// meaning, else the engine's message, else the raw code.
function errorText(error) {
    if (!error) {
        return "irlume refused the request.";
    }
    const meaning = errorMeanings[error.code];
    if (meaning !== undefined) {
        return meaning;
    }
    if (error.message) {
        return String(error.message);
    }
    return error.code ? ("irlume refused the request (" + error.code + ").") : "irlume refused the request.";
}

// ---- Doctor checks (MACHINE-API.md "irlume doctor --json") ----

var checkTitles = {
    "platform": "Distribution family",
    "install-origin": "Where this build came from",
    "tpm": "TPM 2.0 device",
    "secure-boot": "Secure Boot",
    "boot-mode": "Boot chain",
    "emitter-undo-pending": "IR emitter changes left by an interrupted setup",
    "emitter-stream-pending": "IR emitter stream records",
    "capture-mode": "Capture schedule for this camera pair",
    "signed-pcr-policy": "Signed PCR policy (Tier 1)",
    "pcrlock": "systemd-pcrlock policy (Tier 2)",
    // Titles name what is checked, never the outcome: the same title sits
    // beside a failing or undetermined state.
    "camera-nodes": "RGB and IR cameras",
    "ir-stream-hello-minimum": "IR stream against the Windows Hello minimum",
    "rgb-stream-hello-minimum": "RGB stream against the Windows Hello minimum",
    "models": "Face models",
    "stage-detection-model": "Face detection model",
    "stage-landmarks-model": "Face landmarks model",
    "stage-recognition-model": "Face recognition model",
    "ort-dylib-path": "ONNX Runtime path override",
    "onnxruntime": "ONNX Runtime library",
    "tflite-runtime": "TensorFlow Lite runtime",
    "fingerprint-reader": "Fingerprint reader",
    "templates": "Face template encryption",
    "recovery-passphrase": "Recovery passphrase",
    "polkit-app-prompts": "Face login in app prompts (polkit)",
    "polkit-helper-sandbox": "polkit helper sandbox",
    "ir-calibration": "IR liveness calibration",
    "login-wiring": "Face login wiring",
    "display-manager": "Login manager support",
    "pam-regeneration-guard": "Protection against PAM regeneration",
    "install-hygiene": "Leftover and hand-installed files",
    "keyring-secrets": "Login keyring",
    "keyring-os-upgrade": "Keyring unlock after the next system upgrade",
    "camera-groups": "Secondary camera groups",
    "pam-faillock": "Login lockout counter (pam_faillock)",
};

// Documented as a reserved legacy check that is always `info`.
var hiddenChecks = ["credential-release-challenge"];

// Checks that read a root-only store: `unknown` for every run that is not
// root, by contract.
var rootOnlyChecks = ["emitter-undo-pending", "emitter-stream-pending"];

function checkTitle(id) {
    const title = checkTitles[id];
    return title !== undefined ? title : text(id);
}

function checkHidden(id) {
    return hiddenChecks.indexOf(id) >= 0;
}

function checkNeedsAdmin(check) {
    return check.state === "unknown" && rootOnlyChecks.indexOf(check.id) >= 0;
}

// Section order: problems first.
var checkGroups = [
    {state: "fail", title: "Failing", level: PROBLEM},
    {state: "warn", title: "Warnings", level: ATTENTION},
    {state: "unknown", title: "Not determined", level: UNKNOWN},
    {state: "pass", title: "Passing", level: GOOD},
    {state: "info", title: "Informational", level: NEUTRAL},
];

function checkGroupIndex(state) {
    for (let i = 0; i < checkGroups.length; ++i) {
        if (checkGroups[i].state === state) {
            return i;
        }
    }
    return checkGroups.length; // "Other": a state this module does not know
}

function checkGroupTitle(index) {
    return index < checkGroups.length ? checkGroups[index].title : "Other";
}

function checkLevel(state) {
    const index = checkGroupIndex(state);
    return index < checkGroups.length ? checkGroups[index].level : UNKNOWN;
}

// ---- Camera census (MACHINE-API.md "irlume camera census --json") ----

// Mirrors render_class in crates/irlume-camera/src/census.rs.
function censusClass(entry) {
    switch (entry["class"]) {
    case "uvc_rgb": return "RGB camera";
    case "uvc_ir": return "IR sensor";
    case "y8_ir": return "IR sensor (unbranded Y8 format)";
    case "metadata_only": return "metadata interface";
    case "dummy_node": return "test device (not hardware)";
    case "unreadable_node": return "unreadable device";
    case "mc_centric": return "media-controller node";
    case "mipi_ipu":
        return entry.generation ? ("Intel " + entry.generation + " MIPI camera pipeline")
                                : "Intel MIPI camera pipeline";
    case "mipi_vendor_bridge":
        return entry.usb_id ? ("vendor MIPI camera bridge (USB " + entry.usb_id + ")")
                            : "vendor MIPI camera bridge";
    case "usb_camera_without_driver":
        return entry.usb_id ? ("USB camera with no driver (USB " + entry.usb_id + ")")
                            : "USB camera with no driver";
    default: return text(entry["class"]);
    }
}

// A row's title: the device node when there is one, else the machine-level
// class (MIPI pipelines and unbound USB devices have no node).
function censusTitle(entry) {
    const node = text(entry.node);
    const cls = censusClass(entry);
    if (node.length === 0) {
        return cls.length > 0 ? (cls.charAt(0).toUpperCase() + cls.slice(1)) : "Camera device";
    }
    return cls.length > 0 ? (node + ": " + cls) : node;
}

function censusVerdictWord(verdict) {
    switch (verdict) {
    case "supported": return "Supported";
    case "supported_with_limits": return "Supported with limits";
    case "informational": return "Not a camera";
    case "not_hardware": return "Not hardware";
    case "unsupported": return "Not supported";
    case "broken": return "Not working";
    default: return text(verdict);
    }
}

function censusVerdictLevel(verdict) {
    switch (verdict) {
    case "supported": return GOOD;
    case "supported_with_limits":
    case "unsupported": return ATTENTION;
    case "broken": return PROBLEM;
    case "informational":
    case "not_hardware": return NEUTRAL;
    default: return UNKNOWN;
    }
}

// `paired` means the same physical device also has a node of the other
// kind (an RGB camera beside an IR sensor). It does not say which pair
// irlume is set to use, nor whether face login is set up.
var pairedText = "part of an RGB + IR pair";

// Rows that describe something other than a camera; the page folds them
// into one line.
function censusIsAside(entry) {
    return entry.verdict === "informational" || entry.verdict === "not_hardware";
}

// ---- Login wiring (MACHINE-API.md "irlume login status --json") ----

function loginRole(role) {
    switch (role) {
    case "login-screen": return "Login screen";
    case "login-screen-fingerprint": return "Fingerprint login screen";
    case "lock-screen": return "Lock screen";
    case "sudo": return "sudo";
    case "polkit": return "App prompts (polkit)";
    default: return text(role);
    }
}

function loginMode(mode) {
    switch (mode) {
    case "face-first": return "face starts at the prompt";
    case "on-demand": return "face on an empty Enter";
    case "keyring": return "fingerprint keyring unlock";
    case "verify": return "face at the prompt, password as fallback";
    default: return text(mode);
    }
}
