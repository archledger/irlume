//! `lumen` — operator CLI. A thin, unprivileged client of `lumend` (same socket
//! protocol as the PAM module). Enrollment requests are authorized by the daemon
//! via SO_PEERCRED, not by this binary.
//!
//! Subcommands (planned):
//!   lumen enroll [--user U] [--profile NAME]   register a face profile
//!   lumen verify [--user U]                     one-shot auth test
//!   lumen profiles [--user U]                   list profiles
//!   lumen delete  --user U --profile NAME       remove a profile
//!   lumen selftest align                        Phase-1 gate: same crop -> ~1.0
//!   lumen selftest liveness                     run the IR PAD cues
//!   lumen doctor                                check cameras/IR/TPM/models

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("selftest") if args.get(1).map(String::as_str) == Some("align") => {
            // The make-or-break Phase-1 check, end to end through real ONNX:
            // capture one crop, embed it TWICE, assert cosine ~= 1.0. If this
            // fails, alignment/normalization is wrong — fix before anything else.
            println!("[selftest align] placeholder — wire to lumend SelfTest::AlignmentIdentity");
        }
        Some(cmd) => println!("lumen: '{cmd}' not yet implemented (scaffold)"),
        None => println!("lumen <enroll|verify|profiles|delete|selftest|doctor>"),
    }
}
