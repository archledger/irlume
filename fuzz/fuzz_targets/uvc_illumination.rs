#![no_main]
//! The UVC MS-XU illumination metadata parser.
//!
//! uvcvideo hands the daemon whatever bytes the camera appended to its UVC
//! payload headers, and until the "Avoid partial metadata buffers" series
//! (Fixes 088ead255245, in stable from 6.12.97 on) the FIRST buffer of a
//! metadata queue that transitioned from empty to ready started mid-header.
//! A camera is external hardware on a USB port, so this is attacker-reachable
//! input to a root daemon: a panic or hang here is a local denial of service
//! against authentication. The parser must answer or return None on every
//! byte string, and burst selection must stay inside the burst and never let
//! a camera-flagged-dark frame beat a flagged-lit one while a lit one exists.
use irlume_camera::ir_metadata::{brightest_lit, parse_illumination, Illumination};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parsing is deterministic: identical bytes must classify identically,
    // whatever the ring state around them.
    assert_eq!(parse_illumination(data), parse_illumination(data));

    if data.is_empty() {
        return;
    }
    // Derive a small selection problem from the bytes so the invariant runs
    // on fuzzer-shaped inputs rather than only the unit fixtures.
    let n = usize::from(data[data.len() - 1]) % 8 + 1;
    let means: Vec<f64> = (0..n).map(|i| f64::from(data[i % data.len()])).collect();
    let flags: Vec<Option<Illumination>> = (0..n)
        .map(|i| match data[(i + n) % data.len()] % 3 {
            0 => None,
            1 => Some(Illumination::Lit),
            _ => Some(Illumination::Dark),
        })
        .collect();
    if let Some(best) = brightest_lit(&means, &flags) {
        assert!(best < means.len(), "selection must stay inside the burst");
        let any_lit = flags
            .iter()
            .any(|flag| matches!(flag, Some(Illumination::Lit)));
        if any_lit {
            assert!(
                matches!(flags[best], Some(Illumination::Lit)),
                "a lit frame exists, so a dark-flagged frame must not win"
            );
        }
    }
});
