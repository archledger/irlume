// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

pub fn header(scope: &str) {
    println!(
        "scope={scope} version={} arch={} os={} debug_assertions={}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS,
        cfg!(debug_assertions)
    );
    println!("percentiles=nearest-rank; timings exclude reporting and output destruction");
}

pub fn file(label: &str, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = path.canonicalize()?;
    let mut file = std::fs::File::open(&resolved)?;
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        hash.update(&buffer[..count]);
    }
    let digest: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!(
        "{label}: path={} bytes={bytes} sha256={digest}",
        resolved.display()
    );
    Ok(())
}

pub fn construct<T, E: std::fmt::Display>(
    name: &str,
    load: impl FnOnce() -> Result<T, E>,
) -> Result<T, String> {
    let start = Instant::now();
    let result = load();
    let elapsed = start.elapsed();
    let value = result.map_err(|error| format!("construct {name} failed: {error}"))?;
    println!(
        "construct {name}: elapsed_ms={:.3}",
        elapsed.as_secs_f64() * 1000.0
    );
    Ok(value)
}

// Called after construction so probing/hashing does not pre-warm its inputs.
pub fn runtimes() -> Result<(), Box<dyn std::error::Error>> {
    let (candidate, verdict) = irlume_vision::runtime_resolution();
    println!(
        "onnxruntime: resolver_candidate={candidate:?} version={}",
        verdict?
    );
    println!(
        "runtime_selection: ORT_DYLIB_PATH={:?} IRLUME_TFLITE_LIB={:?}",
        std::env::var_os("ORT_DYLIB_PATH"),
        std::env::var_os("IRLUME_TFLITE_LIB")
    );
    println!("execution_provider=not-observed; record Cargo features; production wrappers may fall back to CPU");
    // Linux maps identify the actual loaded files even when the resolver uses
    // a soname. No guessed installed version or hash of an unused override.
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    let paths: BTreeSet<_> = maps
        .lines()
        .filter_map(|line| {
            let path = &line[line.find('/')?..];
            let name = Path::new(path).file_name()?.to_str()?;
            (name.starts_with("libonnxruntime.so") || name.starts_with("libtensorflowlite_c.so"))
                .then_some(path)
        })
        .collect();
    if paths.is_empty() {
        return Err("no loaded runtime paths found in /proc/self/maps".into());
    }
    for path in paths {
        file("mapped_runtime", Path::new(path))?;
    }
    Ok(())
}
