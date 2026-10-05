// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Explicit, non-granting two-device transport probe. No frames are saved.

use irlume_camera::{
    camera_inventory_publication, capture_split_pair_with_control,
    lease::{acquire_split_camera_operation, CameraOperationKind, SplitLeaseRequest},
    CaptureControl, Role, SplitSideExpectation,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

fn main() {
    if run().is_err() {
        eprintln!("split capture probe refused");
        std::process::exit(1);
    }
}

fn run() -> Result<(), &'static str> {
    // SAFETY: geteuid has no pointers or preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("root required");
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(2..=3).contains(&args.len()) || (args.len() == 3 && args[2] != "--cancel-after-rgb") {
        eprintln!("usage: split_capture_probe RGB_NODE IR_NODE [--cancel-after-rgb]");
        return Err("arguments");
    }
    // Explicit classification of the complete observed inventory, not a filtered
    // view that hides an ordinary pair's claim. This probe reserves transport;
    // it never publishes a split candidate or authorizes an account.
    let _scan = irlume_camera::scan_nodes();
    let (snapshot, sides) = camera_inventory_publication();
    let side = |path: &str, role| -> Result<SplitSideExpectation, &'static str> {
        let mut matches = sides
            .iter()
            .filter(|side| side.endpoint == path && side.role == role);
        let found = matches.next().ok_or("side unavailable")?;
        if matches.next().is_some() {
            return Err("ambiguous side");
        }
        Ok(SplitSideExpectation {
            instance_id: found.instance_id.clone(),
            generation: found.generation,
            endpoint: found.endpoint.clone(),
            identity: found.identity.clone(),
            controller: found.controller.clone(),
            domain: found.domain.clone(),
            ports: found.ports.clone(),
        })
    };
    let expected = SplitLeaseRequest {
        supervisor_id: snapshot.supervisor_id.ok_or("inventory unavailable")?,
        revision: snapshot.revision,
        rgb: side(&args[0], Role::Rgb)?,
        ir: side(&args[1], Role::Ir)?,
    };
    let operation = acquire_split_camera_operation(
        &expected,
        CameraOperationKind::Diagnostics,
        Duration::from_secs(2),
    )
    .map_err(|_| "lease refused")?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancelled);
    let cancel_after_rgb = args.len() == 3;
    let control = CaptureControl::new(
        irlume_camera::no_progress(),
        Arc::new(move || flag.load(Ordering::SeqCst)),
    )
    .with_deadline(Some(Instant::now() + Duration::from_secs(30)));
    let started = Instant::now();
    let result = if cancel_after_rgb {
        irlume_camera::capture_split_pair_observed(
            &args[0],
            &args[1],
            &operation,
            &control,
            &|role, _| {
                if role == irlume_camera::contracts::StreamRole::Rgb {
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
        )
    } else {
        capture_split_pair_with_control(&args[0], &args[1], &operation, &control)
    };
    let outcome = match result {
        Ok(capture) if !cancel_after_rgb => {
            let (rgb, ir, _) = capture
                .into_parts(&operation)
                .map_err(|_| "receipt refused")?;
            if rgb.provenance().binding().camera_instance_id()
                == ir.provenance().binding().camera_instance_id()
                || operation.lease().validate().is_err()
            {
                return Err("provenance refused");
            }
            "complete"
        }
        Err(irlume_common::Error::Preempted(_)) if cancel_after_rgb => "cancelled_after_rgb",
        _ => return Err("capture refused"),
    };
    drop(operation);
    // New diagnostic reservations prove neither side remained owned by this
    // process. They open no camera and establish no cross-process exclusivity.
    for endpoint in [&args[0], &args[1]] {
        let released = irlume_camera::lease::acquire_camera_operation(
            &[endpoint.as_str()],
            CameraOperationKind::Diagnostics,
            Duration::ZERO,
        )
        .map_err(|_| "reservation retained")?;
        drop(released);
    }
    println!(
        "{}",
        serde_json::json!({
            "outcome":outcome, "split":true, "sequential":true,
            "reservations_released":true, "elapsed_ms":started.elapsed().as_millis(),
            "account_authorization":false,
        })
    );
    Ok(())
}
