#![no_main]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Generate small declared graphs and check deterministic, bounded resolution.

use irlume_vision::native_generation::{
    check, EdgeKind, ExecutableBinding, GraphDescription, NodeBytes, NodeDeclaration, NodeId,
    MAX_EDGES, MAX_NODES,
};
use libfuzzer_sys::fuzz_target;

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        0
    } else {
        data[index % data.len()]
    }
}

fn word(bytes: &mut [u8], offset: usize, value: u64, size: usize) {
    bytes[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
}

fn image(
    needed: &[String],
    soname: &str,
    runpath: Option<&str>,
    extra: Option<(i64, u64)>,
    interp: Option<&str>,
) -> Vec<u8> {
    let headers = 2 + usize::from(interp.is_some());
    let mut strings = vec![0];
    let mut entries = Vec::new();
    for name in needed {
        entries.push((1i64, strings.len() as u64));
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    entries.push((14, strings.len() as u64));
    strings.extend_from_slice(soname.as_bytes());
    strings.push(0);
    if let Some(path) = runpath {
        entries.push((29, strings.len() as u64));
        strings.extend_from_slice(path.as_bytes());
        strings.push(0);
    }
    if let Some(entry) = extra {
        entries.push(entry);
    }
    let dynamic = 64 + headers * 56;
    let dynamic_size = (entries.len() + 3) * 16;
    let table = dynamic + dynamic_size;
    let interpreter = table + strings.len();
    let size = interpreter + interp.map_or(0, |value| value.len() + 1);
    let mut bytes = vec![0u8; size];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value, width) in [
        (16, 3, 2),
        (18, 62, 2),
        (20, 1, 4),
        (32, 64, 8),
        (52, 64, 2),
        (54, 56, 2),
        (56, headers as u64, 2),
    ] {
        word(&mut bytes, offset, value, width);
    }
    for (index, kind, offset, length) in [(0, 1, 0, size), (1, 2, dynamic, dynamic_size)] {
        let base = 64 + index * 56;
        for (field, value, width) in [
            (0, kind, 4),
            (4, 4, 4),
            (8, offset as u64, 8),
            (16, 0x1000 + offset as u64, 8),
            (32, length as u64, 8),
            (40, length as u64, 8),
            (48, 8, 8),
        ] {
            word(&mut bytes, base + field, value, width);
        }
    }
    if let Some(path) = interp {
        let base = 64 + 2 * 56;
        for (field, value, width) in [
            (0, 3, 4),
            (4, 4, 4),
            (8, interpreter as u64, 8),
            (16, 0x1000 + interpreter as u64, 8),
            (32, (path.len() + 1) as u64, 8),
            (40, (path.len() + 1) as u64, 8),
            (48, 1, 8),
        ] {
            word(&mut bytes, base + field, value, width);
        }
        bytes[interpreter..interpreter + path.len()].copy_from_slice(path.as_bytes());
    }
    entries.push((5, 0x1000 + table as u64));
    entries.push((10, strings.len() as u64));
    entries.push((0, 0));
    for (index, (tag, value)) in entries.iter().enumerate() {
        word(&mut bytes, dynamic + index * 16, *tag as u64, 8);
        word(&mut bytes, dynamic + index * 16 + 8, *value, 8);
    }
    bytes[table..table + strings.len()].copy_from_slice(&strings);
    bytes
}

fuzz_target!(|data: &[u8]| {
    let count = usize::from(byte(data, 0) % 8) + 1;
    let executable = count > 1 && byte(data, 1) & 1 != 0;
    let ids: Vec<_> = (0..count)
        .map(|index| {
            NodeId(if index == 0 && byte(data, 2) & 1 != 0 {
                65535
            } else {
                u16::try_from(index * 17).unwrap()
            })
        })
        .collect();
    let mut buffers = Vec::new();
    let mut targets = Vec::new();
    for index in 0..count {
        let edge_count = usize::from(byte(data, 3 + index) % 4);
        let wanted: Vec<_> = (0..edge_count)
            .map(|edge| usize::from(byte(data, 16 + index * 4 + edge)) % count)
            .collect();
        let names: Vec<_> = wanted
            .iter()
            .map(|target| {
                if executable && *target == 0 {
                    "app".to_owned()
                } else {
                    format!("n{target}.so")
                }
            })
            .collect();
        let soname = if executable && index == 0 {
            "app".to_owned()
        } else {
            format!("n{index}.so")
        };
        let runpath = match byte(data, 48 + index) % 5 {
            0 => None,
            1 => Some(if executable && index == 0 {
                "$ORIGIN/../lib"
            } else {
                "$ORIGIN"
            }),
            2 => Some(""),
            3 => Some("$LIB"),
            _ => Some("$ORIGIN:$ORIGIN"),
        };
        let extra = match byte(data, 56 + index) % 5 {
            0 => Some((0x12345678, 0)),
            1 => Some((30, 0x19)),
            2 => Some((30, 0x80000000)),
            _ => None,
        };
        buffers.push(image(
            &names,
            &soname,
            runpath,
            extra,
            (executable && index == 0).then_some("/fixture/lib/n1.so"),
        ));
        targets.push(wanted);
    }
    let declarations = buffers
        .iter()
        .enumerate()
        .map(|(index, bytes)| NodeDeclaration {
            id: ids[index],
            path: if executable && index == 0 {
                "bin/app".into()
            } else {
                format!("lib/n{index}.so")
            },
            sha256: irlume_common::sha256_hex(bytes),
            aliases: match byte(data, 64 + index) % 4 {
                0 => vec![],
                1 => vec![format!("a{index}.so")],
                2 => vec!["n0.so".into()],
                _ => vec!["bad/name".into()],
            },
        })
        .collect();
    let description = GraphDescription {
        logical_root: "/fixture".into(),
        nodes: declarations,
        roots: if byte(data, 72) & 1 != 0 {
            ids.clone()
        } else {
            vec![ids[0]]
        },
        executable: executable.then(|| ExecutableBinding {
            node: ids[0],
            interpreter: Some(ids[1]),
        }),
    };
    let mut inputs: Vec<_> = buffers
        .iter()
        .enumerate()
        .map(|(index, bytes)| NodeBytes {
            id: ids[index],
            bytes,
        })
        .collect();
    if byte(data, 73) & 1 != 0 {
        inputs.reverse();
    }
    let first = check(&description, &inputs);
    if data == include_bytes!("../seeds/native_generation/library-graph.bin")
        || data == include_bytes!("../seeds/native_generation/interpreter-graph.bin")
    {
        assert!(
            first.is_ok(),
            "positive graph seed must reach successful resolution"
        );
    }
    match (first, check(&description, &inputs)) {
        (Err(left), Err(right)) => assert!(left == right),
        (Ok(left), Ok(right)) => {
            assert!(left.nodes().len() == count && count <= MAX_NODES);
            assert!(left.edges().len() <= MAX_EDGES);
            assert!(left.policy_id() == right.policy_id());
            assert!(left.roots() == description.roots && left.roots() == right.roots());
            assert!(left.edges() == right.edges());
            for (index, node) in left.nodes().iter().enumerate() {
                assert!(node.id() == ids[index]);
                assert!(node.bytes().as_ptr() == buffers[index].as_ptr());
                assert!(node.bytes().len() == buffers[index].len());
                assert!(node.sha256() == description.nodes[index].sha256);
                let edges: Vec<_> = left
                    .edges()
                    .iter()
                    .filter(|edge| {
                        edge.from == node.id() && matches!(edge.kind, EdgeKind::Needed { .. })
                    })
                    .collect();
                assert!(edges.len() == targets[index].len());
                for (dynamic_index, (edge, target)) in edges.iter().zip(&targets[index]).enumerate()
                {
                    assert!(!executable || *target != 0);
                    assert!(edge.to == ids[*target]);
                    assert!(edge.kind == EdgeKind::Needed { dynamic_index });
                }
            }
            let interpreters = left
                .edges()
                .iter()
                .filter(|edge| matches!(edge.kind, EdgeKind::Interpreter))
                .count();
            assert!(interpreters == usize::from(executable));
            if executable {
                let interpreter = left
                    .edges()
                    .iter()
                    .find(|edge| matches!(edge.kind, EdgeKind::Interpreter))
                    .unwrap();
                assert!(interpreter.from == ids[0] && interpreter.to == ids[1]);
            }
        }
        _ => panic!("declared graph resolution is not deterministic"),
    }
});
