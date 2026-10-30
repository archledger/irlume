// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

#[derive(Default)]
pub(super) struct Image<'a> {
    pub needed: &'a [&'a str],
    pub sonames: &'a [&'a str],
    pub runpaths: &'a [&'a str],
    pub interpreter: Option<&'a str>,
    pub tags: &'a [(i64, u64)],
    pub trailing: &'a [(i64, u64)],
}

impl Image<'_> {
    pub fn bytes(&self) -> Vec<u8> {
        fn u16_at(b: &mut [u8], o: usize, v: u16) {
            b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn u32_at(b: &mut [u8], o: usize, v: u32) {
            b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn u64_at(b: &mut [u8], o: usize, v: u64) {
            b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        }
        let mut strings = vec![0];
        let mut entries = vec![(5_i64, 0_u64), (10, 0)];
        for (tag, values) in [(1, self.needed), (14, self.sonames), (29, self.runpaths)] {
            for value in values {
                entries.push((tag, strings.len() as u64));
                strings.extend_from_slice(value.as_bytes());
                strings.push(0);
            }
        }
        entries[1].1 = strings.len() as u64;
        entries.extend_from_slice(self.tags);
        entries.push((0, 0));
        entries.extend_from_slice(self.trailing);
        let string_offset = 512 + entries.len() * 16;
        let interpreter_offset = string_offset + strings.len();
        let interpreter_size = self.interpreter.map_or(0, |v| v.len() + 1);
        let mut bytes = vec![0; interpreter_offset + interpreter_size + 16];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        u16_at(&mut bytes, 16, 3);
        u16_at(&mut bytes, 18, 62);
        u32_at(&mut bytes, 20, 1);
        u64_at(&mut bytes, 32, 64);
        u16_at(&mut bytes, 52, 64);
        u16_at(&mut bytes, 54, 56);
        u16_at(
            &mut bytes,
            56,
            if self.interpreter.is_some() { 3 } else { 2 },
        );
        let size = bytes.len() as u64;
        for (index, kind, off, len) in [
            (0, 1, 0, size),
            (1, 2, 512, (entries.len() * 16) as u64),
            (2, 3, interpreter_offset as u64, interpreter_size as u64),
        ] {
            if index == 2 && self.interpreter.is_none() {
                continue;
            }
            let at = 64 + index * 56;
            u32_at(&mut bytes, at, kind);
            u32_at(&mut bytes, at + 4, 4);
            u64_at(&mut bytes, at + 8, off);
            u64_at(&mut bytes, at + 16, 0x1000 + off);
            u64_at(&mut bytes, at + 32, len);
            u64_at(&mut bytes, at + 40, len);
            u64_at(&mut bytes, at + 48, 1);
        }
        for (i, (tag, value)) in entries.iter().enumerate() {
            u64_at(&mut bytes, 512 + i * 16, *tag as u64);
            u64_at(
                &mut bytes,
                520 + i * 16,
                if *tag == 5 {
                    0x1000 + string_offset as u64
                } else {
                    *value
                },
            );
        }
        bytes[string_offset..string_offset + strings.len()].copy_from_slice(&strings);
        if let Some(value) = self.interpreter {
            bytes[interpreter_offset..interpreter_offset + value.len()]
                .copy_from_slice(value.as_bytes());
        }
        bytes
    }
}

pub(super) fn description(nodes: &[(u16, &str, &[u8])], roots: &[u16]) -> GraphDescription {
    GraphDescription {
        logical_root: "/fixture".into(),
        nodes: nodes
            .iter()
            .map(|(id, path, bytes)| NodeDeclaration {
                id: NodeId(*id),
                path: (*path).into(),
                sha256: irlume_common::sha256_hex(bytes),
                aliases: vec![],
            })
            .collect(),
        roots: roots.iter().copied().map(NodeId).collect(),
        executable: None,
    }
}

pub(super) fn input(id: u16, bytes: &[u8]) -> NodeBytes<'_> {
    NodeBytes {
        id: NodeId(id),
        bytes,
    }
}

fn refuses(d: &GraphDescription, b: &[NodeBytes<'_>], error: GraphError) {
    assert_eq!(check(d, b).err(), Some(error));
}

#[test]
fn generic_sparse_roots_resolve_real_parsed_transitive_cycles() {
    let a = Image {
        needed: &["b.so"],
        ..Image::default()
    }
    .bytes();
    let b = Image {
        needed: &["a.so"],
        ..Image::default()
    }
    .bytes();
    let d = description(&[(65535, "lib/a.so", &a), (3, "lib/b.so", &b)], &[65535, 3]);
    let g = check(&d, &[input(3, &b), input(65535, &a)]).unwrap();
    assert_eq!(g.roots(), &[NodeId(65535), NodeId(3)]);
    assert_eq!(g.nodes()[0].id(), NodeId(65535));
    assert_eq!(g.nodes()[0].bytes().as_ptr(), a.as_ptr());
    assert_eq!(g.nodes()[0].sha256(), d.nodes[0].sha256);
    assert_eq!(g.edges().len(), 2);
    assert_eq!(
        (g.edges()[0].from, g.edges()[0].to),
        (NodeId(65535), NodeId(3))
    );
}

#[test]
fn repeated_needed_edges_keep_dynamic_order() {
    let a = Image {
        needed: &["c.so", "b.so", "c.so"],
        ..Image::default()
    }
    .bytes();
    let b = Image::default().bytes();
    let d = description(
        &[
            (1, "lib/a.so", &a),
            (7, "lib/b.so", &b),
            (9, "lib/c.so", &b),
        ],
        &[1],
    );
    let g = check(&d, &[input(1, &a), input(7, &b), input(9, &b)]).unwrap();
    assert_eq!(
        g.edges().iter().map(|e| (e.to, e.kind)).collect::<Vec<_>>(),
        vec![
            (NodeId(9), EdgeKind::Needed { dynamic_index: 2 }),
            (NodeId(7), EdgeKind::Needed { dynamic_index: 3 }),
            (NodeId(9), EdgeKind::Needed { dynamic_index: 4 }),
        ]
    );
}

#[test]
fn input_ids_and_digests_are_exact_bijections() {
    let b = Image::default().bytes();
    let d = description(&[(7, "lib/a.so", &b)], &[7]);
    for inputs in [vec![], vec![input(8, &b)], vec![input(7, &b), input(7, &b)]] {
        refuses(&d, &inputs, GraphError::InputMismatch);
    }
    let mut wrong = b.clone();
    wrong[8] = 1;
    refuses(&d, &[input(7, &wrong)], GraphError::DigestMismatch);
    for hash in ["", "abcd", &"A".repeat(64), &"g".repeat(64)] {
        let mut changed = d.clone();
        changed.nodes[0].sha256 = hash.into();
        refuses(&changed, &[input(7, &b)], GraphError::InvalidDigest);
    }
    let mut duplicate = d.clone();
    duplicate.nodes.push(duplicate.nodes[0].clone());
    refuses(
        &duplicate,
        &[input(7, &b), input(7, &b)],
        GraphError::DuplicateNode,
    );
}

#[test]
fn empty_duplicate_missing_roots_and_unreachable_members_refuse() {
    let b = Image::default().bytes();
    for roots in [vec![], vec![7, 7], vec![8]] {
        let d = description(&[(7, "lib/a.so", &b)], &roots);
        refuses(&d, &[input(7, &b)], GraphError::Roots);
    }
    let d = description(&[(7, "lib/a.so", &b), (8, "lib/b.so", &b)], &[7]);
    refuses(&d, &[input(7, &b), input(8, &b)], GraphError::Unreachable);
}

#[test]
fn aliases_and_sonames_have_one_explicit_library_owner() {
    let a = Image {
        needed: &["alias.so"],
        ..Image::default()
    }
    .bytes();
    let b = Image {
        sonames: &["alias.so"],
        ..Image::default()
    }
    .bytes();
    let mut d = description(&[(1, "lib/a.so", &a), (2, "lib/b.so", &b)], &[1]);
    d.nodes[1].aliases.push("alias.so".into());
    assert!(check(&d, &[input(1, &a), input(2, &b)]).is_ok());
    d.nodes[0].aliases.push("alias.so".into());
    refuses(&d, &[input(1, &a), input(2, &b)], GraphError::NameCollision);
    d.nodes[0].aliases.clear();
    d.nodes[1].aliases.push("alias.so".into());
    refuses(&d, &[input(1, &a), input(2, &b)], GraphError::NameCollision);
    d.nodes[1].aliases = vec!["a.so".into()];
    refuses(&d, &[input(1, &a), input(2, &b)], GraphError::NameCollision);
    let mut d = description(&[(2, "lib/b.so", &b)], &[2]);
    refuses(&d, &[input(2, &b)], GraphError::Soname);
    d.nodes[0].aliases.push("alias.so".into());
    assert!(check(&d, &[input(2, &b)]).is_ok());
}

#[test]
fn executable_interpreter_binding_is_explicit_distinct_and_exact() {
    let exe = Image {
        interpreter: Some("/fixture/lib/ld.so"),
        runpaths: &["$ORIGIN/../lib"],
        ..Image::default()
    }
    .bytes();
    let ld = Image::default().bytes();
    let mut d = description(&[(7, "bin/program", &exe), (65535, "lib/ld.so", &ld)], &[7]);
    d.executable = Some(ExecutableBinding {
        node: NodeId(7),
        interpreter: Some(NodeId(65535)),
    });
    let g = check(&d, &[input(7, &exe), input(65535, &ld)]).unwrap();
    assert_eq!(
        g.edges(),
        &[Edge {
            from: NodeId(7),
            to: NodeId(65535),
            kind: EdgeKind::Interpreter
        }]
    );
    d.executable.as_mut().unwrap().interpreter = Some(NodeId(7));
    refuses(
        &d,
        &[input(7, &exe), input(65535, &ld)],
        GraphError::ExecutableBinding,
    );
    d.executable.as_mut().unwrap().interpreter = None;
    refuses(
        &d,
        &[input(7, &exe), input(65535, &ld)],
        GraphError::ExecutableBinding,
    );
    d.executable = None;
    refuses(
        &d,
        &[input(7, &exe), input(65535, &ld)],
        GraphError::ExecutableBinding,
    );
}

#[test]
fn executable_without_interpreter_and_library_only_graphs_work() {
    let b = Image::default().bytes();
    let mut d = description(&[(7, "bin/static-label", &b)], &[7]);
    d.executable = Some(ExecutableBinding {
        node: NodeId(7),
        interpreter: None,
    });
    assert!(check(&d, &[input(7, &b)]).is_ok());
    d.nodes[0].aliases.push("alias".into());
    refuses(&d, &[input(7, &b)], GraphError::InvalidNode);
    let d = description(&[(7, "lib/just-a-library.so", &b)], &[7]);
    assert!(check(&d, &[input(7, &b)]).is_ok());
}

#[test]
fn runpath_templates_are_fixture_only_and_duplicates_refuse() {
    for value in [
        "$ORIGIN",
        "",
        "${ORIGIN}",
        "$ORIGIN:$ORIGIN",
        "$LIB",
        "/lib",
    ] {
        let b = Image {
            runpaths: &[value],
            ..Image::default()
        }
        .bytes();
        let d = description(&[(1, "lib/a.so", &b)], &[1]);
        assert_eq!(check(&d, &[input(1, &b)]).is_ok(), value == "$ORIGIN");
    }
    let b = Image {
        runpaths: &["$ORIGIN", "$ORIGIN"],
        ..Image::default()
    }
    .bytes();
    refuses(
        &description(&[(1, "lib/a.so", &b)], &[1]),
        &[input(1, &b)],
        GraphError::DuplicateTag,
    );
    let b = Image {
        sonames: &["a.so", "a.so"],
        ..Image::default()
    }
    .bytes();
    refuses(
        &description(&[(1, "lib/a.so", &b)], &[1]),
        &[input(1, &b)],
        GraphError::DuplicateTag,
    );
}

#[test]
fn active_tag_and_flag_policy_ignores_ineffective_trailing_entries() {
    let permitted = [
        2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 32, 33, 34,
        35, 36, 37, 0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffa, 0x6ffffffc, 0x6ffffffd,
        0x6ffffffe, 0x6fffffff,
    ];
    for tag in permitted {
        let b = Image {
            tags: &[(tag, 123)],
            ..Image::default()
        }
        .bytes();
        let d = description(&[(1, "lib/a.so", &b)], &[1]);
        assert!(check(&d, &[input(1, &b)]).is_ok(), "tag {tag}");
        let b = Image {
            tags: &[(tag, 0), (tag, 0)],
            ..Image::default()
        }
        .bytes();
        refuses(
            &description(&[(1, "lib/a.so", &b)], &[1]),
            &[input(1, &b)],
            GraphError::DuplicateTag,
        );
    }
    for tag in [
        15, 16, 22, 31, 39, 0x6ffffdfd, 0x6ffffefa, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff,
        -1,
    ] {
        let b = Image {
            tags: &[(tag, 0)],
            ..Image::default()
        }
        .bytes();
        refuses(
            &description(&[(1, "lib/a.so", &b)], &[1]),
            &[input(1, &b)],
            GraphError::TagPolicy,
        );
        let b = Image {
            trailing: &[(tag, u64::MAX), (29, u64::MAX), (5, u64::MAX)],
            ..Image::default()
        }
        .bytes();
        assert!(check(&description(&[(1, "lib/a.so", &b)], &[1]), &[input(1, &b)]).is_ok());
    }
    for (tag, mask) in [(30, 0x19_u64), (0x6ffffffb, 0x08000001)] {
        for bit in 0..64 {
            let value = 1_u64 << bit;
            let b = Image {
                tags: &[(tag, value)],
                ..Image::default()
            }
            .bytes();
            let d = description(&[(1, "lib/a.so", &b)], &[1]);
            assert_eq!(check(&d, &[input(1, &b)]).is_ok(), value & mask != 0);
        }
    }
}

#[test]
fn roots_paths_aliases_and_needed_names_are_bounded() {
    let b = Image::default().bytes();
    let d = description(&[(1, "lib/a.so", &b)], &[1]);
    for root in [
        "", "/", "relative", "/a/", "/a//b", "/a/../b", "/a/./b", "/a\0b", "/é",
    ] {
        let mut d = d.clone();
        d.logical_root = root.into();
        refuses(&d, &[input(1, &b)], GraphError::InvalidRoot);
    }
    for path in [
        "lib/", "lib/.", "lib/..", "lib/a/b", "other/a", "lib/a\0b", "lib/é",
    ] {
        let mut d = d.clone();
        d.nodes[0].path = path.into();
        refuses(&d, &[input(1, &b)], GraphError::InvalidNode);
    }
    let mut long = d.clone();
    long.logical_root = format!("/{}", "a".repeat(4094));
    refuses(&long, &[input(1, &b)], GraphError::Limits);
    let mut limit = d.clone();
    limit.nodes[0].path = format!("lib/{}", "a".repeat(255));
    assert!(check(&limit, &[input(1, &b)]).is_ok());
    limit.nodes[0].path.push('a');
    refuses(&limit, &[input(1, &b)], GraphError::InvalidNode);
    for needed in ["", ".", "..", "a/b", "$ORIGIN/a", "a:b"] {
        let b = Image {
            needed: &[needed],
            ..Image::default()
        }
        .bytes();
        refuses(
            &description(&[(1, "lib/a.so", &b)], &[1]),
            &[input(1, &b)],
            GraphError::Needed,
        );
    }
    let b = Image {
        needed: &["missing.so"],
        ..Image::default()
    }
    .bytes();
    refuses(
        &description(&[(1, "lib/a.so", &b)], &[1]),
        &[input(1, &b)],
        GraphError::Unresolved,
    );
}

#[test]
fn malformed_elf_is_rejected_after_its_exact_digest_matches() {
    let b = b"not an ELF";
    refuses(
        &description(&[(1, "lib/a.so", b)], &[1]),
        &[input(1, b)],
        GraphError::Metadata,
    );
}

#[test]
fn graph_is_borrowed_descriptive_and_does_not_replace_certification() {
    let b = Image::default().bytes();
    let d = description(&[(1, "lib/a.so", &b)], &[1]);
    let g = check(&d, &[input(1, &b)]).unwrap();
    assert!(std::ptr::eq(g.description(), &d));
    assert_eq!(g.policy_id(), POLICY_ID);
    #[cfg(feature = "npu")]
    assert!(crate::npu::runtime::admit_loading().is_err());
}

#[test]
fn graph_owned_reservations_fail_without_partial_success() {
    let bytes = Image::default().bytes();
    let d = description(&[(0, "lib/a.so", &bytes)], &[0]);
    for fail_at in 1..=5 {
        let mut calls = 0;
        let result = check_with_reserve(&d, &[input(0, &bytes)], &mut || {
            calls += 1;
            if calls == fail_at {
                Err(GraphError::Allocation)
            } else {
                Ok(())
            }
        });
        assert_eq!(result.err(), Some(GraphError::Allocation));
        assert_eq!(calls, fail_at);
    }
    let mut calls = 0;
    assert!(check_with_reserve(&d, &[input(0, &bytes)], &mut || {
        calls += 1;
        Ok(())
    })
    .is_ok());
    assert_eq!(calls, 5);
}

#[test]
fn content_and_path_budgets_use_checked_math_without_large_allocations() {
    let mut total = 0;
    for _ in 0..4 {
        charge_bytes(&mut total, MAX_NODE_BYTES).unwrap();
    }
    assert_eq!(total, MAX_TOTAL_BYTES);
    assert_eq!(charge_bytes(&mut total, 1), Err(GraphError::Limits));
    assert_eq!(total, MAX_TOTAL_BYTES);
    assert_eq!(
        charge_bytes(&mut 0, MAX_NODE_BYTES + 1),
        Err(GraphError::Limits)
    );
    let mut overflow = usize::MAX;
    assert_eq!(charge_bytes(&mut overflow, 1), Err(GraphError::Limits));
    assert_eq!(joined_length(4096 - 1 - 8, 8), Ok(4096));
    assert_eq!(joined_length(4096 - 8, 8), Err(GraphError::Limits));
    assert_eq!(joined_length(usize::MAX, 1), Err(GraphError::Limits));
    let bytes = Image::default().bytes();
    let mut d = description(&[(1, "lib/a.so", &bytes)], &[1]);
    d.logical_root = format!("/{}", "a".repeat(4086));
    assert!(check(&d, &[input(1, &bytes)]).is_ok());
    d.logical_root.push('a');
    refuses(&d, &[input(1, &bytes)], GraphError::Limits);
}

#[test]
fn interpreter_and_repeated_needed_edges_share_one_budget() {
    let mut edges = reserve(MAX_EDGES, &mut || Ok(())).unwrap();
    let needed = Edge {
        from: NodeId(0),
        to: NodeId(1),
        kind: EdgeKind::Needed { dynamic_index: 2 },
    };
    for _ in 0..MAX_EDGES - 1 {
        add_edge(&mut edges, needed).unwrap();
    }
    add_edge(
        &mut edges,
        Edge {
            from: NodeId(0),
            to: NodeId(1),
            kind: EdgeKind::Interpreter,
        },
    )
    .unwrap();
    assert_eq!(edges.len(), MAX_EDGES);
    assert_eq!(add_edge(&mut edges, needed), Err(GraphError::Limits));
    assert_eq!(edges.len(), MAX_EDGES);

    // The same guard is exercised by public checking, not only its helper.
    let needed = vec!["target.so"; 256];
    let bytes = Image {
        needed: &needed,
        ..Image::default()
    }
    .bytes();
    let declarations: Vec<_> = (0..17)
        .map(|id| {
            (
                id,
                if id == 0 {
                    "lib/target.so".to_owned()
                } else {
                    format!("lib/node{id}.so")
                },
            )
        })
        .collect();
    let make = |count| GraphDescription {
        logical_root: "/fixture".into(),
        nodes: declarations[..count]
            .iter()
            .map(|(id, path)| NodeDeclaration {
                id: NodeId(*id),
                path: path.clone(),
                sha256: irlume_common::sha256_hex(&bytes),
                aliases: vec![],
            })
            .collect(),
        roots: declarations[..count]
            .iter()
            .map(|(id, _)| NodeId(*id))
            .collect(),
        executable: None,
    };
    let inputs: Vec<_> = declarations
        .iter()
        .map(|(id, _)| input(*id, &bytes))
        .collect();
    assert_eq!(check(&make(16), &inputs[..16]).unwrap().edges().len(), 4096);
    refuses(&make(17), &inputs, GraphError::Limits);
}

#[test]
fn node_root_and_alias_count_ceilings_are_enforced() {
    let bytes = Image::default().bytes();
    let mut d = description(&[(1, "lib/a.so", &bytes)], &[1]);
    d.nodes[0].aliases = (0..256).map(|n| format!("alias{n}")).collect();
    assert!(check(&d, &[input(1, &bytes)]).is_ok());
    d.nodes[0].aliases.push("one-more".into());
    refuses(&d, &[input(1, &bytes)], GraphError::Limits);
    d.nodes[0].aliases.clear();
    let mut too_many = d.clone();
    too_many.roots = vec![NodeId(1); 257];
    refuses(&too_many, &[input(1, &bytes)], GraphError::Limits);
    let mut too_many = d.clone();
    too_many.nodes = vec![d.nodes[0].clone(); 257];
    refuses(&too_many, &[input(1, &bytes)], GraphError::Limits);

    let digest = irlume_common::sha256_hex(&bytes);
    let nodes: Vec<_> = (0..256)
        .map(|id| NodeDeclaration {
            id: NodeId(id),
            path: format!("lib/node{id}.so"),
            sha256: digest.clone(),
            aliases: vec![],
        })
        .collect();
    let roots = nodes.iter().map(|node| node.id).collect();
    let inputs: Vec<_> = nodes.iter().map(|node| input(node.id.0, &bytes)).collect();
    let exact = GraphDescription {
        logical_root: "/fixture".into(),
        nodes,
        roots,
        executable: None,
    };
    assert_eq!(check(&exact, &inputs).unwrap().nodes().len(), MAX_NODES);
}

#[test]
fn executable_bindings_reject_missing_nonroot_and_foreign_interpreters() {
    let bytes = Image {
        interpreter: Some("/foreign/lib/ld.so"),
        ..Image::default()
    }
    .bytes();
    let library = Image::default().bytes();
    let mut d = description(
        &[(3, "bin/program", &bytes), (8, "lib/ld.so", &library)],
        &[3],
    );
    d.executable = Some(ExecutableBinding {
        node: NodeId(3),
        interpreter: Some(NodeId(8)),
    });
    refuses(
        &d,
        &[input(3, &bytes), input(8, &library)],
        GraphError::ExecutableBinding,
    );
    d.executable.as_mut().unwrap().interpreter = Some(NodeId(9));
    refuses(
        &d,
        &[input(3, &bytes), input(8, &library)],
        GraphError::ExecutableBinding,
    );
    d.executable.as_mut().unwrap().interpreter = Some(NodeId(8));
    d.roots = vec![NodeId(8)];
    refuses(
        &d,
        &[input(3, &bytes), input(8, &library)],
        GraphError::ExecutableBinding,
    );
    let mut library = library.clone();
    library[16..18].copy_from_slice(&2_u16.to_le_bytes());
    let d = description(&[(8, "lib/ld.so", &library)], &[8]);
    refuses(&d, &[input(8, &library)], GraphError::ExecutableBinding);
}

#[test]
fn active_string_table_duplicates_and_header_flags_refuse() {
    for tag in [5, 10] {
        let bytes = Image {
            tags: &[(tag, 0)],
            ..Image::default()
        }
        .bytes();
        refuses(
            &description(&[(1, "lib/a.so", &bytes)], &[1]),
            &[input(1, &bytes)],
            GraphError::Metadata,
        );
    }
    for tag in [30, 0x6ffffffb] {
        let bytes = Image {
            tags: &[(tag, 0), (tag, 0)],
            ..Image::default()
        }
        .bytes();
        refuses(
            &description(&[(1, "lib/a.so", &bytes)], &[1]),
            &[input(1, &bytes)],
            GraphError::DuplicateTag,
        );
    }
    let mut bytes = Image::default().bytes();
    bytes[48..52].copy_from_slice(&1_u32.to_le_bytes());
    refuses(
        &description(&[(1, "lib/a.so", &bytes)], &[1]),
        &[input(1, &bytes)],
        GraphError::FlagPolicy,
    );
}
