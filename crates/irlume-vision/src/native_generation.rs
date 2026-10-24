// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Complete declared graphs in a single-library fixture namespace.
//! This does not model glibc resolution, discover runtime roots, validate an ABI,
//! establish physical paths or issue native-loading permission.

use crate::native_metadata::{inspect, ElfMetadata, StringKind};
use std::fmt;

/// The fixture-only graph policy, not a certification or generation identity.
pub const POLICY_ID: &str = "declared-fixture-graph-v1";
/// Maximum declared nodes and roots, separately.
pub const MAX_NODES: usize = 256;
/// Maximum explicit aliases across the description.
pub const MAX_ALIASES: usize = 256;
/// Maximum ordered dependency and interpreter edges together.
pub const MAX_EDGES: usize = 4096;
/// Maximum raw bytes for any one supplied node.
pub const MAX_NODE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum raw bytes for all supplied nodes, charged independently.
pub const MAX_TOTAL_BYTES: usize = 1024 * 1024 * 1024;

/// A description-local identifier, never an array index or OS descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId(pub u16);

/// A declared fixture member. Fields are untrusted until checked.
#[derive(Clone)]
pub struct NodeDeclaration {
    /// Unique description-local identity.
    pub id: NodeId,
    /// Exactly bin/basename or lib/basename, not a physical path.
    pub path: String,
    /// Exactly 64 lowercase hexadecimal digits.
    pub sha256: String,
    /// Explicit library lookup names; forbidden for bin/ members.
    pub aliases: Vec<String>,
}

/// Optional executable/interpreter relationship in the declared fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutableBinding {
    /// The sole bin/ member, also required to be a root.
    pub node: NodeId,
    /// Distinct lib/ node whose logical path must match PT_INTERP exactly.
    pub interpreter: Option<NodeId>,
}

/// A generic declared graph, without mandatory runtime-specific component roles.
#[derive(Clone)]
pub struct GraphDescription {
    /// Absolute logical fixture root, not a filesystem acquisition boundary.
    pub logical_root: String,
    /// Declared members in the output's node/edge ordering.
    pub nodes: Vec<NodeDeclaration>,
    /// Nonempty unique explicit roots; no filename establishes a runtime role.
    pub roots: Vec<NodeId>,
    /// At most one explicit executable, or a library-only graph.
    pub executable: Option<ExecutableBinding>,
}

/// Borrowed input bytes. The checker hashes and parses this exact slice once.
#[derive(Clone, Copy)]
pub struct NodeBytes<'a> {
    /// Identifier matched by value, not by position in this input list.
    pub id: NodeId,
    /// Supplied bytes; no content is reopened or fetched.
    pub bytes: &'a [u8],
}

/// One edge's source, preserving repeated DT_NEEDED entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    /// Index of the active DT_NEEDED entry in its source object's dynamic table.
    Needed { dynamic_index: usize },
    /// Explicit PT_INTERP binding; charged to the same edge budget.
    Interpreter,
}

/// An ordered declared relationship, not an observation of loader behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    /// Source node.
    pub from: NodeId,
    /// Target node.
    pub to: NodeId,
    /// Origin of this edge.
    pub kind: EdgeKind,
}

/// Value-redacted graph refusals, never raw paths, hashes or native error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphError {
    /// A count, length or byte-work limit failed.
    Limits,
    /// Logical root syntax is outside the fixture policy.
    InvalidRoot,
    /// A member or alias name is outside the fixture policy.
    InvalidNode,
    /// An expected digest is not exactly lowercase SHA-256 text.
    InvalidDigest,
    /// A node ID occurs more than once.
    DuplicateNode,
    /// Inputs do not form a bijection with the declared node IDs.
    InputMismatch,
    /// Root IDs are empty, repeated or undeclared.
    Roots,
    /// A library name has more than one declared occurrence/owner.
    NameCollision,
    /// Executable placement or interpreter binding disagrees with the description.
    ExecutableBinding,
    /// Bytes do not have their declared digest.
    DigestMismatch,
    /// The supplied ELF cannot be structurally extracted.
    Metadata,
    /// An active tag is outside the explicit fixture policy.
    TagPolicy,
    /// An active singleton tag occurs more than once.
    DuplicateTag,
    /// Header or dynamic flags contain unsupported bits.
    FlagPolicy,
    /// SONAME is not its node's basename or explicitly owned alias.
    Soname,
    /// RUNPATH is not an exact supported fixture template.
    Runpath,
    /// A NEEDED string is not a supported basename.
    Needed,
    /// A NEEDED name has no declared owner.
    Unresolved,
    /// A declared member is unreachable from all explicit roots.
    Unreachable,
    /// A bounded graph-owned reservation failed.
    Allocation,
}

/// One exact node/content binding, retaining its original input bytes.
pub struct CheckedNode<'a> {
    declaration: &'a NodeDeclaration,
    bytes: &'a [u8],
}

/// Checked declared coverage only. Borrows its own description and node buffers;
/// does not replace any legacy manifest, identity, certification or cache key.
pub struct DeclaredGraph<'a> {
    description: &'a GraphDescription,
    nodes: Vec<CheckedNode<'a>>,
    edges: Vec<Edge>,
}

impl CheckedNode<'_> {
    /// The description-local ID, not a descriptor number.
    pub fn id(&self) -> NodeId {
        self.declaration.id
    }
    /// The original input allocation; no physical file is reopened.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// The declared content digest that matched these exact bytes.
    pub fn sha256(&self) -> &str {
        &self.declaration.sha256
    }
}

impl DeclaredGraph<'_> {
    /// The fixture policy name; not a generation or certification identity.
    pub fn policy_id(&self) -> &'static str {
        POLICY_ID
    }
    /// The exact borrowed description checked by this graph.
    pub fn description(&self) -> &GraphDescription {
        self.description
    }
    /// Nodes in declaration order, each retaining its input byte borrow.
    pub fn nodes(&self) -> &[CheckedNode<'_>] {
        &self.nodes
    }
    /// Roots in declaration order; names do not prove runtime component roles.
    pub fn roots(&self) -> &[NodeId] {
        &self.description.roots
    }
    /// Edges in node order; an interpreter edge precedes its node's ordered
    /// NEEDED edges. Repeated NEEDED occurrences remain separate edges.
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "declared fixture graph refused: {self:?}")
    }
}
impl std::error::Error for GraphError {}

struct Name<'a> {
    bytes: &'a [u8],
    owner: NodeId,
}

fn basename(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 255
        && bytes != b"."
        && bytes != b".."
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
}

fn member(path: &str) -> Option<(bool, &str)> {
    let (bin, name) = if let Some(name) = path.strip_prefix("bin/") {
        (true, name)
    } else {
        (false, path.strip_prefix("lib/")?)
    };
    basename(name.as_bytes()).then_some((bin, name))
}

fn joined_length(root: usize, member: usize) -> Result<usize, GraphError> {
    root.checked_add(1)
        .and_then(|n| n.checked_add(member))
        .filter(|n| *n <= 4096)
        .ok_or(GraphError::Limits)
}

fn charge_bytes(total: &mut usize, count: usize) -> Result<(), GraphError> {
    if count > MAX_NODE_BYTES {
        return Err(GraphError::Limits);
    }
    *total = total
        .checked_add(count)
        .filter(|n| *n <= MAX_TOTAL_BYTES)
        .ok_or(GraphError::Limits)?;
    Ok(())
}

fn node_index(description: &GraphDescription, id: NodeId) -> Option<usize> {
    description.nodes.iter().position(|node| node.id == id)
}

fn preflight(d: &GraphDescription, inputs: &[NodeBytes<'_>]) -> Result<usize, GraphError> {
    if d.nodes.is_empty() || d.nodes.len() > MAX_NODES || d.roots.len() > MAX_NODES {
        return Err(GraphError::Limits);
    }
    let root = d.logical_root.as_bytes();
    if root.len() < 2
        || root.len() > 4096
        || !root.starts_with(b"/")
        || !root.is_ascii()
        || root.contains(&0)
        || root[1..]
            .split(|b| *b == b'/')
            .any(|c| c.is_empty() || c == b"." || c == b"..")
    {
        return Err(GraphError::InvalidRoot);
    }
    let mut aliases = 0usize;
    let mut bin_count = 0;
    for (index, node) in d.nodes.iter().enumerate() {
        if d.nodes[..index].iter().any(|other| other.id == node.id) {
            return Err(GraphError::DuplicateNode);
        }
        let (bin, _) = member(&node.path).ok_or(GraphError::InvalidNode)?;
        joined_length(root.len(), node.path.len())?;
        if node.sha256.len() != 64
            || !node
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(GraphError::InvalidDigest);
        }
        if bin {
            bin_count += 1;
            if !node.aliases.is_empty() {
                return Err(GraphError::InvalidNode);
            }
        }
        aliases = aliases
            .checked_add(node.aliases.len())
            .filter(|n| *n <= MAX_ALIASES)
            .ok_or(GraphError::Limits)?;
        if node.aliases.iter().any(|a| !basename(a.as_bytes())) {
            return Err(GraphError::InvalidNode);
        }
    }
    if d.roots.is_empty() {
        return Err(GraphError::Roots);
    }
    for (index, id) in d.roots.iter().enumerate() {
        if node_index(d, *id).is_none() || d.roots[..index].contains(id) {
            return Err(GraphError::Roots);
        }
    }
    match d.executable {
        None if bin_count != 0 => return Err(GraphError::ExecutableBinding),
        Some(binding) => {
            let node = node_index(d, binding.node)
                .map(|i| &d.nodes[i])
                .ok_or(GraphError::ExecutableBinding)?;
            if bin_count != 1 || !node.path.starts_with("bin/") || !d.roots.contains(&binding.node)
            {
                return Err(GraphError::ExecutableBinding);
            }
            if let Some(interpreter) = binding.interpreter {
                let target = node_index(d, interpreter)
                    .map(|i| &d.nodes[i])
                    .ok_or(GraphError::ExecutableBinding)?;
                if interpreter == binding.node || !target.path.starts_with("lib/") {
                    return Err(GraphError::ExecutableBinding);
                }
            }
        }
        None => {}
    }
    if inputs.len() != d.nodes.len() {
        return Err(GraphError::InputMismatch);
    }
    let mut total = 0;
    for (index, input) in inputs.iter().enumerate() {
        charge_bytes(&mut total, input.bytes.len())?;
        if node_index(d, input.id).is_none()
            || inputs[..index].iter().any(|other| other.id == input.id)
        {
            return Err(GraphError::InputMismatch);
        }
    }
    Ok(aliases)
}

fn reserve<T>(
    count: usize,
    hook: &mut impl FnMut() -> Result<(), GraphError>,
) -> Result<Vec<T>, GraphError> {
    hook()?;
    let mut out = Vec::new();
    out.try_reserve_exact(count)
        .map_err(|_| GraphError::Allocation)?;
    Ok(out)
}

fn insert_name<'a>(
    names: &mut Vec<Name<'a>>,
    bytes: &'a [u8],
    owner: NodeId,
) -> Result<(), GraphError> {
    if names.iter().any(|name| name.bytes == bytes) {
        return Err(GraphError::NameCollision);
    }
    names.push(Name { bytes, owner });
    Ok(())
}

fn add_edge(edges: &mut Vec<Edge>, edge: Edge) -> Result<(), GraphError> {
    if edges.len() >= MAX_EDGES {
        return Err(GraphError::Limits);
    }
    edges.push(edge);
    Ok(())
}

// Exact active-tag set for the fixture policy. 35/36/37 are the gABI RELR
// family, absent from elf 0.8.0's exports. No tag here authorizes execution.
const TAGS: &[i64] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29,
    30, 32, 33, 34, 35, 36, 37, 0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffa, 0x6ffffffb,
    0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff,
];

fn check_tags(metadata: &ElfMetadata<'_>) -> Result<(), GraphError> {
    if metadata.header().flags != 0 {
        return Err(GraphError::FlagPolicy);
    }
    let mut seen = [false; TAGS.len()];
    for entry in metadata.active_dynamic_entries() {
        let index = TAGS
            .iter()
            .position(|tag| *tag == entry.tag)
            .ok_or(GraphError::TagPolicy)?;
        if entry.tag != 1 && seen[index] {
            return Err(GraphError::DuplicateTag);
        }
        seen[index] = true;
        let mask = match entry.tag {
            30 => Some(0x19_u64),
            0x6ffffffb => Some(0x08000001),
            _ => None,
        };
        if mask.is_some_and(|mask| entry.value & !mask != 0) {
            return Err(GraphError::FlagPolicy);
        }
    }
    Ok(())
}

fn matches_joined(bytes: &[u8], root: &str, path: &str) -> bool {
    bytes.len() == root.len() + 1 + path.len()
        && bytes.starts_with(root.as_bytes())
        && bytes.get(root.len()) == Some(&b'/')
        && bytes.get(root.len() + 1..) == Some(path.as_bytes())
}

/// Check a complete declared fixture dependency graph over the supplied bytes.
/// Hashing and parsing use each exact input once. No paths, descriptors, loaders
/// or runtime component roles are discovered. Output borrows this description
/// and each buffer, not the input-view collection. No legacy identity/key changes.
///
/// # Errors
/// Returns a fixed refusal for invalid declarations, input mismatches, content or
/// parser failures, unsupported active metadata, unresolved/unreachable nodes,
/// bounded work or failed graph reservations. Per-file parser limits apply too.
/// Content/work budgets do not prevent allocator/kernel OOM or bound acquisition.
///
/// ```
/// use irlume_vision::native_generation::{check, GraphDescription, NodeBytes};
/// fn accepts_borrows<'a>(description: &'a GraphDescription, bytes: &[NodeBytes<'a>]) {
///     let _ = check(description, bytes);
/// }
/// ```
/// ```compile_fail
/// use irlume_vision::native_generation::DeclaredGraph;
/// fn cannot_launch(graph: DeclaredGraph<'_>) { graph.launch(); }
/// ```
pub fn check<'a>(
    description: &'a GraphDescription,
    inputs: &[NodeBytes<'a>],
) -> Result<DeclaredGraph<'a>, GraphError> {
    check_with_reserve(description, inputs, &mut || Ok(()))
}

fn check_with_reserve<'a>(
    d: &'a GraphDescription,
    inputs: &[NodeBytes<'a>],
    hook: &mut impl FnMut() -> Result<(), GraphError>,
) -> Result<DeclaredGraph<'a>, GraphError> {
    let aliases = preflight(d, inputs)?;
    let mut names = reserve(d.nodes.len() + aliases, hook)?;
    for node in &d.nodes {
        let (bin, name) = member(&node.path).ok_or(GraphError::InvalidNode)?;
        if !bin {
            insert_name(&mut names, name.as_bytes(), node.id)?;
            for alias in &node.aliases {
                insert_name(&mut names, alias.as_bytes(), node.id)?;
            }
        }
    }
    let mut nodes = reserve(d.nodes.len(), hook)?;
    let mut metadata = reserve(d.nodes.len(), hook)?;
    let mut edges = reserve(MAX_EDGES, hook)?;
    let mut queue = reserve(d.nodes.len(), hook)?;
    for declaration in &d.nodes {
        let input = inputs
            .iter()
            .find(|input| input.id == declaration.id)
            .ok_or(GraphError::InputMismatch)?;
        if irlume_common::sha256_hex(input.bytes) != declaration.sha256 {
            return Err(GraphError::DigestMismatch);
        }
        metadata.push(inspect(input.bytes).map_err(|_| GraphError::Metadata)?);
        nodes.push(CheckedNode {
            declaration,
            bytes: input.bytes,
        });
    }
    for (index, node) in d.nodes.iter().enumerate() {
        let m = &metadata[index];
        check_tags(m)?;
        match d.executable.filter(|binding| binding.node == node.id) {
            Some(binding) => match (binding.interpreter, m.interpreter()) {
                (None, None) => {}
                (Some(target), Some(value)) => {
                    let target_node =
                        &d.nodes[node_index(d, target).ok_or(GraphError::ExecutableBinding)?];
                    if !matches_joined(value, &d.logical_root, &target_node.path) {
                        return Err(GraphError::ExecutableBinding);
                    }
                    add_edge(
                        &mut edges,
                        Edge {
                            from: node.id,
                            to: target,
                            kind: EdgeKind::Interpreter,
                        },
                    )?;
                }
                _ => return Err(GraphError::ExecutableBinding),
            },
            None if m.header().file_type != 3 || m.interpreter().is_some() => {
                return Err(GraphError::ExecutableBinding)
            }
            None => {}
        }
        for string in m.strings() {
            match string.kind() {
                StringKind::Needed => {
                    if !basename(string.bytes()) {
                        return Err(GraphError::Needed);
                    }
                    let owner = names
                        .iter()
                        .find(|name| name.bytes == string.bytes())
                        .map(|name| name.owner)
                        .ok_or(GraphError::Unresolved)?;
                    add_edge(
                        &mut edges,
                        Edge {
                            from: node.id,
                            to: owner,
                            kind: EdgeKind::Needed {
                                dynamic_index: string.entry_index(),
                            },
                        },
                    )?;
                }
                StringKind::Soname => {
                    let (_, own_name) = member(&node.path).ok_or(GraphError::InvalidNode)?;
                    if string.bytes() != own_name.as_bytes()
                        && !node
                            .aliases
                            .iter()
                            .any(|alias| alias.as_bytes() == string.bytes())
                    {
                        return Err(GraphError::Soname);
                    }
                }
                StringKind::Runpath => {
                    let expected = if node.path.starts_with("lib/") {
                        b"$ORIGIN".as_slice()
                    } else {
                        b"$ORIGIN/../lib"
                    };
                    if string.bytes() != expected {
                        return Err(GraphError::Runpath);
                    }
                }
                StringKind::Rpath => return Err(GraphError::TagPolicy),
            }
        }
    }
    for root in &d.roots {
        queue.push(node_index(d, *root).ok_or(GraphError::Roots)?);
    }
    let mut cursor = 0;
    while cursor < queue.len() {
        let node = d.nodes[queue[cursor]].id;
        for edge in edges.iter().filter(|edge| edge.from == node) {
            let target = node_index(d, edge.to).ok_or(GraphError::Unresolved)?;
            if !queue.contains(&target) {
                queue.push(target);
            }
        }
        cursor += 1;
    }
    if queue.len() != d.nodes.len() {
        return Err(GraphError::Unreachable);
    }
    Ok(DeclaredGraph {
        description: d,
        nodes,
        edges,
    })
}

#[cfg(all(irlume_hw_evidence, feature = "npu"))]
pub mod fixtures;

#[cfg(test)]
mod tests;
