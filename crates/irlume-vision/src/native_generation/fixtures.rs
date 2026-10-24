// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Evidence-only adapter for retained fixture observations. Logical paths are
//! explicitly remapped labels, not verified physical paths or launch authority.

use super::{check, DeclaredGraph, GraphDescription, GraphError, NodeBytes, NodeId, MAX_NODES};
use crate::measurement_profile::observe::ObservedFixtureFiles;
use std::fmt;

/// Value-redacted failures in the explicit observation-to-node bijection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureGraphError {
    /// A binding is missing, repeated, out of range or names an unknown node.
    Bindings,
    /// A bounded input-view allocation failed.
    Allocation,
    /// The real byte graph refused the description.
    Graph(GraphError),
}

impl fmt::Display for FixtureGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture graph adapter refused: {self:?}")
    }
}
impl std::error::Error for FixtureGraphError {}

/// Check retained real fixture buffers under explicit observation-index/ID
/// bindings. Every observation and declared node must occur exactly once.
/// The returned graph borrows the observation buffers and its own description;
/// the ordinal mapping deliberately does not compare physical and logical paths.
/// It proves no physical-path binding, stable filesystem, runtime role or launch
/// permission and never reopens files or exports descriptors.
///
/// # Errors
/// Returns a fixed error for a missing/repeated/unknown binding or allocation,
/// or the underlying declared-graph refusal over the actual retained buffers.
pub fn check_observed<'a>(
    description: &'a GraphDescription,
    observations: &'a ObservedFixtureFiles,
    bindings: &[(usize, NodeId)],
) -> Result<DeclaredGraph<'a>, FixtureGraphError> {
    let count = observations.files().len();
    if count > MAX_NODES || bindings.len() != count || description.nodes.len() != count {
        return Err(FixtureGraphError::Bindings);
    }
    for (i, (index, id)) in bindings.iter().enumerate() {
        if *index >= count
            || !description.nodes.iter().any(|node| node.id == *id)
            || bindings[..i]
                .iter()
                .any(|(prior_index, prior_id)| prior_index == index || prior_id == id)
        {
            return Err(FixtureGraphError::Bindings);
        }
    }
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(count)
        .map_err(|_| FixtureGraphError::Allocation)?;
    for (index, id) in bindings {
        inputs.push(NodeBytes {
            id: *id,
            bytes: observations.files()[*index].bytes(),
        });
    }
    check(description, &inputs).map_err(FixtureGraphError::Graph)
}

#[cfg(test)]
mod tests;
