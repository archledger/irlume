// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Strict runtime evidence bound to one immutable camera lease reference.

use crate::contracts::{CameraGeneration, CameraInstanceId, StreamRole};

/// Immutable camera identity and logical role copied from a validated lease.
///
/// This value owns its identity so a dequeued frame never depends on a later
/// `/dev/videoN` lookup or a mutable inventory observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameBinding {
    camera_instance_id: CameraInstanceId,
    generation: CameraGeneration,
    stream_role: StreamRole,
}

impl FrameBinding {
    pub(crate) fn new(
        camera_instance_id: CameraInstanceId,
        generation: CameraGeneration,
        stream_role: StreamRole,
    ) -> Self {
        Self {
            camera_instance_id,
            generation,
            stream_role,
        }
    }

    /// Process-scoped identity of the physical camera incarnation.
    #[must_use]
    pub const fn camera_instance_id(&self) -> &CameraInstanceId {
        &self.camera_instance_id
    }

    /// Lifecycle generation validated when the lease was acquired.
    #[must_use]
    pub const fn generation(&self) -> CameraGeneration {
        self.generation
    }

    /// Logical role of the endpoint producing frames under this binding.
    #[must_use]
    pub const fn stream_role(&self) -> StreamRole {
        self.stream_role
    }
}
