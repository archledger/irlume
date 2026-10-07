// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Process-wide cooperative camera leases and operation lifecycle state.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

use crate::{
    contracts::{CameraInstanceId, StreamRole},
    frame_provenance::FrameBinding,
    inventory::{CameraInventory, CameraInventoryRef},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CameraOperationKind {
    Capture,
    Authentication,
    Enrollment,
    Preview,
    Diagnostics,
    Setup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CameraSessionState {
    Acquiring,
    Acquired,
    Configured,
    Streaming,
    Stopping,
    Released,
    ContinuityLost,
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CameraLeaseError {
    DeadlineExpired {
        current_owner: Option<CameraOperationKind>,
    },
    TokenExhausted,
    Stale,
    UnknownEndpoint,
    /// Every requested endpoint is a live camera node, but they belong to
    /// `cameras` different USB devices, and a lease covers RGB and IR only
    /// within one physical camera (ADR-0031 §3). Carries a count, never the
    /// nodes or their identities (ADR-0030 §4).
    SplitPhysicalCamera {
        cameras: usize,
    },
    Poisoned,
    InvalidTransition {
        from: CameraSessionState,
        to: CameraSessionState,
    },
    EmptyKey,
    EndpointNotCovered,
    AmbiguousEndpointBinding,
    InvalidEndpoint(String),
    /// Split capture is not enabled for enrollment or authentication.
    SplitActivationDisabled,
    /// One stream is already active on a split operation.
    SplitRequiresSequential,
}

impl std::fmt::Display for CameraLeaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeadlineExpired { current_owner } => match current_owner {
                Some(owner) => write!(
                    formatter,
                    "camera lease deadline expired; current owner: {owner:?}"
                ),
                None => formatter.write_str("camera lease deadline expired"),
            },
            Self::TokenExhausted => formatter.write_str("camera lease token space exhausted"),
            Self::Stale => formatter.write_str("camera lifecycle reference is stale"),
            Self::UnknownEndpoint => {
                formatter.write_str("camera endpoint is not in the supervisor inventory")
            }
            Self::SplitPhysicalCamera { cameras } => write!(
                formatter,
                "the RGB and IR nodes are on {cameras} different USB devices; irlume pairs \
                 them only within one physical camera"
            ),
            Self::Poisoned => formatter.write_str("camera lease authority is unavailable"),
            Self::InvalidTransition { from, to } => {
                write!(
                    formatter,
                    "invalid camera session transition from {from:?} to {to:?}"
                )
            }
            Self::EmptyKey => {
                formatter.write_str("camera lease requires at least one physical camera")
            }
            Self::EndpointNotCovered => {
                formatter.write_str("camera endpoint is not covered by this operation lease")
            }
            Self::AmbiguousEndpointBinding => {
                formatter.write_str("camera endpoint is covered by multiple lease references")
            }
            Self::InvalidEndpoint(message) => formatter.write_str(message),
            Self::SplitActivationDisabled => {
                formatter.write_str("split enrollment and authentication are not enabled")
            }
            Self::SplitRequiresSequential => {
                formatter.write_str("split capture requires sequential streaming")
            }
        }
    }
}

impl std::error::Error for CameraLeaseError {}

thread_local! {
    static ACTIVE_OPERATIONS: RefCell<Vec<CameraLease>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn active_permit(endpoint: &str) -> Result<Option<CameraLease>, CameraLeaseError> {
    ACTIVE_OPERATIONS.with(|operations| {
        let lease = operations.borrow().last().cloned();
        if let Some(lease) = lease {
            lease.require_endpoint(endpoint)?;
            Ok(Some(lease))
        } else {
            Ok(None)
        }
    })
}

pub(crate) fn permit_for_discovery(
    endpoint: &str,
    timeout: Duration,
) -> Result<Option<CameraLease>, CameraLeaseError> {
    match permit_for_endpoint(endpoint, CameraOperationKind::Diagnostics, timeout) {
        Ok(permit) => Ok(Some(permit)),
        Err(CameraLeaseError::UnknownEndpoint | CameraLeaseError::InvalidEndpoint(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn permit_for_endpoint(
    endpoint: &str,
    operation: CameraOperationKind,
    timeout: Duration,
) -> Result<CameraLease, CameraLeaseError> {
    if let Some(permit) = active_permit(endpoint)? {
        return Ok(permit);
    }
    let session = acquire_camera_operation(&[endpoint], operation, timeout)?;
    Ok(session.into_lease())
}

struct ActiveOperationGuard;

impl Drop for ActiveOperationGuard {
    fn drop(&mut self) {
        ACTIVE_OPERATIONS.with(|operations| {
            operations.borrow_mut().pop();
        });
    }
}

/// Acquire one operation-scoped lease for all supplied endpoints.
///
/// RGB and IR endpoints from one physical camera resolve to one atomic key. The
/// returned session may be moved across threads, but every open must remain
/// covered by one of its endpoint paths.
///
/// # Errors
///
/// Returns [`CameraLeaseError::Stale`] when the endpoint set is not one current
/// physical-camera observation, [`CameraLeaseError::SplitPhysicalCamera`] when
/// every endpoint is a live camera node but they span several USB devices,
/// [`CameraLeaseError::DeadlineExpired`] on contention, or
/// [`CameraLeaseError::Poisoned`] if supervisor state is unsafe.
pub fn acquire_camera_operation(
    endpoint_paths: &[&str],
    operation: CameraOperationKind,
    timeout: Duration,
) -> Result<CameraOperationSession, CameraLeaseError> {
    #[cfg(feature = "test-support")]
    crate::backend::record_lease_request(endpoint_paths, operation);
    let result = crate::backend::with_camera_supervisor(|supervisor| {
        supervisor.acquire_operation(
            endpoint_paths,
            operation,
            Instant::now()
                .checked_add(timeout)
                .ok_or(CameraLeaseError::DeadlineExpired {
                    current_owner: None,
                })?,
        )
    });
    // Only an endpoint the inventory does not know may be a node that is not
    // a pinned camera at all, so only that refusal is re-examined here. A
    // split pair's nodes are each a live inventory camera; re-checking them
    // would replace the cause the user needs with a per-node verdict.
    if matches!(result, Err(CameraLeaseError::UnknownEndpoint)) {
        for endpoint in endpoint_paths {
            crate::verify_pinned(endpoint)
                .map_err(|error| CameraLeaseError::InvalidEndpoint(error.to_string()))?;
        }
    }
    result
}

/// One ordinary pair chosen from a classified inventory publication.
///
/// These runtime expectations are not credential identity and must not be
/// persisted in an enrollment. Acquisition checks the complete pair even when
/// only its IR endpoint and optional metadata are requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrdinaryLeaseRequest {
    /// Supervisor that published the chosen pair.
    pub supervisor_id: String,
    /// Exact ordinary pair, including its instance, generation and USB facts.
    pub pair: crate::ConnectedPair,
}

/// Acquire an operation for an exact selected ordinary camera incarnation.
///
/// Every requested endpoint must belong to the chosen physical unit. The
/// complete RGB/IR pair is checked against one healthy Current publication;
/// the resulting inventory reference is retained across contention and
/// revalidated before returning a session and on subsequent opens. No fresh
/// path lookup or discovery fallback substitutes a replacement camera.
///
/// # Errors
///
/// Returns [`CameraLeaseError::Stale`] for a foreign supervisor, nonCurrent or
/// unhealthy publication, changed pair facts, or lost continuity while waiting.
/// Returns [`CameraLeaseError::EndpointNotCovered`] for an empty endpoint set
/// or paths outside the selected unit, [`CameraLeaseError::DeadlineExpired`]
/// on contention or deadline overflow, [`CameraLeaseError::TokenExhausted`]
/// on authority exhaustion, or [`CameraLeaseError::Poisoned`] on unsafe state.
pub fn acquire_selected_camera_operation(
    expected: &OrdinaryLeaseRequest,
    endpoints: &[&str],
    kind: CameraOperationKind,
    timeout: Duration,
) -> Result<CameraOperationSession, CameraLeaseError> {
    #[cfg(feature = "test-support")]
    crate::backend::record_lease_request(endpoints, kind);
    let deadline =
        Instant::now()
            .checked_add(timeout)
            .ok_or(CameraLeaseError::DeadlineExpired {
                current_owner: None,
            })?;
    crate::backend::with_camera_supervisor(|supervisor| {
        supervisor.acquire_selected_operation(expected, endpoints, kind, deadline)
    })
}

/// Runtime expectations from one classified inventory publication. These are
/// not credential identity and must not be persisted in an enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitLeaseRequest {
    /// Supervisor that supplied the displayed facts.
    pub supervisor_id: String,
    /// Publication revision that supplied the displayed facts.
    pub revision: u64,
    /// RGB incarnation and persistent facts.
    pub rgb: crate::SplitSideExpectation,
    /// IR incarnation and persistent facts.
    pub ir: crate::SplitSideExpectation,
}

/// Whether the split acquisition and capture gates admit one trust kind.
///
/// Production: false for Authentication, Enrollment and Capture, so both
/// gates keep refusing every split trust operation. Diagnostics, Setup and
/// Preview are not trust kinds; the gates admit them on their own and this
/// returns false for them too. The reviewed activation change edits only
/// this body. No environment or configuration input is read.
///
/// A `test-support` build also asks the non-granting fixture installed on
/// the calling thread, whose admission can name only Enrollment or
/// Authentication and whose backend refuses every open.
#[must_use]
pub fn split_trust_admitted(kind: CameraOperationKind) -> bool {
    match kind {
        CameraOperationKind::Enrollment | CameraOperationKind::Authentication => {
            fixture_admits_split_trust(kind)
        }
        CameraOperationKind::Capture
        | CameraOperationKind::Preview
        | CameraOperationKind::Diagnostics
        | CameraOperationKind::Setup => false,
    }
}

/// No split trust override exists outside `test-support` builds.
#[cfg(not(feature = "test-support"))]
fn fixture_admits_split_trust(_kind: CameraOperationKind) -> bool {
    false
}

/// The calling thread's installed non-granting fixture admission.
#[cfg(feature = "test-support")]
fn fixture_admits_split_trust(kind: CameraOperationKind) -> bool {
    crate::backend::test_support::admits_split_trust(kind)
}

/// Reserve both split-camera instances atomically and bind all subsequent
/// endpoint/stream validation to the supplied facts. Diagnostics, setup and
/// preview may use this primitive; a trust kind only when
/// [`split_trust_admitted`] admits it, which production never does.
///
/// # Errors
/// Refuses stale facts, contention, unsupported operations or unavailable
/// inventory. Failure retains neither instance; ordinary acquisition remains
/// unchanged and still refuses cross-device endpoint sets.
pub fn acquire_split_camera_operation(
    expected: &SplitLeaseRequest,
    operation: CameraOperationKind,
    timeout: Duration,
) -> Result<CameraOperationSession, CameraLeaseError> {
    #[cfg(feature = "test-support")]
    crate::backend::record_lease_request(
        &[
            expected.rgb.endpoint.as_str(),
            expected.ir.endpoint.as_str(),
        ],
        operation,
    );
    if !matches!(
        operation,
        CameraOperationKind::Diagnostics
            | CameraOperationKind::Setup
            | CameraOperationKind::Preview
    ) && !split_trust_admitted(operation)
    {
        return Err(CameraLeaseError::SplitActivationDisabled);
    }
    let deadline =
        Instant::now()
            .checked_add(timeout)
            .ok_or(CameraLeaseError::DeadlineExpired {
                current_owner: None,
            })?;
    crate::backend::with_camera_supervisor(|supervisor| {
        supervisor.acquire_split_operation(expected, operation, deadline)
    })
}

#[derive(Default)]
struct LeaseState {
    next_token: u64,
    next_waiter: u64,
    active: BTreeMap<CameraInstanceId, ActiveLease>,
    waiters: BTreeMap<u64, Vec<CameraInstanceId>>,
}

#[derive(Clone, Copy)]
struct ActiveLease {
    token: u64,
    operation: CameraOperationKind,
}

#[derive(Default)]
pub(crate) struct LeaseAuthority {
    state: Mutex<LeaseState>,
    changed: Condvar,
}

impl LeaseAuthority {
    /// Inspect actual ownership and waiter registration for deterministic tests.
    ///
    /// # Panics
    /// Panics if a test poisoned the lease-authority mutex.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn counts_for_test(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (state.active.len(), state.waiters.len())
    }

    fn acquire(
        self: &Arc<Self>,
        mut keys: Vec<CameraInstanceId>,
        operation: CameraOperationKind,
        deadline: Instant,
    ) -> Result<AuthorityPermit, CameraLeaseError> {
        keys.sort();
        keys.dedup();
        if keys.is_empty() {
            return Err(CameraLeaseError::EmptyKey);
        }

        let mut state = self.state.lock().map_err(|_| CameraLeaseError::Poisoned)?;
        let waiter = state
            .next_waiter
            .checked_add(1)
            .ok_or(CameraLeaseError::TokenExhausted)?;
        state.next_waiter = waiter;
        state.waiters.insert(waiter, keys.clone());

        loop {
            let earlier_conflict = state.waiters.range(..waiter).any(|(_, waiting)| {
                waiting
                    .iter()
                    .any(|waiting_key| keys.binary_search(waiting_key).is_ok())
            });
            if !earlier_conflict && keys.iter().all(|key| !state.active.contains_key(key)) {
                let Some(token) = state.next_token.checked_add(1) else {
                    state.waiters.remove(&waiter);
                    self.changed.notify_all();
                    return Err(CameraLeaseError::TokenExhausted);
                };
                state.next_token = token;
                state.waiters.remove(&waiter);
                for key in &keys {
                    state
                        .active
                        .insert(key.clone(), ActiveLease { token, operation });
                }
                return Ok(AuthorityPermit {
                    authority: self.clone(),
                    token,
                    keys,
                });
            }

            let now = Instant::now();
            if now >= deadline {
                let current_owner = keys
                    .iter()
                    .find_map(|key| state.active.get(key).map(|active| active.operation));
                state.waiters.remove(&waiter);
                self.changed.notify_all();
                return Err(CameraLeaseError::DeadlineExpired { current_owner });
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, timed_out) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| CameraLeaseError::Poisoned)?;
            state = next;
            if timed_out.timed_out() {
                let current_owner = keys
                    .iter()
                    .find_map(|key| state.active.get(key).map(|active| active.operation));
                state.waiters.remove(&waiter);
                self.changed.notify_all();
                return Err(CameraLeaseError::DeadlineExpired { current_owner });
            }
        }
    }
}

struct AuthorityPermit {
    authority: Arc<LeaseAuthority>,
    token: u64,
    keys: Vec<CameraInstanceId>,
}

impl Drop for AuthorityPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.authority.state.lock() else {
            return;
        };
        for key in &self.keys {
            if state
                .active
                .get(key)
                .is_some_and(|active| active.token == self.token)
            {
                state.active.remove(key);
            }
        }
        self.authority.changed.notify_all();
    }
}

struct CameraLeaseInner {
    _permit: AuthorityPermit,
    inventory: Arc<Mutex<CameraInventory>>,
    references: Vec<CameraInventoryRef>,
    operation: CameraOperationKind,
    state: Mutex<CameraSessionState>,
    streams: AtomicUsize,
    split: Option<Box<SplitLeaseRequest>>,
}

impl Drop for CameraLeaseInner {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            *state = CameraSessionState::Released;
        }
    }
}

#[derive(Clone)]
pub struct CameraLease {
    inner: Arc<CameraLeaseInner>,
}

impl CameraLease {
    pub(crate) fn same_operation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
    pub(crate) fn acquire(
        authority: &Arc<LeaseAuthority>,
        inventory: Arc<Mutex<CameraInventory>>,
        references: Vec<CameraInventoryRef>,
        operation: CameraOperationKind,
        deadline: Instant,
    ) -> Result<Self, CameraLeaseError> {
        Self::acquire_bound(authority, inventory, references, operation, deadline, None)
    }

    pub(crate) fn acquire_split(
        authority: &Arc<LeaseAuthority>,
        inventory: Arc<Mutex<CameraInventory>>,
        expected: &SplitLeaseRequest,
        operation: CameraOperationKind,
        deadline: Instant,
    ) -> Result<Self, CameraLeaseError> {
        let references = {
            let held = inventory.lock().map_err(|_| CameraLeaseError::Poisoned)?;
            validate_split_publication(&held, expected, true)?;
            [&expected.rgb.endpoint, &expected.ir.endpoint]
                .iter()
                .map(|path| {
                    held.reference_for_endpoints(&[path.as_str()])
                        .map_err(|_| CameraLeaseError::Stale)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        Self::acquire_bound(
            authority,
            inventory,
            references,
            operation,
            deadline,
            Some(Box::new(expected.clone())),
        )
    }

    fn acquire_bound(
        authority: &Arc<LeaseAuthority>,
        inventory: Arc<Mutex<CameraInventory>>,
        references: Vec<CameraInventoryRef>,
        operation: CameraOperationKind,
        deadline: Instant,
        split: Option<Box<SplitLeaseRequest>>,
    ) -> Result<Self, CameraLeaseError> {
        validate_references(&inventory, &references)?;
        let keys = references
            .iter()
            .map(|reference| reference.descriptor().camera_instance_id().clone())
            .collect();
        let permit = authority.acquire(keys, operation, deadline)?;
        let lease = Self {
            inner: Arc::new(CameraLeaseInner {
                _permit: permit,
                inventory,
                references,
                operation,
                state: Mutex::new(CameraSessionState::Acquiring),
                streams: AtomicUsize::new(0),
                split,
            }),
        };
        if let Some(expected) = lease.inner.split.as_ref() {
            // A waiter may have slept through reconciliation. Validate again
            // after both keys are held; any refusal drops the complete permit.
            let held = lease
                .inner
                .inventory
                .lock()
                .map_err(|_| CameraLeaseError::Poisoned)?;
            validate_split_publication(&held, expected, true)?;
        }
        lease.validate()?;
        lease.set_state(CameraSessionState::Acquired);
        Ok(lease)
    }

    pub(crate) fn run_active<R>(&self, operation: impl FnOnce() -> R) -> R {
        ACTIVE_OPERATIONS.with(|operations| operations.borrow_mut().push(self.clone()));
        let _guard = ActiveOperationGuard;
        operation()
    }

    pub fn operation(&self) -> CameraOperationKind {
        self.inner.operation
    }

    /// Revalidate every descriptor-bound inventory reference.
    ///
    /// # Errors
    ///
    /// Returns [`CameraLeaseError::Stale`] after removal, generation change, or
    /// lifecycle invalidation, and [`CameraLeaseError::Poisoned`] on unsafe state.
    pub fn validate(&self) -> Result<(), CameraLeaseError> {
        match self.state() {
            CameraSessionState::ContinuityLost | CameraSessionState::Released => {
                return Err(CameraLeaseError::Stale);
            }
            CameraSessionState::Fault => return Err(CameraLeaseError::Poisoned),
            _ => {}
        }
        let validation = if let Some(expected) = self.inner.split.as_ref() {
            let held = self
                .inner
                .inventory
                .lock()
                .map_err(|_| CameraLeaseError::Poisoned)?;
            self.inner
                .references
                .iter()
                .try_for_each(|reference| {
                    held.validate_reference(reference)
                        .map_err(|_| CameraLeaseError::Stale)
                })
                .and_then(|()| validate_split_publication(&held, expected, false))
        } else {
            validate_references(&self.inner.inventory, &self.inner.references)
        };
        if let Err(error) = validation {
            self.set_state(CameraSessionState::ContinuityLost);
            return Err(error);
        }
        Ok(())
    }

    pub fn covers_endpoint(&self, path: &str) -> bool {
        if let Some(expected) = self.inner.split.as_ref() {
            return path == expected.rgb.endpoint || path == expected.ir.endpoint;
        }
        self.inner
            .references
            .iter()
            .any(|reference| reference.endpoint_paths().iter().any(|known| known == path))
    }

    pub(crate) fn require_endpoint(&self, path: &str) -> Result<(), CameraLeaseError> {
        self.validate()?;
        if self.covers_endpoint(path) {
            Ok(())
        } else {
            Err(CameraLeaseError::EndpointNotCovered)
        }
    }

    /// Copy immutable frame identity from the one lease reference covering an endpoint.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle validation error for stale inventory, refuses an
    /// uncovered endpoint, and fails closed if malformed lease state contains
    /// more than one reference covering the path.
    pub fn frame_binding(
        &self,
        path: &str,
        stream_role: StreamRole,
    ) -> Result<FrameBinding, CameraLeaseError> {
        self.require_stream_role(path, stream_role)?;
        let mut matching = self
            .inner
            .references
            .iter()
            .filter(|reference| reference.endpoint_paths().iter().any(|known| known == path));
        let reference = matching
            .next()
            .ok_or(CameraLeaseError::EndpointNotCovered)?;
        if matching.next().is_some() {
            return Err(CameraLeaseError::AmbiguousEndpointBinding);
        }
        let descriptor = reference.descriptor();
        Ok(FrameBinding::new(
            descriptor.camera_instance_id().clone(),
            descriptor.generation(),
            stream_role,
        ))
    }

    pub fn state(&self) -> CameraSessionState {
        self.inner
            .state
            .lock()
            .map(|state| *state)
            .unwrap_or(CameraSessionState::Fault)
    }

    pub(crate) fn require_stream_role(
        &self,
        path: &str,
        stream_role: StreamRole,
    ) -> Result<(), CameraLeaseError> {
        self.require_endpoint(path)?;
        if let Some(expected) = self.inner.split.as_ref() {
            if (path == expected.rgb.endpoint && stream_role != StreamRole::Rgb)
                || (path == expected.ir.endpoint && stream_role != StreamRole::Ir)
            {
                return Err(CameraLeaseError::EndpointNotCovered);
            }
        }
        Ok(())
    }

    /// Split-only native admission before any format/control write. Ordinary
    /// opens keep their existing contract. The fd supplies identity and role;
    /// a path lookup cannot stand in for the descriptor that will be configured.
    pub(crate) fn require_split_descriptor(
        &self,
        endpoint: &str,
        device: &v4l::Device,
        role: StreamRole,
    ) -> irlume_common::Result<()> {
        use v4l::video::Capture;
        let Some(_) = self.inner.split.as_ref() else {
            return Ok(());
        };
        self.require_stream_role(endpoint, role)
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
        let identity =
            crate::uvc_descriptor::identity_from_fd(device.handle().fd()).map_err(|_| {
                irlume_common::Error::Hardware("opened descriptor identity is unavailable".into())
            })?;
        self.require_split_fd_identity(endpoint, &identity)?;
        let formats = device.enum_formats().map_err(|_| {
            irlume_common::Error::Hardware("opened descriptor formats are unavailable".into())
        })?;
        let formats: Vec<_> = formats.iter().map(|format| format.fourcc.repr).collect();
        let actual_role =
            crate::role_with_ir_attestation(&formats, || identity.ir_function_evidence().is_ok());
        let wanted = match role {
            StreamRole::Rgb => crate::Role::Rgb,
            StreamRole::Ir => crate::Role::Ir,
        };
        if actual_role != wanted {
            return Err(irlume_common::Error::Hardware(
                "opened descriptor role differs from selected camera".into(),
            ));
        }
        self.require_stream_role(endpoint, role)
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))
    }

    fn require_split_fd_identity(
        &self,
        endpoint: &str,
        identity: &crate::uvc_descriptor::CameraIdentity,
    ) -> irlume_common::Result<()> {
        let expected = self.inner.split.as_ref().ok_or_else(|| {
            irlume_common::Error::Hardware("split fd identity requires a split lease".into())
        })?;
        let side = if endpoint == expected.rgb.endpoint {
            &expected.rgb
        } else if endpoint == expected.ir.endpoint {
            &expected.ir
        } else {
            return Err(irlume_common::Error::Hardware(
                "opened descriptor is not covered".into(),
            ));
        };
        let reference = self
            .inner
            .references
            .iter()
            .find(|reference| {
                reference
                    .endpoint_paths()
                    .iter()
                    .any(|path| path == endpoint)
            })
            .ok_or_else(|| {
                irlume_common::Error::Hardware("opened descriptor is not covered".into())
            })?;
        let binding = crate::binding_identity(
            &format!("{:04x}:{:04x}", identity.vid, identity.pid),
            identity.serial.as_deref(),
        );
        if identity.usb_devpath != reference.descriptor().physical_id().topology_path()
            || binding != side.identity
        {
            return Err(irlume_common::Error::Hardware(
                "opened descriptor differs from selected camera".into(),
            ));
        }
        let location = crate::usb_controller_location(&identity.usb_devpath).ok_or_else(|| {
            irlume_common::Error::Hardware("opened descriptor location is unavailable".into())
        })?;
        let domain = match location.domain {
            crate::RootHubDomain::Usb2 => "usb2",
            crate::RootHubDomain::SuperSpeed => "superspeed",
        };
        if location.controller != side.controller
            || domain != side.domain
            || location.ports != side.ports
        {
            return Err(irlume_common::Error::Hardware(
                "opened descriptor differs from selected camera".into(),
            ));
        }
        Ok(())
    }

    /// Cleanup-only admission for an already owned original fd. The caller must
    /// establish producer quiescence and ownership/readback before its restore.
    /// This never resets the invalid whole-pair capability or authorizes capture.
    pub(crate) fn require_restore_fd(
        &self,
        endpoint: &str,
        fd: std::os::fd::RawFd,
    ) -> irlume_common::Result<()> {
        if !self.is_split_pair() {
            return self
                .require_endpoint(endpoint)
                .map_err(|error| irlume_common::Error::Hardware(error.to_string()));
        }
        let reference = self
            .inner
            .references
            .iter()
            .find(|reference| {
                reference
                    .endpoint_paths()
                    .iter()
                    .any(|path| path == endpoint)
            })
            .ok_or_else(|| {
                irlume_common::Error::Hardware("restore descriptor is not covered".into())
            })?;
        let live = || {
            self.inner
                .inventory
                .lock()
                .map_err(|_| {
                    irlume_common::Error::Hardware("restore inventory is unavailable".into())
                })?
                .validate_reference(reference)
                .map_err(|_| {
                    irlume_common::Error::Hardware("restore camera incarnation changed".into())
                })
        };
        live()?;
        let identity = crate::uvc_descriptor::identity_from_fd(fd).map_err(|_| {
            irlume_common::Error::Hardware("restore descriptor identity is unavailable".into())
        })?;
        self.require_split_fd_identity(endpoint, &identity)?;
        live()
    }

    /// Whether this permit reserves two matched incarnations. Capture
    /// code must carry this fact into evidence, never infer it from skew.
    pub fn is_split_pair(&self) -> bool {
        self.inner.split.is_some()
    }

    pub(crate) fn start_stream(&self) -> Result<(), CameraLeaseError> {
        self.validate()?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| CameraLeaseError::Poisoned)?;
        let from = *state;
        if self.inner.split.is_some() && self.inner.streams.load(Ordering::SeqCst) != 0 {
            return Err(CameraLeaseError::SplitRequiresSequential);
        }
        if !matches!(
            from,
            CameraSessionState::Acquired
                | CameraSessionState::Configured
                | CameraSessionState::Streaming
                | CameraSessionState::Stopping
        ) {
            return Err(CameraLeaseError::InvalidTransition {
                from,
                to: CameraSessionState::Streaming,
            });
        }
        if matches!(
            from,
            CameraSessionState::Acquired | CameraSessionState::Stopping
        ) {
            *state = CameraSessionState::Configured;
        }
        self.inner.streams.fetch_add(1, Ordering::SeqCst);
        *state = CameraSessionState::Streaming;
        Ok(())
    }

    pub(crate) fn stop_stream(&self) {
        let previous = self.inner.streams.fetch_sub(1, Ordering::SeqCst);
        if previous == 0 {
            self.inner.streams.store(0, Ordering::SeqCst);
            self.set_state(CameraSessionState::Fault);
        } else if previous == 1 && self.state() == CameraSessionState::Streaming {
            self.set_state(CameraSessionState::Stopping);
        }
    }

    fn set_state(&self, state: CameraSessionState) {
        if let Ok(mut current) = self.inner.state.lock() {
            *current = state;
        }
    }
}

fn validate_references(
    inventory: &Arc<Mutex<CameraInventory>>,
    references: &[CameraInventoryRef],
) -> Result<(), CameraLeaseError> {
    if references.is_empty() {
        return Err(CameraLeaseError::EmptyKey);
    }
    let inventory = inventory.lock().map_err(|_| CameraLeaseError::Poisoned)?;
    for reference in references {
        inventory
            .validate_reference(reference)
            .map_err(|_| CameraLeaseError::Stale)?;
    }
    Ok(())
}

fn validate_split_publication(
    inventory: &CameraInventory,
    expected: &SplitLeaseRequest,
    require_revision: bool,
) -> Result<(), CameraLeaseError> {
    let snapshot = inventory.snapshot();
    if snapshot.supervisor_id.as_deref() != Some(expected.supervisor_id.as_str())
        || (require_revision && snapshot.revision != expected.revision)
    {
        return Err(CameraLeaseError::Stale);
    }
    crate::connected::revalidate_against(
        &expected.rgb,
        &expected.ir,
        &(snapshot, inventory.classified_endpoints()),
    )
    .map_err(|_| CameraLeaseError::Stale)
}

pub struct CameraOperationSession {
    lease: CameraLease,
    release_on_drop: bool,
}

impl CameraOperationSession {
    pub(crate) fn new(lease: CameraLease) -> Self {
        Self {
            lease,
            release_on_drop: true,
        }
    }

    pub(crate) fn into_lease(mut self) -> CameraLease {
        self.release_on_drop = false;
        self.lease.clone()
    }

    pub fn lease(&self) -> &CameraLease {
        &self.lease
    }

    /// Run work under this operation's explicit re-entrant capability.
    ///
    /// The scope is thread-local and panic-safe. A worker thread must call
    /// `run` itself; capabilities are never inherited or inferred globally.
    ///
    /// # Errors
    ///
    /// Returns [`CameraLeaseError::Stale`] if lifecycle continuity is lost before
    /// or during the scope, or [`CameraLeaseError::Poisoned`] if inventory state
    /// becomes unsafe.
    pub fn run<R>(&self, operation: impl FnOnce() -> R) -> Result<R, CameraLeaseError> {
        self.lease.validate()?;
        ACTIVE_OPERATIONS.with(|operations| operations.borrow_mut().push(self.lease.clone()));
        let guard = ActiveOperationGuard;
        let result = operation();
        drop(guard);
        self.lease.validate()?;
        Ok(result)
    }

    /// Open one RGB endpoint covered by this operation lease.
    ///
    /// # Errors
    ///
    /// Returns a hardware error for stale or uncovered endpoints and backend
    /// failures.
    pub fn open_rgb(&self, endpoint: &str) -> irlume_common::Result<crate::RgbCamera> {
        self.lease
            .require_endpoint(endpoint)
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
        self.run(|| crate::backend::open_rgb(endpoint, self.lease.clone()))
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?
    }

    /// Open one IR endpoint covered by this operation lease.
    ///
    /// # Errors
    ///
    /// Returns a hardware error for stale or uncovered endpoints and backend
    /// failures.
    pub fn open_ir(&self, endpoint: &str) -> irlume_common::Result<crate::IrCamera> {
        self.lease
            .require_endpoint(endpoint)
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
        self.run(|| crate::backend::open_ir(endpoint, self.lease.clone()))
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?
    }

    pub fn state(&self) -> CameraSessionState {
        self.lease.state()
    }

    /// Mark successful stream configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CameraLeaseError::InvalidTransition`] or a validation error.
    pub fn configure(&mut self) -> Result<(), CameraLeaseError> {
        self.transition(CameraSessionState::Configured)
    }

    /// Mark the configured operation as streaming.
    ///
    /// # Errors
    ///
    /// Returns [`CameraLeaseError::InvalidTransition`] or a validation error.
    pub fn start(&mut self) -> Result<(), CameraLeaseError> {
        self.transition(CameraSessionState::Streaming)
    }

    /// Enter the stopping phase before backend cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`CameraLeaseError::InvalidTransition`] or a validation error.
    pub fn begin_stop(&mut self) -> Result<(), CameraLeaseError> {
        self.transition(CameraSessionState::Stopping)
    }

    /// Mark a non-faulted session released.
    ///
    /// # Errors
    ///
    /// Returns [`CameraLeaseError::InvalidTransition`] or a validation error.
    pub fn release(&mut self) -> Result<(), CameraLeaseError> {
        self.transition(CameraSessionState::Released)
    }

    pub fn fault(&mut self) {
        self.lease.set_state(CameraSessionState::Fault);
    }

    fn transition(&mut self, to: CameraSessionState) -> Result<(), CameraLeaseError> {
        self.lease.validate()?;
        let mut state = self
            .lease
            .inner
            .state
            .lock()
            .map_err(|_| CameraLeaseError::Poisoned)?;
        let from = *state;
        let valid = matches!(
            (from, to),
            (CameraSessionState::Acquired, CameraSessionState::Configured)
                | (
                    CameraSessionState::Configured,
                    CameraSessionState::Streaming
                )
                | (CameraSessionState::Streaming, CameraSessionState::Stopping)
                | (CameraSessionState::Stopping, CameraSessionState::Released)
                | (CameraSessionState::Acquired, CameraSessionState::Released)
                | (CameraSessionState::Configured, CameraSessionState::Released)
        );
        if !valid {
            return Err(CameraLeaseError::InvalidTransition { from, to });
        }
        *state = to;
        Ok(())
    }
}

impl Drop for CameraOperationSession {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        if !matches!(
            self.lease.state(),
            CameraSessionState::Fault
                | CameraSessionState::ContinuityLost
                | CameraSessionState::Released
        ) {
            self.lease.set_state(CameraSessionState::Released);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{panic::AssertUnwindSafe, time::Duration};

    use super::*;
    use crate::{
        contracts::{BackendKind, CameraCapabilities, PhysicalCameraId},
        inventory::CameraObservation,
    };

    fn instance(byte: char) -> CameraInstanceId {
        CameraInstanceId::new(byte.to_string().repeat(32)).unwrap()
    }

    fn authority_permit(
        authority: &Arc<LeaseAuthority>,
        keys: &[CameraInstanceId],
    ) -> AuthorityPermit {
        authority
            .acquire(
                keys.to_vec(),
                CameraOperationKind::Capture,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap()
    }

    fn lease_fixture() -> (
        Arc<LeaseAuthority>,
        Arc<Mutex<CameraInventory>>,
        CameraLease,
    ) {
        let authority = Arc::new(LeaseAuthority::default());
        let inventory = Arc::new(Mutex::new(CameraInventory::with_instance_ids_for_test(
            vec![instance('1')],
        )));
        let observation = CameraObservation::with_lifecycle_evidence_and_endpoints(
            BackendKind::UvcV4l2,
            PhysicalCameraId::new("/devices/pci/camera", None).unwrap(),
            CameraCapabilities::default(),
            vec!["evidence".into()],
            vec!["/dev/video0".into(), "/dev/video2".into()],
        );
        inventory
            .lock()
            .unwrap()
            .reconcile(vec![observation])
            .unwrap();
        let reference = inventory
            .lock()
            .unwrap()
            .reference_for_endpoints(&["/dev/video0", "/dev/video2"])
            .unwrap();
        let lease = CameraLease::acquire(
            &authority,
            inventory.clone(),
            vec![reference],
            CameraOperationKind::Authentication,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        (authority, inventory, lease)
    }

    struct SplitFixture {
        authority: Arc<LeaseAuthority>,
        inventory: Arc<Mutex<CameraInventory>>,
        observations: Vec<CameraObservation>,
        expected: SplitLeaseRequest,
    }

    fn split_request(inventory: &mut CameraInventory) -> SplitLeaseRequest {
        let before = inventory.endpoint_generations();
        inventory.record_roles(
            &before,
            [
                ("/dev/video0", crate::Role::Rgb),
                ("/dev/video1", crate::Role::Ir),
            ],
        );
        let snapshot = inventory.snapshot();
        let sides = inventory.classified_endpoints();
        let expectation = |role| {
            let side = sides.iter().find(|side| side.role == role).unwrap();
            crate::SplitSideExpectation {
                instance_id: side.instance_id.clone(),
                generation: side.generation,
                endpoint: side.endpoint.clone(),
                identity: side.identity.clone(),
                controller: side.controller.clone(),
                domain: side.domain.clone(),
                ports: side.ports.clone(),
            }
        };
        SplitLeaseRequest {
            supervisor_id: snapshot.supervisor_id.unwrap(),
            revision: snapshot.revision,
            rgb: expectation(crate::Role::Rgb),
            ir: expectation(crate::Role::Ir),
        }
    }

    fn split_fixture() -> SplitFixture {
        let observations = [
            ("/devices/split-rgb", "/dev/video0", "1234:0001", 8),
            ("/devices/split-ir", "/dev/video1", "1234:0002", 5),
        ]
        .map(|(topology, path, identity, port)| {
            CameraObservation::with_lifecycle_evidence_and_endpoints(
                BackendKind::UvcV4l2,
                PhysicalCameraId::new(topology, None).unwrap(),
                CameraCapabilities::default(),
                vec!["split-wait-fixture".into()],
                vec![path.into()],
            )
            .with_usb_device(Some(
                crate::inventory::UsbDeviceFacts::new(identity.into(), true).with_location(Some(
                    crate::UsbLocation {
                        controller: "0000:00:14.0".into(),
                        domain: crate::RootHubDomain::Usb2,
                        ports: vec![port],
                    },
                )),
            ))
        })
        .to_vec();
        let mut inventory =
            CameraInventory::with_instance_ids_for_test(vec![instance('1'), instance('2')]);
        inventory.reconcile(observations.clone()).unwrap();
        let expected = split_request(&mut inventory);
        SplitFixture {
            authority: Arc::default(),
            inventory: Arc::new(Mutex::new(inventory)),
            observations,
            expected,
        }
    }

    fn hold_split_side(fixture: &SplitFixture, endpoint: &str) -> CameraLease {
        let reference = fixture
            .inventory
            .lock()
            .unwrap()
            .reference_for_endpoints(&[endpoint])
            .unwrap();
        CameraLease::acquire(
            &fixture.authority,
            fixture.inventory.clone(),
            vec![reference],
            CameraOperationKind::Setup,
            Instant::now(),
        )
        .unwrap()
    }

    fn acquire_fixture_split(
        fixture: &SplitFixture,
        expected: &SplitLeaseRequest,
    ) -> Result<CameraLease, CameraLeaseError> {
        CameraLease::acquire_split(
            &fixture.authority,
            fixture.inventory.clone(),
            expected,
            CameraOperationKind::Diagnostics,
            Instant::now() + Duration::from_secs(5),
        )
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn split_receipt_rejects_a_different_capability_for_the_same_incarnations() {
        use crate::test_support::{bound_uniform_frame, uniform_ir_stats};
        let fixture = split_fixture();
        let original = CameraOperationSession::new(
            acquire_fixture_split(&fixture, &fixture.expected).unwrap(),
        );
        let rgb = &fixture.expected.rgb.endpoint;
        let ir = &fixture.expected.ir.endpoint;
        let capture = crate::split_capture::capture_split_pair_with(
            rgb,
            ir,
            &original,
            &crate::CaptureControl::with_progress(crate::no_progress()),
            || {
                Ok(bound_uniform_frame(
                    original
                        .lease()
                        .frame_binding(rgb, StreamRole::Rgb)
                        .unwrap(),
                    Instant::now(),
                ))
            },
            || {
                Ok((
                    bound_uniform_frame(
                        original.lease().frame_binding(ir, StreamRole::Ir).unwrap(),
                        Instant::now(),
                    ),
                    uniform_ir_stats(),
                ))
            },
        )
        .unwrap();
        // Deliberately distinct test authority with identical frozen inventory:
        // incarnation equality must not stand in for capability identity.
        let other = CameraOperationSession::new(
            CameraLease::acquire_split(
                &Arc::default(),
                fixture.inventory.clone(),
                &fixture.expected,
                CameraOperationKind::Diagnostics,
                Instant::now(),
            )
            .unwrap(),
        );
        assert_eq!(
            original
                .lease()
                .frame_binding(rgb, StreamRole::Rgb)
                .unwrap(),
            other.lease().frame_binding(rgb, StreamRole::Rgb).unwrap()
        );
        assert!(capture.revalidate(&original).is_ok());
        assert!(
            capture.revalidate(&other).is_err(),
            "another capability with equal incarnations must refuse the receipt"
        );
    }

    fn observe_split_waiter(fixture: &SplitFixture, held: &CameraLease) {
        let mut keys = vec![
            CameraInstanceId::new(fixture.expected.rgb.instance_id.clone()).unwrap(),
            CameraInstanceId::new(fixture.expected.ir.instance_id.clone()).unwrap(),
        ];
        keys.sort();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let state = fixture.authority.state.lock().unwrap();
            if state.waiters.values().any(|waiting| waiting == &keys) {
                assert_eq!(state.waiters.len(), 1);
                assert_eq!(
                    state.active.len(),
                    1,
                    "a waiting split must not reserve its free side"
                );
                assert!(state
                    .active
                    .contains_key(held.inner.references[0].descriptor().camera_instance_id()));
                return;
            }
            drop(state);
            assert!(
                Instant::now() < deadline,
                "split acquisition never registered its waiter"
            );
            std::thread::yield_now();
        }
    }

    fn assert_split_keys_released(fixture: &SplitFixture) {
        {
            let state = fixture.authority.state.lock().unwrap();
            assert!(state.waiters.is_empty());
            assert!(
                state.active.is_empty(),
                "neither split side may retain a permit"
            );
        }
        // An immediate reservation of both original keys also catches a leaked
        // permit after a side's inventory generation changed.
        drop(authority_permit(
            &fixture.authority,
            &[
                CameraInstanceId::new(fixture.expected.rgb.instance_id.clone()).unwrap(),
                CameraInstanceId::new(fixture.expected.ir.instance_id.clone()).unwrap(),
            ],
        ));
    }

    #[test]
    fn split_wait_revalidates_either_changed_side_and_releases_the_whole_permit() {
        for held_endpoint in ["/dev/video0", "/dev/video1"] {
            for lost_topology in ["/devices/split-rgb", "/devices/split-ir"] {
                let fixture = split_fixture();
                let held = hold_split_side(&fixture, held_endpoint);
                std::thread::scope(|scope| {
                    let waiter = scope.spawn(|| acquire_fixture_split(&fixture, &fixture.expected));
                    observe_split_waiter(&fixture, &held);
                    let refreshed = {
                        let mut inventory = fixture.inventory.lock().unwrap();
                        inventory.invalidate_topologies(&[lost_topology.into()].into());
                        inventory.reconcile(fixture.observations.clone()).unwrap();
                        split_request(&mut inventory)
                    };
                    if lost_topology == "/devices/split-rgb" {
                        assert_ne!(refreshed.rgb.generation, fixture.expected.rgb.generation);
                        assert_eq!(refreshed.ir, fixture.expected.ir);
                    } else {
                        assert_ne!(refreshed.ir.generation, fixture.expected.ir.generation);
                        assert_eq!(refreshed.rgb, fixture.expected.rgb);
                    }
                    drop(held);
                    // A refused acquisition returns no session to open or retarget.
                    assert!(matches!(
                        waiter.join().unwrap(),
                        Err(CameraLeaseError::Stale)
                    ));
                    assert_split_keys_released(&fixture);
                    drop(acquire_fixture_split(&fixture, &refreshed).unwrap());
                    assert_split_keys_released(&fixture);
                });
            }
        }
    }

    #[test]
    fn split_wait_refuses_a_new_publication_even_when_both_sides_still_match() {
        let fixture = split_fixture();
        let held = hold_split_side(&fixture, "/dev/video1");
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| acquire_fixture_split(&fixture, &fixture.expected));
            observe_split_waiter(&fixture, &held);
            let refreshed = {
                let mut inventory = fixture.inventory.lock().unwrap();
                // A hotplug observation elsewhere advances the publication but
                // preserves these two incarnations and all their persistent facts.
                inventory.invalidate_topologies(&Default::default());
                inventory.reconcile(fixture.observations.clone()).unwrap();
                split_request(&mut inventory)
            };
            assert_ne!(refreshed.revision, fixture.expected.revision);
            assert_eq!(refreshed.rgb, fixture.expected.rgb);
            assert_eq!(refreshed.ir, fixture.expected.ir);
            assert_eq!(held.validate(), Ok(()));
            drop(held);
            assert!(matches!(
                waiter.join().unwrap(),
                Err(CameraLeaseError::Stale)
            ));
            assert_split_keys_released(&fixture);
            drop(acquire_fixture_split(&fixture, &refreshed).unwrap());
            assert_split_keys_released(&fixture);
        });
    }

    #[test]
    fn split_wait_valid_wakeup_reserves_exactly_both_sides_until_session_drop() {
        for endpoint in ["/dev/video0", "/dev/video1"] {
            let fixture = split_fixture();
            let held = hold_split_side(&fixture, endpoint);
            std::thread::scope(|scope| {
                let waiter = scope.spawn(|| acquire_fixture_split(&fixture, &fixture.expected));
                observe_split_waiter(&fixture, &held);
                drop(held);
                let session = CameraOperationSession::new(waiter.join().unwrap().unwrap());
                assert!(session.lease().is_split_pair());
                for (endpoint, role, expected) in [
                    ("/dev/video0", StreamRole::Rgb, &fixture.expected.rgb),
                    ("/dev/video1", StreamRole::Ir, &fixture.expected.ir),
                ] {
                    let binding = session.lease().frame_binding(endpoint, role).unwrap();
                    assert_eq!(binding.camera_instance_id().as_str(), expected.instance_id);
                    assert_eq!(binding.generation().get(), expected.generation);
                }
                {
                    let state = fixture.authority.state.lock().unwrap();
                    assert!(state.waiters.is_empty());
                    assert_eq!(state.active.len(), 2);
                    let mut tokens = state.active.values().map(|active| active.token);
                    assert_eq!(
                        tokens.next(),
                        tokens.next(),
                        "one atomic permit owns both sides"
                    );
                }
                // Model cancellation at the operation ownership boundary, without
                // claiming that synthetic reservations exercised physical streams.
                drop(session);
                assert_split_keys_released(&fixture);
            });
        }
    }

    #[test]
    fn split_side_loss_refuses_both_opens_before_backend_routing_and_drop_frees_both() {
        for topology in ["/devices/split-rgb", "/devices/split-ir"] {
            let fixture = split_fixture();
            let session = CameraOperationSession::new(
                acquire_fixture_split(&fixture, &fixture.expected).unwrap(),
            );
            fixture
                .inventory
                .lock()
                .unwrap()
                .invalidate_topologies(&[topology.into()].into());
            assert_eq!(session.lease().validate(), Err(CameraLeaseError::Stale));
            for error in [
                session.open_rgb("/dev/video0").err().unwrap(),
                session.open_ir("/dev/video1").err().unwrap(),
            ] {
                assert!(
                    matches!(error, irlume_common::Error::Hardware(ref message) if message == "camera lifecycle reference is stale")
                );
            }
            assert_eq!(session.state(), CameraSessionState::ContinuityLost);
            drop(session);
            assert_split_keys_released(&fixture);
        }
    }

    #[test]
    fn frame_binding_owns_exact_identity_and_rejects_uncovered_or_stale_endpoints() {
        let (_authority, inventory, lease) = lease_fixture();

        let binding = lease
            .frame_binding("/dev/video2", crate::contracts::StreamRole::Ir)
            .expect("covered current endpoint binds to its immutable descriptor");
        assert_eq!(binding.camera_instance_id(), &instance('1'));
        assert_eq!(
            binding.generation(),
            crate::contracts::CameraGeneration::INITIAL
        );
        assert_eq!(binding.stream_role(), crate::contracts::StreamRole::Ir);
        assert_eq!(
            lease.frame_binding("/dev/video9", crate::contracts::StreamRole::Rgb),
            Err(CameraLeaseError::EndpointNotCovered)
        );

        inventory.lock().unwrap().invalidate_all();
        assert_eq!(
            lease.frame_binding("/dev/video2", crate::contracts::StreamRole::Ir),
            Err(CameraLeaseError::Stale)
        );
    }

    #[test]
    fn frame_binding_refuses_ambiguous_duplicate_endpoint_coverage() {
        let (_authority, inventory, lease) = lease_fixture();
        let reference = lease.inner.references[0].clone();
        drop(lease);
        let authority = Arc::new(LeaseAuthority::default());
        let duplicate = CameraLease::acquire(
            &authority,
            inventory,
            vec![reference.clone(), reference],
            CameraOperationKind::Authentication,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(
            duplicate.frame_binding("/dev/video0", crate::contracts::StreamRole::Rgb),
            Err(CameraLeaseError::AmbiguousEndpointBinding)
        );
    }

    #[test]
    fn pair_acquisition_is_atomic_and_times_out_without_partial_ownership() {
        let authority = Arc::new(LeaseAuthority::default());
        let a = instance('1');
        let b = instance('2');
        let held = authority_permit(&authority, std::slice::from_ref(&b));

        assert!(matches!(
            authority.acquire(
                vec![a.clone(), b.clone()],
                CameraOperationKind::Enrollment,
                Instant::now() + Duration::from_millis(10),
            ),
            Err(CameraLeaseError::DeadlineExpired {
                current_owner: Some(CameraOperationKind::Capture),
            })
        ));
        let independent = authority_permit(&authority, &[a]);
        drop(independent);
        drop(held);
    }

    #[test]
    fn overlapping_waiters_acquire_fifo() {
        use std::sync::mpsc;

        let authority = Arc::new(LeaseAuthority::default());
        let key = instance('1');
        let held = authority_permit(&authority, std::slice::from_ref(&key));
        let (order_tx, order_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let first_authority = authority.clone();
        let first_key = key.clone();
        let first_tx = order_tx.clone();
        let first = std::thread::spawn(move || {
            let permit = first_authority
                .acquire(
                    vec![first_key],
                    CameraOperationKind::Enrollment,
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
            first_tx.send(1).unwrap();
            release_rx.recv().unwrap();
            drop(permit);
        });
        while authority.state.lock().unwrap().waiters.is_empty() {
            std::thread::yield_now();
        }

        let second_authority = authority.clone();
        let second_key = key.clone();
        let second = std::thread::spawn(move || {
            let permit = second_authority
                .acquire(
                    vec![second_key],
                    CameraOperationKind::Authentication,
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
            order_tx.send(2).unwrap();
            drop(permit);
        });
        while authority.state.lock().unwrap().waiters.len() < 2 {
            std::thread::yield_now();
        }

        drop(held);
        assert_eq!(order_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        release_tx.send(()).unwrap();
        assert_eq!(order_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn clone_and_panic_keep_lease_until_last_owner_drops() {
        let authority = Arc::new(LeaseAuthority::default());
        let key = instance('1');
        let permit = Arc::new(authority_permit(&authority, std::slice::from_ref(&key)));
        let clone = permit.clone();
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            drop(clone);
            panic!("operation panic fixture");
        }));
        assert!(matches!(
            authority.acquire(
                vec![key.clone()],
                CameraOperationKind::Enrollment,
                Instant::now() + Duration::from_millis(5),
            ),
            Err(CameraLeaseError::DeadlineExpired {
                current_owner: Some(CameraOperationKind::Capture),
            })
        ));
        drop(permit);
        drop(authority_permit(&authority, &[key]));
    }

    #[test]
    fn stale_lifecycle_reference_invalidates_held_lease() {
        let (_authority, inventory, lease) = lease_fixture();
        assert!(lease.covers_endpoint("/dev/video0"));
        inventory.lock().unwrap().invalidate_all();
        assert_eq!(lease.validate(), Err(CameraLeaseError::Stale));
    }

    #[test]
    #[ignore = "requires the Shinetech four-node UVC camera"]
    fn production_standalone_rgb_transfers_lease_ownership() {
        crate::hostfs::test::host();
        let camera = crate::RgbCamera::open("/dev/video0").expect("standalone RGB open");
        let _session = camera.session().expect("stream under transferred lease");
    }

    #[test]
    #[ignore = "requires the Shinetech four-node UVC camera"]
    fn production_pair_lease_is_atomic_for_real_rgb_and_ir_endpoints() {
        crate::hostfs::test::host();
        let first = acquire_camera_operation(
            &["/dev/video0", "/dev/video2"],
            CameraOperationKind::Diagnostics,
            Duration::from_millis(100),
        )
        .expect("real pair resolves to one current physical camera");
        assert!(first.lease().covers_endpoint("/dev/video0"));
        assert!(first.lease().covers_endpoint("/dev/video2"));
        let rgb = first
            .open_rgb("/dev/video0")
            .expect("open RGB under pair lease");
        let ir = first
            .open_ir("/dev/video2")
            .expect("open IR under pair lease");
        assert!(matches!(
            acquire_camera_operation(
                &["/dev/video2", "/dev/video0"],
                CameraOperationKind::Authentication,
                Duration::from_millis(5),
            ),
            Err(CameraLeaseError::DeadlineExpired {
                current_owner: Some(CameraOperationKind::Diagnostics),
            })
        ));
        drop(rgb);
        drop(ir);
        drop(first);
        acquire_camera_operation(
            &["/dev/video0", "/dev/video2"],
            CameraOperationKind::Authentication,
            Duration::from_millis(100),
        )
        .expect("drop releases the physical-camera key");
    }

    #[test]
    fn session_ownership_transfer_keeps_standalone_permit_live() {
        let (authority, _inventory, lease) = lease_fixture();
        let standalone = CameraOperationSession::new(lease).into_lease();
        assert_eq!(standalone.state(), CameraSessionState::Acquired);
        assert_eq!(standalone.validate(), Ok(()));
        drop(standalone);
        drop(authority_permit(&authority, &[instance('1')]));
    }

    #[test]
    fn active_operation_scope_is_explicit_and_panic_safe() {
        let (_authority, _inventory, lease) = lease_fixture();
        let session = CameraOperationSession::new(lease);

        assert!(active_permit("/dev/video0").unwrap().is_none());
        session
            .run(|| {
                assert!(active_permit("/dev/video0").unwrap().is_some());
                assert!(matches!(
                    active_permit("/dev/video9"),
                    Err(CameraLeaseError::EndpointNotCovered)
                ));
            })
            .unwrap();
        assert!(active_permit("/dev/video0").unwrap().is_none());

        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = session.run(|| panic!("scope panic"));
        }));
        assert!(active_permit("/dev/video0").unwrap().is_none());
    }

    #[test]
    fn raw_set_cur_enters_the_acquired_operations_active_scope() {
        let (_authority, _inventory, lease) = lease_fixture();
        let session = CameraOperationSession::new(lease);
        let _camera =
            crate::ir_emitter::fake_camera::install(crate::ir_emitter::fake_camera::Camera {
                at_first_write: Some(Box::new(|| match active_permit("/dev/video0") {
                    Ok(Some(_)) => Ok(()),
                    Ok(None) => Err("SET_CUR had no current operation".into()),
                    Err(error) => Err(format!("SET_CUR operation was invalid: {error}")),
                })),
                ..Default::default()
            });

        assert_eq!(
            crate::ir_emitter::raw::set_cur(&session, -1_i32, 1, 1, &[7]),
            Ok(())
        );
        assert_eq!(
            crate::ir_emitter::fake_camera::log(),
            vec![crate::ir_emitter::fake_camera::Request::Set(vec![7])]
        );
    }

    #[test]
    fn raw_set_cur_keeps_a_stale_operation_fail_closed_as_estale() {
        use std::os::fd::AsRawFd;

        let (_authority, inventory, lease) = lease_fixture();
        let session = CameraOperationSession::new(lease);
        inventory.lock().unwrap().invalidate_all();
        let file = std::fs::File::open("/dev/null").unwrap();

        let error = crate::ir_emitter::raw::set_cur(&session, file.as_raw_fd(), 1, 1, &[7])
            .expect_err("a stale operation must not reach SET_CUR");
        assert!(error.starts_with("camera did not answer ("));
        assert!(error.ends_with(&format!("(os error {}))", libc::ESTALE)));
    }

    #[test]
    #[ignore = "requires an operator-controlled UVC interface unbind"]
    fn production_active_pair_lease_becomes_stale_on_uvc_loss() {
        use std::io::Write;

        crate::hostfs::test::host();
        let operation = acquire_camera_operation(
            &["/dev/video0", "/dev/video2"],
            CameraOperationKind::Authentication,
            Duration::from_secs(2),
        )
        .expect("acquire real pair");
        println!("IRLUME_LEASE_READY");
        std::io::stdout().flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match operation.lease().validate() {
                Err(CameraLeaseError::Stale) => break,
                Ok(()) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                other => panic!("lease did not become stale after UVC loss: {other:?}"),
            }
        }
        println!("IRLUME_LEASE_STALE");
    }

    #[test]
    fn stream_lifecycle_is_shared_and_reference_counted() {
        let (_authority, _inventory, lease) = lease_fixture();
        let session = CameraOperationSession::new(lease);
        let lease = session.lease().clone();
        let observed = lease.clone();
        assert_eq!(lease.state(), CameraSessionState::Acquired);
        lease.start_stream().unwrap();
        lease.start_stream().unwrap();
        assert_eq!(lease.state(), CameraSessionState::Streaming);
        lease.stop_stream();
        assert_eq!(lease.state(), CameraSessionState::Streaming);
        lease.stop_stream();
        assert_eq!(lease.state(), CameraSessionState::Stopping);
        lease.start_stream().unwrap();
        assert_eq!(lease.state(), CameraSessionState::Streaming);
        lease.stop_stream();
        assert_eq!(lease.state(), CameraSessionState::Stopping);
        drop(session);
        assert_eq!(observed.state(), CameraSessionState::Released);
    }

    #[test]
    fn operation_session_enforces_lifecycle_order() {
        let (_authority, _inventory, lease) = lease_fixture();
        let mut session = CameraOperationSession::new(lease);
        assert_eq!(session.state(), CameraSessionState::Acquired);
        assert!(matches!(
            session.start(),
            Err(CameraLeaseError::InvalidTransition { .. })
        ));
        session.configure().unwrap();
        session.start().unwrap();
        session.begin_stop().unwrap();
        session.release().unwrap();
        assert_eq!(session.state(), CameraSessionState::Released);
    }
}

#[cfg(test)]
#[path = "split_trust_tests.rs"]
mod split_trust_tests;
