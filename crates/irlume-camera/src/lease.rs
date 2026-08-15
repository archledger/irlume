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
    contracts::CameraInstanceId,
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
    Poisoned,
    InvalidTransition {
        from: CameraSessionState,
        to: CameraSessionState,
    },
    EmptyKey,
    EndpointNotCovered,
    InvalidEndpoint(String),
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
            Self::InvalidEndpoint(message) => formatter.write_str(message),
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
/// physical-camera observation, [`CameraLeaseError::DeadlineExpired`] on
/// contention, or [`CameraLeaseError::Poisoned`] if supervisor state is unsafe.
pub fn acquire_camera_operation(
    endpoint_paths: &[&str],
    operation: CameraOperationKind,
    timeout: Duration,
) -> Result<CameraOperationSession, CameraLeaseError> {
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
    if matches!(result, Err(CameraLeaseError::UnknownEndpoint)) {
        for endpoint in endpoint_paths {
            crate::verify_pinned(endpoint)
                .map_err(|error| CameraLeaseError::InvalidEndpoint(error.to_string()))?;
        }
    }
    result
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
    pub(crate) fn acquire(
        authority: &Arc<LeaseAuthority>,
        inventory: Arc<Mutex<CameraInventory>>,
        references: Vec<CameraInventoryRef>,
        operation: CameraOperationKind,
        deadline: Instant,
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
            }),
        };
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
        if let Err(error) = validate_references(&self.inner.inventory, &self.inner.references) {
            self.set_state(CameraSessionState::ContinuityLost);
            return Err(error);
        }
        Ok(())
    }

    pub fn covers_endpoint(&self, path: &str) -> bool {
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

    pub fn state(&self) -> CameraSessionState {
        self.inner
            .state
            .lock()
            .map(|state| *state)
            .unwrap_or(CameraSessionState::Fault)
    }

    pub(crate) fn start_stream(&self) -> Result<(), CameraLeaseError> {
        self.validate()?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| CameraLeaseError::Poisoned)?;
        let from = *state;
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
        let camera = crate::RgbCamera::open("/dev/video0").expect("standalone RGB open");
        let _session = camera.session().expect("stream under transferred lease");
    }

    #[test]
    #[ignore = "requires the Shinetech four-node UVC camera"]
    fn production_pair_lease_is_atomic_for_real_rgb_and_ir_endpoints() {
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
    #[ignore = "requires an operator-controlled UVC interface unbind"]
    fn production_active_pair_lease_becomes_stale_on_uvc_loss() {
        use std::io::Write;

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
