//! Supervisor-owned normalized camera inventory.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the event adapter and frame/session consumers land next"
    )
)]

use std::collections::{BTreeMap, BTreeSet};

use crate::contracts::{
    BackendKind, CameraCapabilities, CameraDescriptor, CameraGeneration, CameraInstanceId,
    PhysicalCameraId,
};

const MAX_INSTANCE_ID_ATTEMPTS: usize = 64;
type InstanceIdSource = Box<dyn FnMut() -> CameraInstanceId + Send>;

/// One backend observation before the supervisor assigns lifecycle identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CameraObservation {
    backend: BackendKind,
    physical_id: PhysicalCameraId,
    capabilities: CameraCapabilities,
}

impl CameraObservation {
    pub(crate) fn new(
        backend: BackendKind,
        physical_id: PhysicalCameraId,
        capabilities: CameraCapabilities,
    ) -> Self {
        Self {
            backend,
            physical_id,
            capabilities,
        }
    }

    pub(crate) fn physical_id(&self) -> &PhysicalCameraId {
        &self.physical_id
    }

    fn descriptor(
        &self,
        instance_id: &CameraInstanceId,
        generation: CameraGeneration,
    ) -> CameraDescriptor {
        CameraDescriptor::new(
            self.backend,
            self.physical_id.clone(),
            instance_id.clone(),
            generation,
            self.capabilities.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InventoryEntry {
    observation: CameraObservation,
    descriptor: CameraDescriptor,
}

/// One deterministic inventory transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CameraInventoryEvent {
    Added(CameraDescriptor),
    Changed {
        previous: CameraDescriptor,
        current: CameraDescriptor,
    },
    Removed(CameraDescriptor),
}

impl CameraInventoryEvent {
    pub(crate) fn descriptor(&self) -> &CameraDescriptor {
        match self {
            Self::Added(descriptor) | Self::Removed(descriptor) => descriptor,
            Self::Changed { current, .. } => current,
        }
    }

    pub(crate) fn topology_path(&self) -> &str {
        self.descriptor().physical_id().topology_path()
    }

    pub(crate) const fn is_added(&self) -> bool {
        matches!(self, Self::Added(_))
    }

    pub(crate) const fn is_changed(&self) -> bool {
        matches!(self, Self::Changed { .. })
    }

    pub(crate) const fn is_removed(&self) -> bool {
        matches!(self, Self::Removed(_))
    }

    const fn phase_rank(&self) -> u8 {
        match self {
            Self::Removed(_) => 0,
            Self::Changed { .. } => 1,
            Self::Added(_) => 2,
        }
    }
}

/// Fail-closed inventory reconciliation or descriptor validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CameraInventoryError {
    DuplicateObservation(String),
    ForeignInstance,
    UnknownCamera,
    Removed,
    StaleGeneration,
    DescriptorMismatch,
    InstanceIdExhausted,
    Poisoned,
}

/// Process-scoped physical-camera lifecycle state.
///
/// Reconciliation is transactional: malformed snapshots and instance-ID
/// exhaustion leave active entries, tombstones, and retired IDs unchanged.
pub(crate) struct CameraInventory {
    active: BTreeMap<String, InventoryEntry>,
    tombstones: BTreeSet<String>,
    retired_instance_ids: BTreeSet<CameraInstanceId>,
    instance_id_source: InstanceIdSource,
}

impl CameraInventory {
    pub(crate) fn new() -> Self {
        Self::with_instance_id_source(Box::new(CameraInstanceId::generate))
    }

    fn with_instance_id_source(instance_id_source: InstanceIdSource) -> Self {
        Self {
            active: BTreeMap::new(),
            tombstones: BTreeSet::new(),
            retired_instance_ids: BTreeSet::new(),
            instance_id_source,
        }
    }

    fn mint_unique_instance_id(
        &mut self,
        active: &BTreeMap<String, InventoryEntry>,
        retired_instance_ids: &BTreeSet<CameraInstanceId>,
    ) -> Result<CameraInstanceId, CameraInventoryError> {
        for _ in 0..MAX_INSTANCE_ID_ATTEMPTS {
            let candidate = (self.instance_id_source)();
            let active_collision = active
                .values()
                .any(|entry| entry.descriptor.camera_instance_id() == &candidate);
            if !active_collision && !retired_instance_ids.contains(&candidate) {
                return Ok(candidate);
            }
        }
        Err(CameraInventoryError::InstanceIdExhausted)
    }

    pub(crate) fn reconcile(
        &mut self,
        observations: Vec<CameraObservation>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
        let mut incoming = BTreeMap::new();
        for observation in observations {
            let key = observation.physical_id().topology_path().to_owned();
            if incoming.insert(key.clone(), observation).is_some() {
                return Err(CameraInventoryError::DuplicateObservation(key));
            }
        }

        let mut next_active = self.active.clone();
        let mut next_tombstones = self.tombstones.clone();
        let mut next_retired_instance_ids = self.retired_instance_ids.clone();
        let keys: BTreeSet<_> = next_active.keys().chain(incoming.keys()).cloned().collect();
        let mut events = Vec::new();

        for key in keys {
            match (next_active.get(&key).cloned(), incoming.remove(&key)) {
                (Some(previous), None) => {
                    next_active.remove(&key);
                    next_tombstones.insert(key);
                    next_retired_instance_ids
                        .insert(previous.descriptor.camera_instance_id().clone());
                    events.push(CameraInventoryEvent::Removed(previous.descriptor));
                }
                (None, Some(observation)) => {
                    next_tombstones.remove(&key);
                    let instance_id =
                        self.mint_unique_instance_id(&next_active, &next_retired_instance_ids)?;
                    let generation = CameraGeneration::INITIAL;
                    let descriptor = observation.descriptor(&instance_id, generation);
                    next_active.insert(
                        key,
                        InventoryEntry {
                            observation,
                            descriptor: descriptor.clone(),
                        },
                    );
                    events.push(CameraInventoryEvent::Added(descriptor));
                }
                (Some(previous), Some(observation)) if previous.observation == observation => {}
                (Some(previous), Some(observation)) => {
                    let (instance_id, generation) = match previous.descriptor.generation().next() {
                        Ok(generation) => {
                            (previous.descriptor.camera_instance_id().clone(), generation)
                        }
                        Err(_) => {
                            next_retired_instance_ids
                                .insert(previous.descriptor.camera_instance_id().clone());
                            (
                                self.mint_unique_instance_id(
                                    &next_active,
                                    &next_retired_instance_ids,
                                )?,
                                CameraGeneration::INITIAL,
                            )
                        }
                    };
                    let descriptor = observation.descriptor(&instance_id, generation);
                    next_active.insert(
                        key,
                        InventoryEntry {
                            observation,
                            descriptor: descriptor.clone(),
                        },
                    );
                    events.push(CameraInventoryEvent::Changed {
                        previous: previous.descriptor,
                        current: descriptor,
                    });
                }
                (None, None) => unreachable!("key came from the active or incoming inventory"),
            }
        }

        events.sort_by(|left, right| {
            left.phase_rank()
                .cmp(&right.phase_rank())
                .then_with(|| left.topology_path().cmp(right.topology_path()))
        });

        self.active = next_active;
        self.tombstones = next_tombstones;
        self.retired_instance_ids = next_retired_instance_ids;
        Ok(events)
    }

    pub(crate) fn active_descriptors(&self) -> Vec<CameraDescriptor> {
        self.active
            .values()
            .map(|entry| entry.descriptor.clone())
            .collect()
    }

    pub(crate) fn validate(
        &self,
        descriptor: &CameraDescriptor,
    ) -> Result<(), CameraInventoryError> {
        let key = descriptor.physical_id().topology_path();
        let Some(active) = self.active.get(key) else {
            return if self.tombstones.contains(key) {
                Err(CameraInventoryError::Removed)
            } else {
                Err(CameraInventoryError::UnknownCamera)
            };
        };
        if descriptor.camera_instance_id() != active.descriptor.camera_instance_id() {
            return Err(CameraInventoryError::ForeignInstance);
        }
        if descriptor.generation() != active.descriptor.generation() {
            return Err(CameraInventoryError::StaleGeneration);
        }
        if descriptor != &active.descriptor {
            return Err(CameraInventoryError::DescriptorMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    fn with_active_for_test(
        observation: CameraObservation,
        instance_id: CameraInstanceId,
        generation: CameraGeneration,
        replacement_id: CameraInstanceId,
    ) -> Self {
        let key = observation.physical_id().topology_path().to_owned();
        let descriptor = observation.descriptor(&instance_id, generation);
        Self {
            active: BTreeMap::from([(
                key,
                InventoryEntry {
                    observation,
                    descriptor,
                },
            )]),
            tombstones: BTreeSet::new(),
            retired_instance_ids: BTreeSet::new(),
            instance_id_source: Box::new(move || replacement_id.clone()),
        }
    }

    #[cfg(test)]
    fn with_instance_ids_for_test(ids: Vec<CameraInstanceId>) -> Self {
        let fallback = ids.last().cloned().expect("at least one fixture ID");
        let mut ids = ids.into_iter();
        Self::with_instance_id_source(Box::new(move || {
            ids.next().unwrap_or_else(|| fallback.clone())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        BackendKind, CameraCapabilities, CameraGeneration, CameraInstanceId, PhysicalCameraId,
        StreamRole,
    };

    fn instance(hex: char) -> CameraInstanceId {
        CameraInstanceId::new(hex.to_string().repeat(32)).expect("valid instance")
    }

    #[test]
    fn generated_instance_ids_are_valid_nonzero_and_fresh() {
        let first = CameraInstanceId::generate();
        let second = CameraInstanceId::generate();

        assert!(CameraInstanceId::new(first.as_str()).is_ok());
        assert!(CameraInstanceId::new(second.as_str()).is_ok());
        assert_ne!(first, second);
    }

    fn observation(path: &str, serial: Option<&str>, roles: &[StreamRole]) -> CameraObservation {
        CameraObservation::new(
            BackendKind::UvcV4l2,
            PhysicalCameraId::new(path, serial.map(str::to_owned)).expect("valid physical id"),
            CameraCapabilities::new(roles.to_vec(), Default::default(), Vec::new())
                .expect("valid capabilities"),
        )
    }

    fn generation(event: &CameraInventoryEvent) -> u64 {
        event.descriptor().generation().get()
    }

    #[test]
    fn add_refresh_and_snapshot_reorder_are_deterministic() {
        let mut inventory = CameraInventory::new();
        let a = observation("/devices/pci/a", Some("A"), &[StreamRole::Rgb]);
        let b = observation("/devices/pci/b", None, &[StreamRole::Ir]);

        let first = inventory.reconcile(vec![b.clone(), a.clone()]).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].topology_path(), "/devices/pci/a");
        assert_eq!(first[1].topology_path(), "/devices/pci/b");
        assert!(first.iter().all(|event| event.is_added()));
        assert!(first.iter().all(|event| generation(event) == 1));
        assert_ne!(
            first[0].descriptor().camera_instance_id(),
            first[1].descriptor().camera_instance_id()
        );

        assert!(inventory.reconcile(vec![a, b]).unwrap().is_empty());
        assert_eq!(inventory.active_descriptors().len(), 2);
    }

    #[test]
    fn remove_readd_retires_instance_and_restarts_generation() {
        let original_id = instance('1');
        let replacement_id = instance('2');
        let mut inventory = CameraInventory::with_instance_ids_for_test(vec![
            original_id.clone(),
            original_id.clone(),
            replacement_id.clone(),
        ]);
        let camera = observation("/devices/pci/camera", None, &[StreamRole::Rgb]);
        let added = inventory.reconcile(vec![camera.clone()]).unwrap();
        let stale = added[0].descriptor().clone();

        let removed = inventory.reconcile(Vec::new()).unwrap();
        assert!(removed[0].is_removed());
        assert_eq!(
            inventory.validate(&stale),
            Err(CameraInventoryError::Removed)
        );

        let readded = inventory.reconcile(vec![camera]).unwrap();
        assert!(readded[0].is_added());
        assert_eq!(generation(&readded[0]), 1);
        assert!(!inventory.tombstones.contains("/devices/pci/camera"));
        assert_ne!(
            readded[0].descriptor().camera_instance_id(),
            stale.camera_instance_id()
        );
        assert_eq!(
            readded[0].descriptor().camera_instance_id(),
            &replacement_id
        );
        assert!(inventory.retired_instance_ids.contains(&original_id));
        assert_eq!(
            inventory.validate(&stale),
            Err(CameraInventoryError::ForeignInstance)
        );
        assert!(inventory.validate(readded[0].descriptor()).is_ok());
    }

    #[test]
    fn security_relevant_observation_change_advances_generation() {
        let mut inventory = CameraInventory::new();
        let old = observation("/devices/pci/camera", None, &[StreamRole::Rgb]);
        let new = observation("/devices/pci/camera", Some("SERIAL"), &[StreamRole::Rgb]);
        let old_descriptor = inventory.reconcile(vec![old]).unwrap()[0]
            .descriptor()
            .clone();

        let changed = inventory.reconcile(vec![new]).unwrap();
        assert_eq!(changed.len(), 1);
        assert!(changed[0].is_changed());
        assert_eq!(generation(&changed[0]), 2);
        assert_eq!(
            changed[0].descriptor().camera_instance_id(),
            old_descriptor.camera_instance_id()
        );
        assert_eq!(
            inventory.validate(&old_descriptor),
            Err(CameraInventoryError::StaleGeneration)
        );
    }

    #[test]
    fn topology_move_retires_old_and_adds_new_identity() {
        let mut inventory = CameraInventory::new();
        let old = observation("/devices/pci/usb1/z-old", None, &[StreamRole::Rgb]);
        let new = observation("/devices/pci/usb1/a-new", None, &[StreamRole::Rgb]);
        let stale = inventory.reconcile(vec![old]).unwrap()[0]
            .descriptor()
            .clone();
        let events = inventory.reconcile(vec![new]).unwrap();

        assert_eq!(events.len(), 2);
        assert!(events[0].is_removed());
        assert!(events[1].is_added());
        assert_eq!(generation(&events[1]), 1);
        assert_ne!(
            events[1].descriptor().camera_instance_id(),
            stale.camera_instance_id()
        );
        assert_eq!(
            inventory.validate(&stale),
            Err(CameraInventoryError::Removed)
        );
    }

    #[test]
    fn duplicate_snapshot_fails_atomically_instead_of_overwriting() {
        let mut inventory = CameraInventory::new();
        let existing = observation("/devices/pci/existing", None, &[StreamRole::Rgb]);
        inventory.reconcile(vec![existing]).unwrap();
        let before = inventory.active_descriptors();
        let duplicate = observation("/devices/pci/duplicate", None, &[StreamRole::Ir]);

        assert!(matches!(
            inventory.reconcile(vec![duplicate.clone(), duplicate]),
            Err(CameraInventoryError::DuplicateObservation(_))
        ));
        assert_eq!(inventory.active_descriptors(), before);
    }

    #[test]
    fn identical_serialless_units_remain_distinct_and_ambiguous() {
        let mut inventory = CameraInventory::new();
        let a = observation(
            "/devices/pci/usb1/1-1",
            None,
            &[StreamRole::Rgb, StreamRole::Ir],
        );
        let b = observation(
            "/devices/pci/usb1/1-2",
            None,
            &[StreamRole::Rgb, StreamRole::Ir],
        );

        let events = inventory.reconcile(vec![b, a]).unwrap();
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].topology_path(), events[1].topology_path());
        assert_ne!(
            events[0].descriptor().camera_instance_id(),
            events[1].descriptor().camera_instance_id()
        );
        assert!(events.iter().all(|event| {
            event.descriptor().identity_strength() == crate::contracts::IdentityStrength::Ambiguous
        }));
    }

    #[test]
    fn validation_rejects_a_descriptor_from_another_supervisor_instance() {
        let camera = observation("/devices/pci/camera", None, &[StreamRole::Rgb]);
        let mut first = CameraInventory::new();
        let descriptor = first.reconcile(vec![camera.clone()]).unwrap()[0]
            .descriptor()
            .clone();
        let mut second = CameraInventory::new();
        second.reconcile(vec![camera]).unwrap();

        assert_eq!(
            second.validate(&descriptor),
            Err(CameraInventoryError::ForeignInstance)
        );
    }

    #[test]
    fn validation_rejects_forged_evidence_at_the_current_generation() {
        let camera = observation("/devices/pci/camera", None, &[StreamRole::Rgb]);
        let mut inventory = CameraInventory::new();
        let descriptor = inventory.reconcile(vec![camera]).unwrap()[0]
            .descriptor()
            .clone();
        let forged = CameraDescriptor::new(
            descriptor.backend(),
            descriptor.physical_id().clone(),
            descriptor.camera_instance_id().clone(),
            descriptor.generation(),
            CameraCapabilities::new(vec![StreamRole::Ir], Default::default(), Vec::new()).unwrap(),
        );

        assert_eq!(
            inventory.validate(&forged),
            Err(CameraInventoryError::DescriptorMismatch)
        );
    }

    #[test]
    fn instance_id_collisions_retry_across_active_cameras() {
        let first = instance('c');
        let second = instance('d');
        let mut inventory = CameraInventory::with_instance_ids_for_test(vec![
            first.clone(),
            first.clone(),
            second.clone(),
        ]);
        let a = observation("/devices/a", None, &[StreamRole::Rgb]);
        let b = observation("/devices/b", None, &[StreamRole::Ir]);

        let events = inventory.reconcile(vec![a, b]).unwrap();
        assert_eq!(events[0].descriptor().camera_instance_id(), &first);
        assert_eq!(events[1].descriptor().camera_instance_id(), &second);
    }

    #[test]
    fn instance_id_collisions_retry_across_retired_instances() {
        let removed_id = instance('e');
        let replacement_id = instance('f');
        let mut inventory = CameraInventory::with_instance_ids_for_test(vec![
            removed_id.clone(),
            removed_id,
            replacement_id.clone(),
        ]);
        inventory
            .reconcile(vec![observation("/devices/old", None, &[StreamRole::Rgb])])
            .unwrap();
        inventory.reconcile(Vec::new()).unwrap();

        let added = inventory
            .reconcile(vec![observation("/devices/new", None, &[StreamRole::Rgb])])
            .unwrap();
        assert_eq!(added[0].descriptor().camera_instance_id(), &replacement_id);
    }

    #[test]
    fn instance_id_exhaustion_fails_atomically() {
        let repeated = instance('c');
        let mut inventory = CameraInventory::with_instance_ids_for_test(vec![repeated]);
        let existing = observation("/devices/a", None, &[StreamRole::Rgb]);
        inventory.reconcile(vec![existing.clone()]).unwrap();
        let before = inventory.active_descriptors();
        let new = observation("/devices/b", None, &[StreamRole::Ir]);

        assert_eq!(
            inventory.reconcile(vec![existing, new]),
            Err(CameraInventoryError::InstanceIdExhausted)
        );
        assert_eq!(inventory.active_descriptors(), before);
    }

    #[test]
    fn generation_exhaustion_retires_instance_without_wrap() {
        let old = observation("/devices/pci/camera", None, &[StreamRole::Rgb]);
        let changed = observation("/devices/pci/camera", Some("SERIAL"), &[StreamRole::Rgb]);
        let original_id = instance('8');
        let replacement_id = instance('9');
        let mut inventory = CameraInventory::with_active_for_test(
            old,
            original_id.clone(),
            CameraGeneration::new(u64::MAX).unwrap(),
            replacement_id.clone(),
        );

        let events = inventory.reconcile(vec![changed]).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_changed());
        assert_eq!(events[0].descriptor().camera_instance_id(), &replacement_id);
        assert_eq!(generation(&events[0]), 1);
        assert!(inventory.retired_instance_ids.contains(&original_id));
    }
}
