// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Fixed, context-bound camera conditioning policies.

use std::{
    collections::BTreeSet,
    io,
    time::{Duration, Instant},
};

use crate::{
    capability_inventory::{CapabilityInventory, MenuValue, StandardControlCapability},
    capture_qualification::ConnectionContext,
    contracts::{CameraGeneration, CameraInstanceId},
    profile::PairTransportProfile,
    V4L2_CID_BACKLIGHT_COMPENSATION,
};

const CATALOG_VERSION: u32 = 1;
const LOW_LIGHT_MEDIAN_MAX: u8 = 63;
const BACKLIT_P90_MIN: u8 = 224;
const BACKLIT_CLIPPED_MIN_BASIS_POINTS: u16 = 500;
const BACKLIT_CONTRAST_MIN: u8 = 96;

const V4L2_CTRL_TYPE_INTEGER: u32 = 1;
const V4L2_CTRL_TYPE_BOOLEAN: u32 = 2;
const V4L2_CTRL_TYPE_MENU: u32 = 3;
const V4L2_CTRL_TYPE_INTEGER_MENU: u32 = 9;

/// Maximum age of process-local scene statistics accepted by the fixed catalog.
pub const CATALOG_TTL: Duration = Duration::from_secs(30);

/// A deterministic scene class derived only from non-model capture statistics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SceneClass {
    /// Ordinary visible-light scene.
    Lit,
    /// Bright highlights and wide contrast indicate a backlit scene.
    Backlit,
    /// Visible-light median is below the fixed low-light boundary.
    LowLight,
    /// Active IR was observed while ambient illumination was dark.
    DarkIr,
}

/// Stable identifier for one member of the fixed conditioning catalog.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConditioningPolicyId {
    /// Safe automatic visible-light policy.
    LitAuto,
    /// Automatic exposure with backlight compensation.
    BacklitAuto,
    /// Automatic exposure for a low-light evidence window.
    LowLight,
    /// Existing active-IR capture and reduction behavior.
    DarkIr,
}

impl ConditioningPolicyId {
    /// Returns the fixed persisted spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LitAuto => "lit-auto",
            Self::BacklitAuto => "backlit-auto",
            Self::LowLight => "low-light",
            Self::DarkIr => "dark-ir",
        }
    }
}

/// The represented standard V4L2 value type requested by a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlSettingKind {
    /// Scalar integer control.
    Integer,
    /// Boolean control represented as exactly zero or one.
    Boolean,
    /// Menu index present in the advertised sparse menu.
    Menu,
}

/// One exact standard V4L2 control request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlSetting {
    id: u32,
    kind: ControlSettingKind,
    value: i64,
}

impl ControlSetting {
    /// Constructs an integer control request.
    #[must_use]
    pub const fn integer(id: u32, value: i64) -> Self {
        Self {
            id,
            kind: ControlSettingKind::Integer,
            value,
        }
    }

    /// Constructs a boolean control request.
    #[must_use]
    pub const fn boolean(id: u32, value: bool) -> Self {
        Self {
            id,
            kind: ControlSettingKind::Boolean,
            value: value as i64,
        }
    }

    /// Constructs a menu-index request.
    #[must_use]
    pub const fn menu(id: u32, index: u32) -> Self {
        Self {
            id,
            kind: ControlSettingKind::Menu,
            value: index as i64,
        }
    }

    /// Returns the standard V4L2 control identifier.
    #[must_use]
    pub const fn id(self) -> u32 {
        self.id
    }

    /// Returns the represented value type.
    #[must_use]
    pub const fn kind(self) -> ControlSettingKind {
        self.kind
    }

    /// Returns the exact requested value.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.value
    }
}

/// One fixed policy's reversible controls and evidence-reduction choices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditioningPolicy {
    id: ConditioningPolicyId,
    controls: Vec<ControlSetting>,
    auto_exposure_enabled: bool,
    rgb_warmup_frames: usize,
    rgb_median_frames: usize,
    ambient_subtraction_enabled: bool,
}

impl ConditioningPolicy {
    /// Constructs a bounded policy with no duplicate control ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate controls or an empty evidence window.
    pub fn new(
        id: ConditioningPolicyId,
        controls: Vec<ControlSetting>,
        auto_exposure_enabled: bool,
        rgb_warmup_frames: usize,
        rgb_median_frames: usize,
        ambient_subtraction_enabled: bool,
    ) -> Result<Self, PolicyError> {
        let mut ids = BTreeSet::new();
        if controls.iter().any(|setting| !ids.insert(setting.id)) {
            return Err(PolicyError::DuplicateControl);
        }
        if rgb_warmup_frames == 0 || rgb_median_frames == 0 {
            return Err(PolicyError::InvalidPolicy);
        }
        Ok(Self {
            id,
            controls,
            auto_exposure_enabled,
            rgb_warmup_frames,
            rgb_median_frames,
            ambient_subtraction_enabled,
        })
    }

    /// Returns the stable catalog identifier.
    #[must_use]
    pub const fn id(&self) -> ConditioningPolicyId {
        self.id
    }

    /// Returns exact standard-control requests.
    #[must_use]
    pub fn controls(&self) -> &[ControlSetting] {
        &self.controls
    }

    /// Returns whether automatic exposure remains enabled.
    #[must_use]
    pub const fn auto_exposure_enabled(&self) -> bool {
        self.auto_exposure_enabled
    }

    /// Returns the fixed RGB automatic-exposure warm-up count.
    #[must_use]
    pub const fn rgb_warmup_frames(&self) -> usize {
        self.rgb_warmup_frames
    }

    /// Returns the fixed RGB temporal-median contributor count.
    #[must_use]
    pub const fn rgb_median_frames(&self) -> usize {
        self.rgb_median_frames
    }

    /// Returns whether IR ambient subtraction is enabled.
    #[must_use]
    pub const fn ambient_subtraction_enabled(&self) -> bool {
        self.ambient_subtraction_enabled
    }

    /// Validates every requested control against one bounded capability inventory.
    ///
    /// # Errors
    ///
    /// Returns an error when a control is absent, ineligible, type-incompatible,
    /// outside its range, off its step lattice, or absent from a sparse menu.
    pub fn validate_against(&self, inventory: &CapabilityInventory) -> Result<(), PolicyError> {
        let domains: Vec<_> = inventory
            .controls()
            .iter()
            .map(ControlDomain::from)
            .collect();
        self.validate_against_domains(&domains)
    }

    fn validate_against_domains(&self, domains: &[ControlDomain]) -> Result<(), PolicyError> {
        for setting in &self.controls {
            let domain = domains
                .iter()
                .find(|domain| domain.id == setting.id)
                .ok_or(PolicyError::UnsupportedControl(setting.id))?;
            domain.validate(*setting)?;
        }
        Ok(())
    }
}

/// Fixed policy catalog and its context-expiration version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditioningCatalog {
    version: u32,
    policies: [ConditioningPolicy; 4],
}

impl ConditioningCatalog {
    /// Builds the fixed catalog from one bounded standard-control inventory.
    /// BLC 2 is included only when its exact integer request is eligible;
    /// otherwise every policy retains its other safe settings without BLC.
    ///
    /// # Errors
    ///
    /// The fixed catalog currently has no mandatory control and therefore
    /// cannot fail. The result keeps catalog construction at the validation
    /// boundary used by manually authored policy validation.
    pub fn fixed(inventory: &CapabilityInventory) -> Result<Self, PolicyError> {
        let domains: Vec<_> = inventory
            .controls()
            .iter()
            .map(ControlDomain::from)
            .collect();
        Ok(Self::definition(
            CATALOG_VERSION,
            exact_blc_two_supported(&domains),
        ))
    }

    fn definition(version: u32, include_blc: bool) -> Self {
        let controls: Vec<_> = include_blc
            .then_some(ControlSetting::integer(V4L2_CID_BACKLIGHT_COMPENSATION, 2))
            .into_iter()
            .collect();
        let policy = |id| ConditioningPolicy {
            id,
            controls: controls.clone(),
            auto_exposure_enabled: true,
            rgb_warmup_frames: 6,
            rgb_median_frames: 5,
            ambient_subtraction_enabled: false,
        };
        Self {
            version,
            policies: [
                policy(ConditioningPolicyId::LitAuto),
                policy(ConditioningPolicyId::BacklitAuto),
                policy(ConditioningPolicyId::LowLight),
                policy(ConditioningPolicyId::DarkIr),
            ],
        }
    }

    /// Returns the fixed catalog version used for observation invalidation.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns a canonical digest over every policy fact that affects capture.
    #[must_use]
    pub fn digest(&self) -> String {
        use std::fmt::Write as _;

        let mut material = format!("conditioning-catalog-v1|version:{}", self.version);
        for policy in &self.policies {
            let _ = write!(
                material,
                "|policy:{}|ae:{}|warmup:{}|median:{}|ambient:{}|controls:{}",
                policy.id.as_str(),
                u8::from(policy.auto_exposure_enabled),
                policy.rgb_warmup_frames,
                policy.rgb_median_frames,
                u8::from(policy.ambient_subtraction_enabled),
                policy.controls.len(),
            );
            for control in &policy.controls {
                let kind = match control.kind {
                    ControlSettingKind::Integer => "integer",
                    ControlSettingKind::Boolean => "boolean",
                    ControlSettingKind::Menu => "menu",
                };
                let _ = write!(material, "|control:{}:{kind}:{}", control.id, control.value);
            }
        }
        irlume_common::sha256_hex(material.as_bytes())
    }

    /// Returns all four IDs in deterministic catalog order.
    #[must_use]
    pub const fn policy_ids(&self) -> [ConditioningPolicyId; 4] {
        [
            ConditioningPolicyId::LitAuto,
            ConditioningPolicyId::BacklitAuto,
            ConditioningPolicyId::LowLight,
            ConditioningPolicyId::DarkIr,
        ]
    }

    /// Returns the first-attempt safe default.
    #[must_use]
    pub const fn safe_default(&self) -> &ConditioningPolicy {
        &self.policies[0]
    }

    /// Returns a policy by stable identifier.
    #[must_use]
    pub fn policy(&self, id: ConditioningPolicyId) -> &ConditioningPolicy {
        let index = match id {
            ConditioningPolicyId::LitAuto => 0,
            ConditioningPolicyId::BacklitAuto => 1,
            ConditioningPolicyId::LowLight => 2,
            ConditioningPolicyId::DarkIr => 3,
        };
        &self.policies[index]
    }

    /// Selects the safe default or a policy derived from one fresh exact-context observation.
    ///
    /// The signature deliberately has no detector, recognition, liveness, PAD,
    /// identity, score, or authentication-result input.
    #[must_use]
    pub fn select(
        &self,
        context: &ConditioningContext,
        now: Instant,
        attempt: ConditioningAttempt<'_>,
    ) -> ConditioningSelection {
        let preceding_observation = match attempt {
            ConditioningAttempt::First => None,
            ConditioningAttempt::Later(observation) => Some(observation),
        };
        let scene = preceding_observation
            .filter(|observation| observation.context == *context)
            .filter(|observation| observation.catalog_version == self.version)
            .filter(|observation| {
                now.checked_duration_since(observation.observed_at)
                    .is_some_and(|age| age < CATALOG_TTL)
            })
            .map_or(SceneClass::Lit, |observation| {
                classify_scene(&observation.statistics)
            });
        let policy_id = match scene {
            SceneClass::Lit => ConditioningPolicyId::LitAuto,
            SceneClass::Backlit => ConditioningPolicyId::BacklitAuto,
            SceneClass::LowLight => ConditioningPolicyId::LowLight,
            SceneClass::DarkIr => ConditioningPolicyId::DarkIr,
        };
        ConditioningSelection {
            scene,
            policy_id,
            catalog_version: self.version,
        }
    }

    #[cfg(test)]
    fn with_version_for_test(version: u32) -> Self {
        Self::definition(version, true)
    }

    #[cfg(test)]
    fn fixed_from_domains_for_test(domains: &[ControlDomain]) -> Self {
        Self::definition(CATALOG_VERSION, exact_blc_two_supported(domains))
    }
}

pub(super) fn current_catalog() -> ConditioningCatalog {
    ConditioningCatalog::definition(CATALOG_VERSION, true)
}

/// Digest of the fixed catalog used by production attempt selection.
#[must_use]
pub fn current_catalog_digest() -> String {
    current_catalog().digest()
}

pub(super) fn current_safe_default() -> ConditioningPolicy {
    current_catalog().safe_default().clone()
}

fn exact_blc_two_supported(domains: &[ControlDomain]) -> bool {
    let setting = ControlSetting::integer(V4L2_CID_BACKLIGHT_COMPENSATION, 2);
    domains
        .iter()
        .any(|domain| domain.id == setting.id && domain.validate(setting).is_ok())
}

/// Exact process-local context that scopes one preceding scene observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditioningContext {
    camera_instance_id: CameraInstanceId,
    camera_generation: CameraGeneration,
    connection: ConnectionContext,
    transport_profile: PairTransportProfile,
}

impl ConditioningContext {
    /// Constructs exact camera, connection, and transport invalidation facts.
    #[must_use]
    pub const fn new(
        camera_instance_id: CameraInstanceId,
        camera_generation: CameraGeneration,
        connection: ConnectionContext,
        transport_profile: PairTransportProfile,
    ) -> Self {
        Self {
            camera_instance_id,
            camera_generation,
            connection,
            transport_profile,
        }
    }

    #[must_use]
    pub const fn camera_instance_id(&self) -> &CameraInstanceId {
        &self.camera_instance_id
    }

    #[must_use]
    pub const fn camera_generation(&self) -> CameraGeneration {
        self.camera_generation
    }

    #[must_use]
    pub const fn connection(&self) -> &ConnectionContext {
        &self.connection
    }

    #[must_use]
    pub const fn transport_profile(&self) -> &PairTransportProfile {
        &self.transport_profile
    }
}

/// Ordered visible-light brightness percentiles from one preceding evidence window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrightnessDistribution {
    p10: u8,
    median: u8,
    p90: u8,
}

impl BrightnessDistribution {
    /// Constructs ordered p10, median, and p90 brightness facts.
    ///
    /// # Errors
    ///
    /// Returns an error unless `p10 <= median <= p90`.
    pub const fn new(p10: u8, median: u8, p90: u8) -> Result<Self, PolicyError> {
        if p10 > median || median > p90 {
            return Err(PolicyError::InvalidStatistics);
        }
        Ok(Self { p10, median, p90 })
    }
}

/// Non-model illumination facts from the preceding RGB and IR evidence windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IlluminationFacts {
    ambient_dark: bool,
    active_ir_observed: bool,
}

impl IlluminationFacts {
    /// Constructs explicit ambient-dark and active-IR observations.
    #[must_use]
    pub const fn new(ambient_dark: bool, active_ir_observed: bool) -> Self {
        Self {
            ambient_dark,
            active_ir_observed,
        }
    }
}

/// Bounded non-model scene statistics from one completed evidence window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SceneStatistics {
    brightness: BrightnessDistribution,
    clipped_high_basis_points: u16,
    contrast: u8,
    illumination: IlluminationFacts,
}

impl SceneStatistics {
    /// Constructs bounded brightness, clipping, contrast, and illumination facts.
    ///
    /// # Errors
    ///
    /// Returns an error when clipping exceeds 100 percent.
    pub const fn new(
        brightness: BrightnessDistribution,
        clipped_high_basis_points: u16,
        contrast: u8,
        illumination: IlluminationFacts,
    ) -> Result<Self, PolicyError> {
        if clipped_high_basis_points > 10_000 {
            return Err(PolicyError::InvalidStatistics);
        }
        Ok(Self {
            brightness,
            clipped_high_basis_points,
            contrast,
            illumination,
        })
    }
}

/// One process-local observation retained only for a later attempt.
///
/// Task 5 exposes no production construction path. External callers cannot
/// fabricate an observation from arbitrary context, time, or statistics.
///
/// ```compile_fail
/// use std::time::Instant;
/// use irlume_camera::conditioning::{
///     ConditioningContext, SceneObservation, SceneStatistics,
/// };
///
/// fn fabricate(context: ConditioningContext, statistics: SceneStatistics) {
///     let _ = SceneObservation::new(context, 1, Instant::now(), statistics);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct SceneObservation {
    context: ConditioningContext,
    catalog_version: u32,
    observed_at: Instant,
    statistics: SceneStatistics,
}

impl SceneObservation {
    pub(crate) const fn from_validated_attempt(
        context: ConditioningContext,
        catalog_version: u32,
        observed_at: Instant,
        statistics: SceneStatistics,
    ) -> Self {
        Self {
            context,
            catalog_version,
            observed_at,
            statistics,
        }
    }

    /// Oldest contributing capture-window start used for freshness checks.
    #[must_use]
    pub const fn freshness_start(&self) -> Instant {
        self.observed_at
    }
}

/// Closed attempt phase for policy selection.
#[derive(Clone, Copy, Debug)]
pub enum ConditioningAttempt<'a> {
    /// Initial attempt, which structurally carries no observation authority.
    First,
    /// Later attempt with one preceding camera-authorized observation.
    Later(&'a SceneObservation),
}

/// Immutable catalog choice for one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditioningSelection {
    scene: SceneClass,
    policy_id: ConditioningPolicyId,
    catalog_version: u32,
}

impl ConditioningSelection {
    /// Returns the selected scene class.
    #[must_use]
    pub const fn scene(self) -> SceneClass {
        self.scene
    }

    /// Returns the selected stable policy identifier.
    #[must_use]
    pub const fn policy_id(self) -> ConditioningPolicyId {
        self.policy_id
    }

    /// Returns the catalog version frozen into this selection.
    #[must_use]
    pub const fn catalog_version(self) -> u32 {
        self.catalog_version
    }
}

/// Classifies one validated non-model statistics record at fixed exact boundaries.
#[must_use]
pub const fn classify_scene(statistics: &SceneStatistics) -> SceneClass {
    if statistics.illumination.ambient_dark && statistics.illumination.active_ir_observed {
        SceneClass::DarkIr
    } else if statistics.brightness.p90 >= BACKLIT_P90_MIN
        && statistics.clipped_high_basis_points >= BACKLIT_CLIPPED_MIN_BASIS_POINTS
        && statistics.contrast >= BACKLIT_CONTRAST_MIN
    {
        SceneClass::Backlit
    } else if statistics.brightness.median <= LOW_LIGHT_MEDIAN_MAX {
        SceneClass::LowLight
    } else {
        SceneClass::Lit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlKind {
    Integer,
    Boolean,
    Menu,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlDomain {
    id: u32,
    kind: ControlKind,
    minimum: i32,
    maximum: i32,
    step: i32,
    menu_indices: Vec<u32>,
    policy_eligible: bool,
}

impl From<&StandardControlCapability> for ControlDomain {
    fn from(control: &StandardControlCapability) -> Self {
        let kind = match control.control_type() {
            V4L2_CTRL_TYPE_INTEGER => ControlKind::Integer,
            V4L2_CTRL_TYPE_BOOLEAN => ControlKind::Boolean,
            V4L2_CTRL_TYPE_MENU | V4L2_CTRL_TYPE_INTEGER_MENU => ControlKind::Menu,
            _ => ControlKind::Unsupported,
        };
        let menu_indices = control
            .menu_values()
            .iter()
            .map(|entry| match entry {
                MenuValue::Name { index, .. } | MenuValue::Integer { index, .. } => *index,
            })
            .collect();
        Self {
            id: control.id(),
            kind,
            minimum: control.minimum(),
            maximum: control.maximum(),
            step: control.step(),
            menu_indices,
            policy_eligible: control.policy_eligible(),
        }
    }
}

impl ControlDomain {
    fn validate(&self, setting: ControlSetting) -> Result<(), PolicyError> {
        if !self.policy_eligible {
            return Err(PolicyError::IneligibleControl(self.id));
        }
        let expected = match setting.kind {
            ControlSettingKind::Integer => ControlKind::Integer,
            ControlSettingKind::Boolean => ControlKind::Boolean,
            ControlSettingKind::Menu => ControlKind::Menu,
        };
        if self.kind != expected {
            return Err(PolicyError::ControlTypeMismatch(self.id));
        }
        let value = i32::try_from(setting.value).map_err(|_| PolicyError::OutOfRange(self.id))?;
        if value < self.minimum || value > self.maximum {
            return Err(PolicyError::OutOfRange(self.id));
        }
        if (i64::from(value) - i64::from(self.minimum)) % i64::from(self.step) != 0 {
            return Err(PolicyError::OffStepLattice(self.id));
        }
        if self.kind == ControlKind::Boolean && !matches!(value, 0 | 1) {
            return Err(PolicyError::OutOfRange(self.id));
        }
        if self.kind == ControlKind::Menu
            && !u32::try_from(value)
                .ok()
                .is_some_and(|index| self.menu_indices.contains(&index))
        {
            return Err(PolicyError::UnavailableMenuValue(self.id));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(
        id: u32,
        kind: ControlKind,
        minimum: i32,
        maximum: i32,
        step: i32,
        menu_indices: &[u32],
        policy_eligible: bool,
    ) -> Self {
        Self {
            id,
            kind,
            minimum,
            maximum,
            step,
            menu_indices: menu_indices.to_vec(),
            policy_eligible,
        }
    }
}

/// Failure to construct, validate, apply, or confirm a conditioning policy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PolicyError {
    /// Scene statistics violate their bounded representation.
    InvalidStatistics,
    /// A policy has an empty evidence window or another invalid fixed field.
    InvalidPolicy,
    /// A policy names one control more than once.
    DuplicateControl,
    /// The inventory did not advertise the named standard control.
    UnsupportedControl(u32),
    /// The control exists but Task 2 marked it ineligible for policy writes.
    IneligibleControl(u32),
    /// The requested represented type differs from the advertised type.
    ControlTypeMismatch(u32),
    /// The requested value is outside the advertised inclusive range.
    OutOfRange(u32),
    /// The requested value is not on the advertised step lattice.
    OffStepLattice(u32),
    /// The requested sparse menu index was not advertised.
    UnavailableMenuValue(u32),
    /// Reading a named control failed.
    ControlRead { id: u32, errno: Option<i32> },
    /// Writing a named control failed. The operation is never retried.
    ControlWrite { id: u32, errno: Option<i32> },
    /// The driver's exact readback differed from the request.
    ReadbackMismatch(u32),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStatistics => formatter.write_str("invalid conditioning statistics"),
            Self::InvalidPolicy => formatter.write_str("invalid conditioning policy"),
            Self::DuplicateControl => formatter.write_str("duplicate conditioning control"),
            Self::UnsupportedControl(id) => write!(formatter, "unsupported control {id:#x}"),
            Self::IneligibleControl(id) => write!(formatter, "ineligible control {id:#x}"),
            Self::ControlTypeMismatch(id) => write!(formatter, "control {id:#x} type mismatch"),
            Self::OutOfRange(id) => write!(formatter, "control {id:#x} value is outside range"),
            Self::OffStepLattice(id) => {
                write!(formatter, "control {id:#x} value is off step lattice")
            }
            Self::UnavailableMenuValue(id) => {
                write!(formatter, "control {id:#x} menu value is unavailable")
            }
            Self::ControlRead { id, errno } => {
                write!(formatter, "control {id:#x} read failed (errno {errno:?})")
            }
            Self::ControlWrite { id, errno } => {
                write!(formatter, "control {id:#x} write failed (errno {errno:?})")
            }
            Self::ReadbackMismatch(id) => {
                write!(formatter, "control {id:#x} exact readback mismatch")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

pub(super) trait ControlIo: Sync {
    fn label(&self) -> &str {
        "camera"
    }

    fn read_control(&self, id: u32) -> io::Result<i64>;
    fn write_control(&self, id: u32, requested: i64) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug)]
struct AppliedControl {
    id: u32,
    requested: i64,
    displaced: i64,
}

/// Owns conditional reverse-order restoration for confirmed standard-control writes.
pub struct AppliedConditioningGuard<'a> {
    controls: &'a dyn ControlIo,
    applied: Vec<AppliedControl>,
    required: Vec<ControlSetting>,
    selection: Option<ConditioningSelection>,
}

/// Proof that one selected policy was exactly applied, read back, and restored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditioningRestoration {
    selection: ConditioningSelection,
}

impl ConditioningRestoration {
    #[must_use]
    pub const fn selection(self) -> ConditioningSelection {
        self.selection
    }

    #[cfg(test)]
    pub(crate) const fn for_test(selection: ConditioningSelection) -> Self {
        Self { selection }
    }

    #[cfg(test)]
    pub(crate) const fn with_policy_for_test(
        mut selection: ConditioningSelection,
        policy_id: ConditioningPolicyId,
    ) -> Self {
        selection.policy_id = policy_id;
        Self { selection }
    }
}

impl std::fmt::Debug for AppliedConditioningGuard<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppliedConditioningGuard")
            .field("applied", &self.applied)
            .finish_non_exhaustive()
    }
}

impl AppliedConditioningGuard<'_> {
    /// Returns whether this guard owns at least one confirmed write.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        !self.applied.is_empty()
    }

    #[must_use]
    pub const fn selection(&self) -> Option<ConditioningSelection> {
        self.selection
    }

    /// Explicitly restores every displaced value and confirms exact readback.
    ///
    /// # Errors
    ///
    /// Returns an error if ownership changed or restoration cannot be confirmed.
    pub fn restore(mut self) -> Result<ConditioningRestoration, PolicyError> {
        for setting in &self.required {
            match self.controls.read_control(setting.id) {
                Ok(value) if value == setting.value => {}
                Ok(_) => return Err(PolicyError::ReadbackMismatch(setting.id)),
                Err(error) => {
                    return Err(PolicyError::ControlRead {
                        id: setting.id,
                        errno: error.raw_os_error(),
                    });
                }
            }
        }
        while let Some(applied) = self.applied.pop() {
            match self.controls.read_control(applied.id) {
                Ok(now) if now == applied.requested => {}
                Ok(_) => return Err(PolicyError::ReadbackMismatch(applied.id)),
                Err(error) => {
                    return Err(PolicyError::ControlRead {
                        id: applied.id,
                        errno: error.raw_os_error(),
                    });
                }
            }
            self.controls
                .write_control(applied.id, applied.displaced)
                .map_err(|error| PolicyError::ControlWrite {
                    id: applied.id,
                    errno: error.raw_os_error(),
                })?;
            match self.controls.read_control(applied.id) {
                Ok(readback) if readback == applied.displaced => {}
                Ok(_) => return Err(PolicyError::ReadbackMismatch(applied.id)),
                Err(error) => {
                    return Err(PolicyError::ControlRead {
                        id: applied.id,
                        errno: error.raw_os_error(),
                    });
                }
            }
        }
        self.selection
            .take()
            .map(|selection| ConditioningRestoration { selection })
            .ok_or(PolicyError::InvalidPolicy)
    }
}

impl Drop for AppliedConditioningGuard<'_> {
    fn drop(&mut self) {
        for applied in self.applied.iter().rev() {
            if matches!(self.controls.read_control(applied.id), Ok(now) if now == applied.requested)
                && self
                    .controls
                    .write_control(applied.id, applied.displaced)
                    .is_err()
            {
                irlume_common::dlog!(
                    "{}: control {:#x} left at {}; restoring {} failed",
                    self.controls.label(),
                    applied.id,
                    applied.requested,
                    applied.displaced,
                );
            }
        }
    }
}

pub(super) fn apply_policy<'a>(
    controls: &'a dyn ControlIo,
    policy: &ConditioningPolicy,
) -> Result<AppliedConditioningGuard<'a>, PolicyError> {
    let mut ordered = policy.controls.to_vec();
    ordered.sort_unstable_by_key(|setting| setting.id);
    let mut guard = AppliedConditioningGuard {
        controls,
        applied: Vec::with_capacity(ordered.len()),
        required: ordered.clone(),
        selection: None,
    };

    for setting in ordered {
        let displaced =
            controls
                .read_control(setting.id)
                .map_err(|error| PolicyError::ControlRead {
                    id: setting.id,
                    errno: error.raw_os_error(),
                })?;
        if displaced == setting.value {
            continue;
        }
        controls
            .write_control(setting.id, setting.value)
            .map_err(|error| PolicyError::ControlWrite {
                id: setting.id,
                errno: error.raw_os_error(),
            })?;
        match controls.read_control(setting.id) {
            Ok(readback) if readback == setting.value => guard.applied.push(AppliedControl {
                id: setting.id,
                requested: setting.value,
                displaced,
            }),
            Ok(_) => {
                let _ = controls.write_control(setting.id, displaced);
                return Err(PolicyError::ReadbackMismatch(setting.id));
            }
            Err(error) => {
                let _ = controls.write_control(setting.id, displaced);
                return Err(PolicyError::ControlRead {
                    id: setting.id,
                    errno: error.raw_os_error(),
                });
            }
        }
    }
    Ok(guard)
}

pub(super) fn apply_selected_policy<'a>(
    controls: &'a dyn ControlIo,
    selection: ConditioningSelection,
    policy: &ConditioningPolicy,
) -> Result<AppliedConditioningGuard<'a>, PolicyError> {
    if selection.catalog_version == 0 || selection.policy_id != policy.id {
        return Err(PolicyError::InvalidPolicy);
    }
    let optional_blc = match policy.controls.as_slice() {
        [setting] if setting.id == V4L2_CID_BACKLIGHT_COMPENSATION => Some(*setting),
        _ => None,
    };
    let mut guard = if let Some(setting) = optional_blc {
        apply_optional_control(controls, setting)?
    } else {
        apply_policy(controls, policy)?
    };
    guard.selection = Some(selection);
    Ok(guard)
}

fn apply_optional_control<'a>(
    controls: &'a dyn ControlIo,
    setting: ControlSetting,
) -> Result<AppliedConditioningGuard<'a>, PolicyError> {
    let empty = || AppliedConditioningGuard {
        controls,
        applied: Vec::new(),
        required: Vec::new(),
        selection: None,
    };
    let displaced = match controls.read_control(setting.id) {
        Ok(value) => value,
        Err(_) => return Ok(empty()),
    };
    if displaced == setting.value {
        return Ok(AppliedConditioningGuard {
            controls,
            applied: Vec::new(),
            required: vec![setting],
            selection: None,
        });
    }
    if controls.write_control(setting.id, setting.value).is_err() {
        return Ok(empty());
    }
    if matches!(controls.read_control(setting.id), Ok(value) if value == setting.value) {
        return Ok(AppliedConditioningGuard {
            controls,
            applied: vec![AppliedControl {
                id: setting.id,
                requested: setting.value,
                displaced,
            }],
            required: vec![setting],
            selection: None,
        });
    }

    controls
        .write_control(setting.id, displaced)
        .map_err(|error| PolicyError::ControlWrite {
            id: setting.id,
            errno: error.raw_os_error(),
        })?;
    match controls.read_control(setting.id) {
        Ok(value) if value == displaced => Ok(empty()),
        Ok(_) => Err(PolicyError::ReadbackMismatch(setting.id)),
        Err(error) => Err(PolicyError::ControlRead {
            id: setting.id,
            errno: error.raw_os_error(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io,
        panic::{catch_unwind, AssertUnwindSafe},
        sync::Mutex,
        time::{Duration, Instant},
    };

    use super::*;
    use crate::{
        capture_qualification::ConnectionContext,
        contracts::{CameraGeneration, CameraInstanceId, StreamRole},
        frame_interval::FrameInterval,
        profile::{CaptureSchedule, DecodedPixelFormat, PairTransportProfile, StreamTuple},
        V4L2_CID_BACKLIGHT_COMPENSATION,
    };

    const GAIN: u32 = 0x0098_0913;
    const CONTRAST: u32 = 0x0098_0901;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Operation {
        Read(u32),
        Write(u32, i64),
    }

    #[derive(Default)]
    struct FakeState {
        values: BTreeMap<u32, i64>,
        operations: Vec<Operation>,
        write_errors: BTreeMap<u32, i32>,
        clamped_values: BTreeMap<(u32, i64), i64>,
    }

    #[derive(Default)]
    struct FakeControls {
        state: Mutex<FakeState>,
    }

    impl FakeControls {
        fn with_values(values: &[(u32, i64)]) -> Self {
            Self {
                state: Mutex::new(FakeState {
                    values: values.iter().copied().collect(),
                    ..FakeState::default()
                }),
            }
        }

        fn fail_write(&self, id: u32, errno: i32) {
            self.state.lock().unwrap().write_errors.insert(id, errno);
        }

        fn clamp_write(&self, id: u32, accepted: i64) {
            self.state
                .lock()
                .unwrap()
                .clamped_values
                .insert((id, 8), accepted);
        }

        fn external_write(&self, id: u32, value: i64) {
            self.state.lock().unwrap().values.insert(id, value);
        }

        fn value(&self, id: u32) -> i64 {
            self.state.lock().unwrap().values[&id]
        }

        fn operations(&self) -> Vec<Operation> {
            self.state.lock().unwrap().operations.clone()
        }
    }

    impl ControlIo for FakeControls {
        fn read_control(&self, id: u32) -> io::Result<i64> {
            let mut state = self.state.lock().unwrap();
            state.operations.push(Operation::Read(id));
            state
                .values
                .get(&id)
                .copied()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
        }

        fn write_control(&self, id: u32, requested: i64) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            state.operations.push(Operation::Write(id, requested));
            if let Some(errno) = state.write_errors.get(&id).copied() {
                return Err(io::Error::from_raw_os_error(errno));
            }
            let accepted = state
                .clamped_values
                .get(&(id, requested))
                .copied()
                .unwrap_or(requested);
            state.values.insert(id, accepted);
            Ok(())
        }
    }

    fn instance(byte: char) -> CameraInstanceId {
        CameraInstanceId::new(byte.to_string().repeat(32)).expect("valid test instance")
    }

    fn context(
        camera: char,
        generation: u64,
        connection: &str,
        transport: &str,
    ) -> ConditioningContext {
        ConditioningContext::new(
            instance(camera),
            CameraGeneration::new(generation).expect("nonzero generation"),
            ConnectionContext::new(
                format!("/devices/{connection}"),
                480_000,
                "uvcvideo".into(),
                "v4l2".into(),
            )
            .expect("valid connection"),
            PairTransportProfile::new(
                transport,
                StreamTuple::new(
                    StreamRole::Rgb,
                    DecodedPixelFormat::Yuyv,
                    640,
                    480,
                    FrameInterval::new(1, 15).unwrap(),
                )
                .unwrap(),
                StreamTuple::new(
                    StreamRole::Ir,
                    DecodedPixelFormat::Grey8,
                    640,
                    400,
                    FrameInterval::new(1, 15).unwrap(),
                )
                .unwrap(),
                CaptureSchedule::Sequential,
            )
            .expect("valid transport profile"),
        )
    }

    fn stats(
        p10: u8,
        median: u8,
        p90: u8,
        clipped_high_basis_points: u16,
        contrast: u8,
        illumination: IlluminationFacts,
    ) -> SceneStatistics {
        SceneStatistics::new(
            BrightnessDistribution::new(p10, median, p90).expect("ordered brightness"),
            clipped_high_basis_points,
            contrast,
            illumination,
        )
        .expect("bounded statistics")
    }

    fn policy(settings: Vec<ControlSetting>) -> ConditioningPolicy {
        ConditioningPolicy::new(ConditioningPolicyId::LitAuto, settings, true, 6, 5, false)
            .expect("valid test policy")
    }

    fn catalog() -> ConditioningCatalog {
        ConditioningCatalog::definition(CATALOG_VERSION, true)
    }

    fn observation(
        context: ConditioningContext,
        catalog_version: u32,
        observed_at: Instant,
        statistics: SceneStatistics,
    ) -> SceneObservation {
        SceneObservation {
            context,
            catalog_version,
            observed_at,
            statistics,
        }
    }

    fn integer(id: u32, minimum: i32, maximum: i32, step: i32) -> ControlDomain {
        ControlDomain::for_test(id, ControlKind::Integer, minimum, maximum, step, &[], true)
    }

    #[test]
    fn production_observation_minting_is_crate_private_and_attempt_validated() {
        let production = include_str!("conditioning.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("test module marker remains present")
            .0;

        assert!(!production.contains("fn observe("));
        assert!(production.contains("pub(crate) const fn from_validated_attempt("));
        assert!(!production.contains("pub const fn from_validated_attempt("));
    }

    #[test]
    fn scene_classification_has_exact_fixed_boundaries() {
        let ordinary = IlluminationFacts::new(false, false);
        assert_eq!(
            classify_scene(&stats(8, 63, 150, 0, 40, ordinary)),
            SceneClass::LowLight
        );
        assert_eq!(
            classify_scene(&stats(8, 64, 150, 0, 40, ordinary)),
            SceneClass::Lit
        );
        assert_eq!(
            classify_scene(&stats(0, 100, 224, 500, 96, ordinary)),
            SceneClass::Backlit
        );
        assert_eq!(
            classify_scene(&stats(0, 100, 224, 499, 96, ordinary)),
            SceneClass::Lit
        );
        assert_eq!(
            classify_scene(&stats(0, 100, 223, 500, 96, ordinary)),
            SceneClass::Lit
        );
        assert_eq!(
            classify_scene(&stats(0, 100, 224, 500, 95, ordinary)),
            SceneClass::Lit
        );
        assert_eq!(
            classify_scene(&stats(
                0,
                10,
                255,
                10_000,
                255,
                IlluminationFacts::new(true, true),
            )),
            SceneClass::DarkIr,
            "confirmed active IR in dark ambient outranks RGB scene classes"
        );
    }

    #[test]
    fn statistics_reject_impossible_distributions_and_clipping() {
        assert_eq!(
            BrightnessDistribution::new(20, 19, 21).unwrap_err(),
            PolicyError::InvalidStatistics
        );
        assert_eq!(
            SceneStatistics::new(
                BrightnessDistribution::new(1, 2, 3).unwrap(),
                10_001,
                2,
                IlluminationFacts::new(false, false),
            )
            .unwrap_err(),
            PolicyError::InvalidStatistics
        );
    }

    #[test]
    fn policy_cannot_name_an_unadvertised_or_ineligible_control() {
        let requested = policy(vec![ControlSetting::integer(GAIN, 8)]);
        assert_eq!(
            requested
                .validate_against_domains(&[integer(CONTRAST, 0, 255, 1)])
                .unwrap_err(),
            PolicyError::UnsupportedControl(GAIN)
        );
        let ineligible = ControlDomain::for_test(GAIN, ControlKind::Integer, 0, 255, 1, &[], false);
        assert_eq!(
            requested
                .validate_against_domains(&[ineligible])
                .unwrap_err(),
            PolicyError::IneligibleControl(GAIN)
        );
    }

    #[test]
    fn requested_values_must_match_type_range_step_and_menu_exactly() {
        let stepped = integer(GAIN, 2, 10, 2);
        assert_eq!(
            policy(vec![ControlSetting::integer(GAIN, 5)])
                .validate_against_domains(std::slice::from_ref(&stepped))
                .unwrap_err(),
            PolicyError::OffStepLattice(GAIN)
        );
        assert_eq!(
            policy(vec![ControlSetting::integer(GAIN, 12)])
                .validate_against_domains(&[stepped])
                .unwrap_err(),
            PolicyError::OutOfRange(GAIN)
        );

        let boolean = ControlDomain::for_test(GAIN, ControlKind::Boolean, 0, 1, 1, &[], true);
        assert_eq!(
            policy(vec![ControlSetting::integer(GAIN, 1)])
                .validate_against_domains(&[boolean])
                .unwrap_err(),
            PolicyError::ControlTypeMismatch(GAIN)
        );

        let menu = ControlDomain::for_test(GAIN, ControlKind::Menu, 0, 4, 1, &[0, 2, 4], true);
        assert_eq!(
            policy(vec![ControlSetting::menu(GAIN, 3)])
                .validate_against_domains(&[menu])
                .unwrap_err(),
            PolicyError::UnavailableMenuValue(GAIN)
        );
    }

    #[test]
    fn fixed_catalog_reproduces_the_current_safe_default() {
        let catalog = catalog();
        assert_eq!(
            catalog.policy_ids(),
            [
                ConditioningPolicyId::LitAuto,
                ConditioningPolicyId::BacklitAuto,
                ConditioningPolicyId::LowLight,
                ConditioningPolicyId::DarkIr,
            ]
        );
        let default = catalog.safe_default();
        assert_eq!(default.id(), ConditioningPolicyId::LitAuto);
        assert_eq!(
            default.controls(),
            &[ControlSetting::integer(V4L2_CID_BACKLIGHT_COMPENSATION, 2,)]
        );
        assert!(default.auto_exposure_enabled());
        assert_eq!(default.rgb_warmup_frames(), 6);
        assert_eq!(default.rgb_median_frames(), 5);
        assert!(!default.ambient_subtraction_enabled());
    }

    #[test]
    fn catalog_digest_binds_version_controls_and_reduction_policy() {
        let with_blc = ConditioningCatalog::definition(1, true);
        let without_blc = ConditioningCatalog::definition(1, false);
        let newer = ConditioningCatalog::definition(2, true);

        assert_eq!(with_blc.digest().len(), 64);
        assert_ne!(with_blc.digest(), without_blc.digest());
        assert_ne!(with_blc.digest(), newer.digest());
        assert_eq!(with_blc.digest(), with_blc.digest());
    }

    #[test]
    fn fixed_catalog_omits_blc_unless_exact_integer_two_is_eligible() {
        let absent = Vec::new();
        let ineligible = vec![ControlDomain::for_test(
            V4L2_CID_BACKLIGHT_COMPENSATION,
            ControlKind::Integer,
            0,
            4,
            1,
            &[],
            false,
        )];
        let wrong_type = vec![ControlDomain::for_test(
            V4L2_CID_BACKLIGHT_COMPENSATION,
            ControlKind::Boolean,
            0,
            1,
            1,
            &[],
            true,
        )];
        let out_of_range = vec![integer(V4L2_CID_BACKLIGHT_COMPENSATION, 0, 1, 1)];
        let off_lattice = vec![integer(V4L2_CID_BACKLIGHT_COMPENSATION, 0, 4, 3)];
        for domains in [
            &absent,
            &ineligible,
            &wrong_type,
            &out_of_range,
            &off_lattice,
        ] {
            let catalog = ConditioningCatalog::fixed_from_domains_for_test(domains);
            assert!(catalog
                .policy_ids()
                .iter()
                .all(|id| catalog.policy(*id).controls().is_empty()));
        }

        let supported = ConditioningCatalog::fixed_from_domains_for_test(&[integer(
            V4L2_CID_BACKLIGHT_COMPENSATION,
            0,
            4,
            1,
        )]);
        assert!(supported.policy_ids().iter().all(|id| {
            supported.policy(*id).controls()
                == [ControlSetting::integer(V4L2_CID_BACKLIGHT_COMPENSATION, 2)]
        }));
    }

    #[test]
    fn manual_blc_policy_still_rejects_every_unsupported_domain() {
        let requested = policy(vec![ControlSetting::integer(
            V4L2_CID_BACKLIGHT_COMPENSATION,
            2,
        )]);
        let ineligible = ControlDomain::for_test(
            V4L2_CID_BACKLIGHT_COMPENSATION,
            ControlKind::Integer,
            0,
            4,
            1,
            &[],
            false,
        );
        let wrong_type = ControlDomain::for_test(
            V4L2_CID_BACKLIGHT_COMPENSATION,
            ControlKind::Boolean,
            0,
            1,
            1,
            &[],
            true,
        );
        for (domains, expected) in [
            (
                Vec::new(),
                PolicyError::UnsupportedControl(V4L2_CID_BACKLIGHT_COMPENSATION),
            ),
            (
                vec![ineligible],
                PolicyError::IneligibleControl(V4L2_CID_BACKLIGHT_COMPENSATION),
            ),
            (
                vec![wrong_type],
                PolicyError::ControlTypeMismatch(V4L2_CID_BACKLIGHT_COMPENSATION),
            ),
            (
                vec![integer(V4L2_CID_BACKLIGHT_COMPENSATION, 0, 1, 1)],
                PolicyError::OutOfRange(V4L2_CID_BACKLIGHT_COMPENSATION),
            ),
            (
                vec![integer(V4L2_CID_BACKLIGHT_COMPENSATION, 0, 4, 3)],
                PolicyError::OffStepLattice(V4L2_CID_BACKLIGHT_COMPENSATION),
            ),
        ] {
            assert_eq!(requested.validate_against_domains(&domains), Err(expected));
        }
    }

    #[test]
    fn first_attempt_always_selects_the_safe_default() {
        let catalog = catalog();
        let selected = catalog.select(
            &context('a', 1, "usb-a", "profile-a"),
            Instant::now(),
            ConditioningAttempt::First,
        );
        assert_eq!(selected.scene(), SceneClass::Lit);
        assert_eq!(selected.policy_id(), ConditioningPolicyId::LitAuto);
    }

    #[test]
    fn later_attempt_uses_only_a_fresh_exact_context_observation() {
        let catalog = catalog();
        let now = Instant::now();
        let exact = context('a', 1, "usb-a", "profile-a");
        let observation = observation(
            exact.clone(),
            catalog.version(),
            now,
            stats(0, 100, 224, 500, 96, IlluminationFacts::new(false, false)),
        );
        assert_eq!(
            catalog
                .select(
                    &exact,
                    now + CATALOG_TTL - Duration::from_nanos(1),
                    ConditioningAttempt::Later(&observation)
                )
                .policy_id(),
            ConditioningPolicyId::BacklitAuto
        );
        assert_eq!(
            catalog
                .select(
                    &exact,
                    now + CATALOG_TTL,
                    ConditioningAttempt::Later(&observation),
                )
                .policy_id(),
            ConditioningPolicyId::LitAuto,
            "an observation expires at the exact TTL"
        );
    }

    #[test]
    fn every_context_or_catalog_change_invalidates_the_observation() {
        let catalog = catalog();
        let now = Instant::now();
        let original = context('a', 1, "usb-a", "profile-a");
        let observation = observation(
            original.clone(),
            catalog.version(),
            now,
            stats(0, 20, 100, 0, 40, IlluminationFacts::new(false, false)),
        );
        let changed = [
            context('b', 1, "usb-a", "profile-a"),
            context('a', 2, "usb-a", "profile-a"),
            context('a', 1, "usb-b", "profile-a"),
            context('a', 1, "usb-a", "profile-b"),
        ];
        for candidate in &changed {
            assert_eq!(
                catalog
                    .select(candidate, now, ConditioningAttempt::Later(&observation))
                    .policy_id(),
                ConditioningPolicyId::LitAuto
            );
        }
        assert_eq!(
            ConditioningCatalog::with_version_for_test(catalog.version() + 1)
                .select(&original, now, ConditioningAttempt::Later(&observation),)
                .policy_id(),
            ConditioningPolicyId::LitAuto
        );
    }

    #[test]
    fn future_observation_defaults_instead_of_gaining_authority() {
        let catalog = catalog();
        let now = Instant::now();
        let exact = context('a', 1, "usb-a", "profile-a");
        let future = observation(
            exact.clone(),
            catalog.version(),
            now + Duration::from_nanos(1),
            stats(0, 20, 100, 0, 40, IlluminationFacts::new(false, false)),
        );
        assert_eq!(
            catalog
                .select(&exact, now, ConditioningAttempt::Later(&future))
                .policy_id(),
            ConditioningPolicyId::LitAuto
        );
    }

    #[test]
    fn controls_apply_in_id_order_and_restore_in_reverse_order() {
        let controls = FakeControls::with_values(&[(GAIN, 2), (CONTRAST, 4)]);
        let requested = policy(vec![
            ControlSetting::integer(GAIN, 8),
            ControlSetting::integer(CONTRAST, 10),
        ]);
        let guard = apply_policy(&controls, &requested).expect("policy applies");
        drop(guard);
        let writes: Vec<_> = controls
            .operations()
            .into_iter()
            .filter(|operation| matches!(operation, Operation::Write(_, _)))
            .collect();
        assert_eq!(
            writes,
            vec![
                Operation::Write(CONTRAST, 10),
                Operation::Write(GAIN, 8),
                Operation::Write(GAIN, 2),
                Operation::Write(CONTRAST, 4),
            ]
        );
    }

    #[test]
    fn exact_readback_mismatch_is_restored_immediately() {
        let controls = FakeControls::with_values(&[(GAIN, 2)]);
        controls.clamp_write(GAIN, 7);
        assert_eq!(
            apply_policy(&controls, &policy(vec![ControlSetting::integer(GAIN, 8)])).unwrap_err(),
            PolicyError::ReadbackMismatch(GAIN)
        );
        assert_eq!(controls.value(GAIN), 2);
        assert_eq!(
            controls.operations(),
            vec![
                Operation::Read(GAIN),
                Operation::Write(GAIN, 8),
                Operation::Read(GAIN),
                Operation::Write(GAIN, 2),
            ]
        );
    }

    #[test]
    fn timeout_and_stall_are_never_retried() {
        for errno in [libc::ETIMEDOUT, libc::EPIPE] {
            let controls = FakeControls::with_values(&[(GAIN, 2)]);
            controls.fail_write(GAIN, errno);
            assert!(matches!(
                apply_policy(&controls, &policy(vec![ControlSetting::integer(GAIN, 8)])),
                Err(PolicyError::ControlWrite { id: GAIN, errno: Some(actual) }) if actual == errno
            ));
            assert_eq!(
                controls
                    .operations()
                    .iter()
                    .filter(|operation| matches!(operation, Operation::Write(GAIN, 8)))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn a_later_failure_restores_every_confirmed_earlier_write() {
        let controls = FakeControls::with_values(&[(CONTRAST, 4), (GAIN, 2)]);
        controls.fail_write(GAIN, libc::EIO);
        let requested = policy(vec![
            ControlSetting::integer(GAIN, 8),
            ControlSetting::integer(CONTRAST, 10),
        ]);
        assert!(apply_policy(&controls, &requested).is_err());
        assert_eq!(controls.value(CONTRAST), 4);
        assert_eq!(controls.value(GAIN), 2);
    }

    #[test]
    fn restore_does_not_overwrite_a_newer_external_value() {
        let controls = FakeControls::with_values(&[(V4L2_CID_BACKLIGHT_COMPENSATION, 0)]);
        let guard = apply_policy(
            &controls,
            &policy(vec![ControlSetting::integer(
                V4L2_CID_BACKLIGHT_COMPENSATION,
                2,
            )]),
        )
        .expect("policy applies");
        controls.external_write(V4L2_CID_BACKLIGHT_COMPENSATION, 1);
        drop(guard);
        assert_eq!(controls.value(V4L2_CID_BACKLIGHT_COMPENSATION), 1);
    }

    #[test]
    fn guard_restores_during_panic_unwind_but_owns_no_preexisting_target() {
        let controls = FakeControls::with_values(&[(GAIN, 2)]);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = apply_policy(&controls, &policy(vec![ControlSetting::integer(GAIN, 8)]))
                .expect("policy applies");
            panic!("synthetic unwind");
        }));
        assert!(result.is_err());
        assert_eq!(controls.value(GAIN), 2);

        controls.external_write(GAIN, 8);
        let guard = apply_policy(&controls, &policy(vec![ControlSetting::integer(GAIN, 8)]))
            .expect("already requested is harmless");
        controls.external_write(GAIN, 6);
        drop(guard);
        assert_eq!(controls.value(GAIN), 6);
    }

    #[test]
    fn selected_policy_requires_apply_readback_and_explicit_restoration_proof() {
        let controls = FakeControls::with_values(&[(GAIN, 3)]);
        let selected = ConditioningSelection {
            scene: SceneClass::Lit,
            policy_id: ConditioningPolicyId::LitAuto,
            catalog_version: CATALOG_VERSION,
        };
        let requested = policy(vec![ControlSetting::integer(GAIN, 8)]);

        let applied = apply_selected_policy(&controls, selected, &requested).unwrap();
        assert_eq!(controls.value(GAIN), 8, "exact readback gates application");

        let proof = applied.restore().unwrap();
        assert_eq!(proof.selection(), selected);
        assert_eq!(controls.value(GAIN), 3, "proof follows exact restoration");
    }

    #[test]
    fn external_change_prevents_restoration_proof() {
        let controls = FakeControls::with_values(&[(GAIN, 3)]);
        let selected = ConditioningSelection {
            scene: SceneClass::Lit,
            policy_id: ConditioningPolicyId::LitAuto,
            catalog_version: CATALOG_VERSION,
        };
        let requested = policy(vec![ControlSetting::integer(GAIN, 8)]);
        let applied = apply_selected_policy(&controls, selected, &requested).unwrap();

        controls.external_write(GAIN, 6);

        assert!(applied.restore().is_err());
        assert_eq!(controls.value(GAIN), 6);
    }

    #[test]
    fn selected_policy_omits_unavailable_optional_blc_and_still_proves_restoration() {
        let controls = FakeControls::with_values(&[]);
        let selected = ConditioningSelection {
            scene: SceneClass::Lit,
            policy_id: ConditioningPolicyId::LitAuto,
            catalog_version: CATALOG_VERSION,
        };
        let requested = policy(vec![ControlSetting::integer(
            V4L2_CID_BACKLIGHT_COMPENSATION,
            2,
        )]);

        let applied = apply_selected_policy(&controls, selected, &requested).unwrap();
        assert!(!applied.is_armed());
        assert_eq!(applied.restore().unwrap().selection(), selected);
    }
}
