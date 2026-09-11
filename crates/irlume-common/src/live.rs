// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Read-only, process-local daemon worker observations; not a device-wide audit.

use crate::{diagnostics::OperationId, live_camera::CameraInventorySnapshot};
use serde::{Deserialize, Deserializer, Serialize};

pub const LIVE_SCHEMA_VERSION: u32 = 1;
pub const MAX_WAITING_KINDS: usize = 18;
pub const MAX_BACKGROUND_OPERATIONS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveStage {
    Starting,
    Ready,
    Rebuilding,
    Stopping,
    #[serde(other)]
    Unknown,
}

/// Static work categories deliberately carry no request fields or outcomes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveOperationKind {
    Authentication,
    WalletAuthentication,
    Enrollment,
    Framing,
    Identification,
    CameraEnumeration,
    CameraSetup,
    CaptureQualification,
    CameraDiagnostics,
    ProfileRead,
    ProfileUpdate,
    SensorReadiness,
    WalletRead,
    WalletUpdate,
    RecoveryUpdate,
    Compatibility,
    Status,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LiveWorkerOperation {
    pub operation_id: OperationId,
    pub kind: LiveOperationKind,
    pub elapsed_ms: u64,
    /// A request to stop, not evidence that the work or camera has stopped.
    pub cancellation_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LiveWaitingCount {
    pub kind: LiveOperationKind,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiveStatusSnapshot {
    pub live_schema: u32,
    pub daemon_instance: OperationId,
    pub daemon_uptime_ms: u64,
    /// Invalidation hint after potentially state-changing work completes,
    /// including failed/unknown outcomes. This is not a successful-write count.
    pub state_revision: u64,
    pub stage: LiveStage,
    pub worker: Option<LiveWorkerOperation>,
    /// Known automatic tasks outside the request worker, not all OS processes.
    pub background: Vec<LiveWorkerOperation>,
    pub waiting: Vec<LiveWaitingCount>,
    pub cameras: CameraInventorySnapshot,
    /// False means worker/queue tracking is unavailable, never idle.
    pub tracking_available: bool,
}

fn bounded_rows<'de, T: Deserialize<'de>, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    struct RowsVisitor<T, const MAX: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> serde::de::Visitor<'de> for RowsVisitor<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX} live status rows")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut rows = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while let Some(row) = seq.next_element()? {
                if rows.len() == MAX {
                    return Err(serde::de::Error::custom("too many live status rows"));
                }
                rows.push(row);
            }
            Ok(rows)
        }
    }
    deserializer.deserialize_seq(RowsVisitor::<T, MAX>(std::marker::PhantomData))
}
fn deserialize_waiting<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<LiveWaitingCount>, D::Error> {
    bounded_rows::<_, _, MAX_WAITING_KINDS>(deserializer)
}
fn deserialize_background<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<LiveWorkerOperation>, D::Error> {
    bounded_rows::<_, _, MAX_BACKGROUND_OPERATIONS>(deserializer)
}

impl<'de> Deserialize<'de> for LiveStatusSnapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            live_schema: u32,
            daemon_instance: OperationId,
            daemon_uptime_ms: u64,
            state_revision: u64,
            stage: LiveStage,
            worker: Option<LiveWorkerOperation>,
            #[serde(deserialize_with = "deserialize_background")]
            background: Vec<LiveWorkerOperation>,
            #[serde(deserialize_with = "deserialize_waiting")]
            waiting: Vec<LiveWaitingCount>,
            cameras: CameraInventorySnapshot,
            tracking_available: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.live_schema != LIVE_SCHEMA_VERSION
            || wire.daemon_instance.as_bytes() == &[0; 16]
            || wire.waiting.len() > MAX_WAITING_KINDS
            || wire
                .waiting
                .iter()
                .try_fold(0_u64, |sum, row| sum.checked_add(row.count))
                .is_none()
            || wire.waiting.iter().enumerate().any(|(index, row)| {
                row.count == 0
                    || wire.waiting[..index]
                        .iter()
                        .any(|prior| prior.kind == row.kind)
            })
            || wire.background.iter().enumerate().any(|(index, task)| {
                task.operation_id.as_bytes() == &[0; 16]
                    || task.elapsed_ms > wire.daemon_uptime_ms
                    || wire
                        .worker
                        .as_ref()
                        .is_some_and(|worker| worker.operation_id == task.operation_id)
                    || wire.background[..index]
                        .iter()
                        .any(|prior| prior.operation_id == task.operation_id)
            })
            || wire.worker.as_ref().is_some_and(|worker| {
                worker.operation_id.as_bytes() == &[0; 16]
                    || worker.elapsed_ms > wire.daemon_uptime_ms
            })
        {
            return Err(serde::de::Error::custom("invalid live status snapshot"));
        }
        Ok(Self {
            live_schema: wire.live_schema,
            daemon_instance: wire.daemon_instance,
            daemon_uptime_ms: wire.daemon_uptime_ms,
            state_revision: wire.state_revision,
            stage: wire.stage,
            worker: wire.worker,
            background: wire.background,
            waiting: wire.waiting,
            cameras: wire.cameras,
            tracking_available: wire.tracking_available,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wire() -> serde_json::Value {
        serde_json::json!({
            "live_schema":1, "daemon_instance":"11111111111111111111111111111111",
            "daemon_uptime_ms":100, "state_revision":0, "stage":"ready", "worker":null,
            "waiting":[], "background":[], "tracking_available":true,
            "cameras":{"state":"uninitialized", "supervisor_id":null, "revision":0,
                "observed_ago_ms":null, "reason":null, "candidates":[]}
        })
    }
    #[test]
    fn live_status_wire_has_no_request_payload_and_accepts_future_labels_as_unknown() {
        let mut value = wire();
        value["stage"] = "future-stage".into();
        value["waiting"] = serde_json::json!([{"kind":"future-operation", "count":1}]);
        let parsed: LiveStatusSnapshot = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.stage, LiveStage::Unknown);
        assert_eq!(parsed.waiting[0].kind, LiveOperationKind::Unknown);
        let response = crate::Response::LiveStatus(Box::new(parsed));
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(serde_json::from_str::<crate::Response>(&encoded).is_ok());
        for private in ["user", "profile", "password", "score", "service"] {
            assert!(!encoded.contains(&format!("\"{private}\"")));
        }
    }
    #[test]
    fn live_status_wire_rejects_invalid_schema_bounds_ids_and_counts() {
        for (field, bad) in [
            ("live_schema", serde_json::json!(2)),
            (
                "daemon_instance",
                serde_json::json!("00000000000000000000000000000000"),
            ),
            (
                "waiting",
                serde_json::json!([{"kind":"enrollment","count":u64::MAX},{"kind":"authentication","count":1}]),
            ),
            (
                "waiting",
                serde_json::json!([{"kind":"enrollment","count":0}]),
            ),
            (
                "waiting",
                serde_json::json!([{"kind":"enrollment","count":1},{"kind":"enrollment","count":2}]),
            ),
            (
                "waiting",
                serde_json::json!(vec![
                    serde_json::json!({"kind":"enrollment","count":1});
                    MAX_WAITING_KINDS + 1
                ]),
            ),
            (
                "worker",
                serde_json::json!({"operation_id":"22222222222222222222222222222222", "kind":"enrollment", "elapsed_ms":101, "cancellation_requested":false}),
            ),
        ] {
            let mut value = wire();
            value[field] = bad;
            assert!(
                serde_json::from_value::<LiveStatusSnapshot>(value).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn live_background_wire_rejects_overflow_duplicate_identity_and_impossible_elapsed() {
        let task = serde_json::json!({"operation_id":"22222222222222222222222222222222", "kind":"capture_qualification", "elapsed_ms":10, "cancellation_requested":false});
        for rows in [
            vec![task.clone(); MAX_BACKGROUND_OPERATIONS + 1],
            vec![task.clone(), task.clone()],
            {
                let mut invalid = task.clone();
                invalid["elapsed_ms"] = 101.into();
                vec![invalid]
            },
            {
                let mut invalid = task.clone();
                invalid["operation_id"] = "00000000000000000000000000000000".into();
                vec![invalid]
            },
        ] {
            let mut value = wire();
            value["background"] = serde_json::json!(rows);
            assert!(serde_json::from_value::<LiveStatusSnapshot>(value).is_err());
        }
        let mut value = wire();
        value["worker"] = task.clone();
        value["background"] = serde_json::json!([task]);
        assert!(serde_json::from_value::<LiveStatusSnapshot>(value).is_err());
    }
}
