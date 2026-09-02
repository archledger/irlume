// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Maintainer-only camera profile qualification contracts.
//!
//! External code cannot fabricate reviewed or verified campaign authority:
//!
//! ```compile_fail
//! use irlume_qualification::ReviewedAggregate;
//! let _reviewed = ReviewedAggregate::new_for_test();
//! ```
//!
//! ```compile_fail
//! use irlume_qualification::{CampaignPolicy, Verified};
//! let document: CampaignPolicy = todo!();
//! let _verified = Verified::new_for_test(document);
//! ```
//!
//! Unsigned release artifacts can be produced only from reviewed authority:
//!
//! ```compile_fail
//! use irlume_qualification::UnsignedReleaseArtifact;
//! let _bytes = UnsignedReleaseArtifact::from_unreviewed_result(b"{}");
//! ```

mod canonical;
mod compiler;
mod lifecycle;
mod policy;
mod protocol;
mod reducer;
mod result;
mod signature;
mod statistics;

pub use canonical::{
    CampaignDiagnostic, CampaignError, CanonicalDocument, Identifier, RatePpb, Sha256Digest,
    SignedRateDifferencePpb, SignerFingerprint, MAX_CAMPAIGN_DOCUMENT_BYTES, RATE_SCALE_PPB,
};
pub use compiler::{compile_unsigned_release_artifact, UnsignedReleaseArtifact};
pub use lifecycle::{
    resolve_deletion, validate_collection_eligibility, validate_evaluation_eligibility,
    validate_frozen_bundle, validate_publication_eligibility, AssetDescriptor, AttemptRecord,
    BundleIndex, CaptureOrderPosition, CaptureShard, CaseSideCapture, DeletionDisposition,
    DeletionReason, DeletionRecord, DeletionStatus, EligibilityPhase, EligibilitySnapshot,
    EligibilityStatus, PairedCaseCapture, TokenEligibility, ValidatedCollectionEligibility,
    ValidatedEvaluationEligibility, ValidatedFrozenBundle, ValidatedPublicationEligibility,
};
pub use policy::{
    BinaryGate, CampaignPolicy, ExpectedOutcome, MissingnessRule, PaiSpecies, PresentationClass,
    StratificationAxis, WithdrawalRule, CAMPAIGN_POLICY_SCHEMA_VERSION, CAMPAIGN_POLICY_VERSION,
    LATENCY_BOOTSTRAP_RESAMPLES, LATENCY_BUDGET_FRACTION_PPB, MAX_ASSETS_PER_ROLE_PER_CASE,
    MAX_ASSET_BYTES, MAX_CAPTURE_SHARD_CASES, MAX_PRIVATE_RETENTION_SECONDS, ONE_SIDED_ALPHA_PPB,
    OVERALL_MARGIN_PPB, REQUIRED_POWER_PPB, STRATUM_MARGIN_PPB,
};
pub use protocol::{
    CampaignProtocol, CaptureSchedule, CasePlan, EquipmentInvalidation, HardwareEndpointScope,
    HardwareScope, LockedSampleSize, OperatingPoint, PilotDiscordance, PixelFormat,
    ProfileContract, PublicRegressionEvidence, RuntimeContractDigests, StratumPlan, StreamContract,
    StreamRole, ValidatedProtocol, CAMPAIGN_PROTOCOL_SCHEMA_VERSION,
    HARDWARE_SCOPE_MATCH_POLICY_VERSION,
};
pub use reducer::{
    reduce_campaign, EvaluatedPairedCase, ProfileCaseOutcome, ReductionContext, StageOutcome,
};
pub use result::{
    assemble_reviewed_aggregate, PrivateTranscriptCase, PrivateTranscriptIndex,
    PrivateTranscriptShard, PublicAggregateResult, PublicCategoryCount, PublicGateResult,
    PublicLatencyResult, PublicPairedTable, PublicPresentationCategory, PublicSecurityResult,
    ReductionOutput, ResultDisposition, ReviewAttestation, ReviewChecks, ReviewContext,
    ReviewDecision, ReviewedAggregate, ReviewedAggregateEnvelope, RESULT_SCHEMA_VERSION,
};
pub use signature::{
    verify_document, DetachedSignatureVerifier, GpgDetachedSignatureVerifier, SignatureAlgorithm,
    SignatureMetadata, SignerRole, Verified, MAX_DETACHED_SIGNATURE_BYTES,
};
pub use statistics::{
    clopper_pearson, clopper_pearson_upper, cluster_bootstrap_latency, minimum_paired_sample_size,
    paired_mover_wilson, paired_mover_wilson_lower, ClopperPearsonUpper, ClusterLatency,
    IntersectionDecision, LatencyResult, MoverWilsonResult, PairedLatencyUs, PairedTable,
    PowerPlan,
};
