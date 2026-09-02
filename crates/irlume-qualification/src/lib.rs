// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Maintainer-only camera profile qualification contracts.

mod canonical;
mod signature;

pub use canonical::{
    CampaignDiagnostic, CampaignError, CanonicalDocument, Identifier, RatePpb, Sha256Digest,
    SignedRateDifferencePpb, SignerFingerprint, MAX_CAMPAIGN_DOCUMENT_BYTES, RATE_SCALE_PPB,
};
pub use signature::{
    verify_document, DetachedSignatureVerifier, GpgDetachedSignatureVerifier, SignatureAlgorithm,
    SignatureMetadata, SignerRole, Verified, MAX_DETACHED_SIGNATURE_BYTES,
};
