# Irlume Face Authentication

Irlume authenticates a local person from camera evidence while preserving a
password fallback and making hardware-dependent decisions explicit.

## Language

**Capture schedule**:
The ordering used to acquire an RGB+IR pair: concurrent or sequential.
_Avoid_: Camera mode, dual mode

**Capture qualification**:
Context-bound evidence authorizing the capture schedule for an exact camera
pair, stream contract, and connection.
_Avoid_: Camera capability, compatibility flag

**Runtime degradation**:
A temporary, process-local demotion from concurrent to sequential after live
capture evidence violates the qualified contract.
_Avoid_: Requalification, permanent downgrade

**Support report**:
A share-safe, human-readable snapshot of sanitized Irlume health and recent
diagnostic facts.
_Avoid_: Log dump, support bundle

**Diagnostic trace**:
A privileged, time-bounded stream of structured events from live Irlume
operations.
_Avoid_: Debug mode, permanent verbose logging

**Campaign policy**:
The versioned maintainer rules that fix cohort, attack, statistical, retention,
review, and invalidation requirements for release qualification.
_Avoid_: Test settings, campaign options

**Campaign protocol**:
A signed declaration that applies one campaign policy to one exact hardware
class and baseline/candidate profile pair before authorizing capture.
_Avoid_: Test plan, run configuration

**Private campaign bundle**:
The frozen, encrypted, content-addressed biometric inputs and audit records for
one release qualification campaign.
_Avoid_: Dataset, corpus archive

**Reviewed aggregate**:
The canonical identity-free envelope binding a campaign result to its passing
independent review attestation.
_Avoid_: Benchmark report, raw result

**Publication boundary**:
The point at which a reviewed aggregate becomes an immutable released fact;
later withdrawal removes retained assets and future use, not the published fact.
_Avoid_: Consent cutoff, release freeze
