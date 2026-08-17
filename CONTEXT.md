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
