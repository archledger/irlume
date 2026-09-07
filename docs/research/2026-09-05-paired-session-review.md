# Paired camera assessment lifecycle

The candidate drains a completed camera burst until its companion completes,
starts paired RGB before IR, and scopes streams to one authentication or enrollment
assessment. Negotiated handles can survive retries, but streaming queues are
re-created so later assessments do not reuse queues left idle through inference.

This changes concurrent retry and enrollment setup cost. Payload, privacy, rate,
continuity and qualification checks remain enforced; concurrent mode is not
enabled by the change. Stream owners drop before matching and consent.

Fresh scoped authentication/camera verification: 776 passed, zero failed,
30 existing ignored. Historical capture experiments were mixed: NexiGo passed
six RGB-first pairs, ASUS retained intermittent short payload refusals, and BRIO
refused capture. These results do not qualify full concurrent authentication,
consent, retry latency or every camera model. Keep this work under review before
rollout and preserve the existing stored sequential selection.
