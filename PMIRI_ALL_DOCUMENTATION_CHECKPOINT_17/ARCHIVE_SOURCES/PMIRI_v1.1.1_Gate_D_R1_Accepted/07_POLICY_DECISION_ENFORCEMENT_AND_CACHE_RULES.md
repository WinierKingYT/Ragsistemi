# Policy Decision, Enforcement and Cache Rules

Policy decision and policy enforcement are distinct.

Security engines produce typed decisions. Data is released only at an accepted
enforcement boundary.

Accepted Gate-C enforcement points include:
- canonical/resource admission;
- `ExternalReadEmissionFence`;
- `ProviderSendFence`.

A cached `ALLOW` never bypasses those enforcement points.

Decision/cache reuse requires the complete SecurityDecisionValidity tuple to remain valid.
At minimum reuse cannot cross:
- principal/delegation chain;
- purpose;
- operation;
- resource/material manifest;
- trust zone;
- destination;
- policy bundle/epoch;
- relevant lifecycle/access validity.

On mismatch: re-evaluate. Never widen from cache.
