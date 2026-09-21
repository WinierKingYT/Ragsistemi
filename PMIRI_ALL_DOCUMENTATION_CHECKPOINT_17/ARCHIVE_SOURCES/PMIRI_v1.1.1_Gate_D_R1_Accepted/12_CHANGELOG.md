# v1.1.1 Changelog

- Added least-privilege AuthorizationSubjectChain.
- Added TrustZoneAttestation and PurposeBinding.
- Added temporal authoritative SecurityClassificationBinding and ClassificationChangeDecision.
- Preserved CLASSIFICATION_UNKNOWN while external behavior remains fail-closed.
- Added DerivedSensitivityAssessment for mosaic/aggregate sensitivity.
- Added scope-aware SecurityPolicyEpoch and SecurityDecisionValidity.
- Bound cache reuse to principal/purpose/resource/trust/destination/policy validity.
- Added DestinationSecurityBinding for local and external destinations.
- Added EgressMaterialManifest binding exact material to egress decisions.
- Added DisclosureEquivalenceClass for existence-safe shaping.
- Separated policy decision from Gate-C enforcement points.
- H-D1-01…20 recheck: ALL PASS.
