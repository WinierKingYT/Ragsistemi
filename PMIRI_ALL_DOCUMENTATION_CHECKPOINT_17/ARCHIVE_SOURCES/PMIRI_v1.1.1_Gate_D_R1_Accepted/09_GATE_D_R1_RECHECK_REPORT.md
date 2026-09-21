# Gate D Round 1 Recheck Report

**Result: ALL PASS**

| Check | Result | Closure evidence |
|---|---|---|
| R-D1-01 | PASS | RequestAuthorizationBinding is trusted-boundary derived. |
| R-D1-02 | PASS | AuthorizationSubjectChain uses least-privilege intersection. |
| R-D1-03 | PASS | Caller narrowing cannot broaden allowed domain. |
| R-D1-04 | PASS | Public URL never auto-creates PUBLIC classification. |
| R-D1-05 | PASS | CLOUD_OK still requires exact material + destination + policy allow. |
| R-D1-06 | PASS | LOCAL_ONLY external-provider egress denied. |
| R-D1-07 | PASS | ClassificationChangeDecision required for re/declassification. |
| R-D1-08 | PASS | No numeric label ordering exists. |
| R-D1-09 | PASS | DerivedSensitivityAssessment handles aggregate/mosaic sensitivity. |
| R-D1-10 | PASS | Access/policy revocation invalidates applicable policy epoch/decision validity. |
| R-D1-11 | PASS | Provider/destination-policy revocation invalidates send eligibility. |
| R-D1-12 | PASS | Cached decisions bind full validity tuple. |
| R-D1-13 | PASS | DisclosureEquivalenceClass can hide denied vs nonexistent externally. |
| R-D1-14 | PASS | Internal omission/denial reasons require disclosure projection. |
| R-D1-15 | PASS | Models/source text cannot change security policy. |
| R-D1-16 | PASS | Egress allow bound to exact destination and material manifest. |
| R-D1-17 | PASS | Local model/workload requires DestinationSecurityBinding + TrustZoneAttestation. |
| R-D1-18 | PASS | External INDETERMINATE fails closed. |
| R-D1-19 | PASS | Missing material SecurityLineage blocks external disclosure/egress. |
| R-D1-20 | PASS | Internal reason graphs are not externally mandatory. |

Round 1 is ACCEPTED. Gate D remains OPEN.
