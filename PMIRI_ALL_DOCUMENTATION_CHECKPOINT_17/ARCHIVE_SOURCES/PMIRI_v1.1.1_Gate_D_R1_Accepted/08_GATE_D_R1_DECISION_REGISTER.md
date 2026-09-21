# Gate D Round 1 Accepted Decision Register

D1-D01 one owner does not collapse identities/zones  
D1-D02 authentication != authorization  
D1-D03 trusted-boundary RequestAuthorizationBinding  
D1-D04 effective authority = delegation intersection, not union  
D1-D05 trust zone requires trusted attestation  
D1-D06 purpose is workflow-bound state, not arbitrary caller label  
D1-D07 classifications are non-ordinal temporal authoritative bindings  
D1-D08 CLASSIFICATION_UNKNOWN is preserved and externally fail-closed  
D1-D09 classification does not grant access  
D1-D10 re/declassification requires typed authorized decision  
D1-D11 derived transforms preserve SecurityLineage  
D1-D12 aggregate/mosaic sensitivity requires DerivedSensitivityAssessment  
D1-D13 ResourceAccessDecision is purpose/zone/access/policy aware  
D1-D14 SecurityPolicyEpoch is scope-aware and invalidates stale decisions  
D1-D15 security-decision cache reuse binds the full validity tuple  
D1-D16 disclosure equivalence classes may hide protected existence without rewriting truth  
D1-D17 DestinationSecurityBinding covers local workloads and external providers  
D1-D18 EgressDecision binds exact destination + purpose + EgressMaterialManifest  
D1-D19 CLOUD_OK is not automatic allow; LOCAL_ONLY cannot external-egress  
D1-D20 policy decisions do not release data without Gate-C enforcement fences  
D1-D21 models/prompts/source text cannot authorize policy changes  
D1-D22 external INDETERMINATE fails closed
