# PMIRI — Gate D Round 2 Entry Contract

**Status:** AUTHORIZED NEXT DESIGN ROUND / NOT IMPLEMENTATION AUTHORIZATION

## Mission

Define provider/destination trust, capability freshness authority, destination-specific
redaction/constrained-egress policy, connector boundary security and SSRF/external-fetch controls.

## Required topics

D2-01 provider/connector trust registry and destination trust assertions  
D2-02 CapabilityObservation authority, freshness, invalidation and fail-closed rules  
D2-03 provider feature/subprocessor/retention/training policy dimensions  
D2-04 redaction and `EgressConstrainedContextArtifact` policy  
D2-05 semantic-obligation impact of redaction  
D2-06 connector credential boundary and least privilege  
D2-07 URL/fetch/attachment boundary and SSRF protections  
D2-08 redirect/DNS/rebinding/content-type/size/network-address policy  
D2-09 outbound network allowlisting / trust-zone egress enforcement interface  
D2-10 Round-2 adversarial review

Encryption/key-domain and forensic-retention design remain D3.

Production implementation remains blocked.
