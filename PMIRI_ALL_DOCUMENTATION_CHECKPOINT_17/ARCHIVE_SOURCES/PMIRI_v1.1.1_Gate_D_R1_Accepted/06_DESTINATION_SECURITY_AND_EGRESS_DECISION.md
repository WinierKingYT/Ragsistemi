# Destination Security and Egress Decision Contract

## DestinationSecurityBinding

```text
DestinationSecurityBinding
- destination_binding_id
- destination_kind:
    LOCAL_WORKLOAD
    LOCAL_MODEL_RUNTIME
    CONNECTOR_SERVICE
    EXTERNAL_PROVIDER
- service/workload/provider identity ref
- trust_zone_attestation_ref
- provider_id?
- model_id?
- feature_id?
- purpose compatibility refs
- capability/trust-policy refs
- fingerprint
```

"Local" is not an automatic allow.

## EgressMaterialManifest

```text
EgressMaterialManifest
- manifest_id
- source EvidenceSet/context refs
- material security-lineage refs[]
- derived-sensitivity assessment refs[]
- semantic-obligation refs
- exact material/span membership digest
- canonical/access epoch refs
- fingerprint
```

## EgressDecision

An EgressDecision binds:
- exact RequestAuthorizationBinding/subject chain;
- exact purpose;
- exact DestinationSecurityBinding;
- exact EgressMaterialManifest;
- exact SecurityPolicyBundle + epoch coverage;
- current resource/canonical access;
- Gate-C semantic obligations;
- provider capability/trust inputs as later refined by D2.

Outcomes:
`ALLOW_AS_IS | ALLOW_WITH_CONSTRAINTS | RECOMPILE_REQUIRED_WITH_CONSTRAINTS |
DENY | INDETERMINATE`.

An allow for one material manifest or destination cannot be replayed for another.

`CLOUD_OK` is eligibility only. `LOCAL_ONLY` cannot cross a policy-defined external
provider boundary.
