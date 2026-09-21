# Resource Access and External Disclosure Policy

## ResourceAccessDecision

Outcomes:
`ALLOW | DENY | INDETERMINATE | REVALIDATE_REQUIRED`.

Authorization requires the accepted combination of:
- valid RequestAuthorizationBinding;
- effective delegated authority;
- project/collection/source or canonical-record access;
- lifecycle/standing;
- security classification/composition policy;
- purpose;
- trust-zone policy;
- current policy epoch.

Classification alone never grants access.

## ExternalReadDisclosureDecision

Outcomes may include:
`DISCLOSE_AS_IS | DISCLOSE_REDACTED | DISCLOSE_COARSENED |
OPAQUE_NOT_AVAILABLE | DENY | INDETERMINATE`.

## DisclosureEquivalenceClass

Policy may intentionally map multiple internal states to one externally observable class,
such as nonexistent, inaccessible, stale-reference, or historical-but-currently-denied.

The mapping affects disclosure only; it does not rewrite internal truth.

All V1 external read operations use Gate C's universal disclosure projection and
`ExternalReadEmissionFence`.
