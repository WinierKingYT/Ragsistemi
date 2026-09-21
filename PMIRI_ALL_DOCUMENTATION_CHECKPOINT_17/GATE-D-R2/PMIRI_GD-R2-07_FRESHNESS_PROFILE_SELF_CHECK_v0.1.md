# PMIRI — Gate D Round 2
# Freshness Profile Self-Check v0.1

**Status:** `DOCUMENTARY SELF-CHECK`
**Implementation authorization:** `NOT GRANTED`
**Runtime authorization:** `NOT GRANTED`

The authority matrix declares the profile ID
`D2-POLICY-FRESHNESS-001`. The fingerprint is computed over exactly this
payload, with object keys sorted lexicographically at every depth, array order
preserved, compact JSON separators, UTF-8 encoding and no trailing newline:

```json
{"dimensions":[...matrix dimensions in declared order...],"freshness_profile_id":"D2-POLICY-FRESHNESS-001"}
```

The expected SHA-256 is:

```text
604dd146196571cf7dd5d25eec7d8db066cebbeca07814ccfe647c9edd267d41
```

A validator MUST recompute the payload from
`PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json`, compare the result to
`/freshness_profile_fingerprint`, and fail closed on mismatch before using a
policy observation or derived decision. This file records the exact check
definition; it does not prove that a future runtime performs it.
