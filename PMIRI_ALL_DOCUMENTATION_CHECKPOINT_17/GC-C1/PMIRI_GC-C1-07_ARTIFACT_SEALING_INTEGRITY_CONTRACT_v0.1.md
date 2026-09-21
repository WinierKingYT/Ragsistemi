# PMIRI GC-C1-07 — Artifact Sealing and Integrity Contract

**Version:** 0.1  
**Status:** DESIGN_ONLY  
**Scope:** Preflight and future replay evidence artifacts  

## 1. Purpose

This contract defines how a PMIRI GC-C1 run seals its inputs, outputs and evidence references so that a later reviewer can establish:

- which exact authority, schema, catalog, matrix and runner inputs were used;
- which exact bytes produced each reported result;
- whether any file was modified, omitted, substituted or silently truncated;
- whether a negative, blocked or isolation-violation result remains visible;
- whether the bundle is reviewable without trusting mutable ambient state.

This is a design contract only. It does not execute preflight checks, replay fixtures or R-FC tests, and it does not create a PASS result.

## 2. Sealed bundle model

Every future run produces one immutable bundle with these logical components:

~~~text
bundle/
  artifact-manifest.json       # canonical inventory and hashes
  preflight-record.json        # PF-01..PF-16 result record
  evidence-records/            # one or more R-FC evidence records, if executed
  runner-manifest.json         # exact runner declaration
  authority/                   # exact authority inputs or immutable references
  fixtures/                    # selected fixture and case inputs
  environment/                 # isolation, determinism and resource evidence
  review/                      # independent review and sealing attestations
~~~

The physical layout may vary, but the manifest must preserve the same logical roles. A file is in scope when it is referenced by the manifest or required by the applicable output contract.

## 3. Manifest authority

The artifact manifest is the root integrity object. It must contain:

- a unique bundle identifier and contract version;
- creation timestamp and sealing timestamp;
- the ordered list of entries;
- each entry’s logical role, relative path, byte length and SHA-256 digest;
- the digest of the canonical manifest payload before the seal field is added;
- the final bundle digest and seal status;
- explicit completeness status.

The sealing validator must additionally enforce unique entry IDs, unique
normalized paths, role coverage against the required role set, and a complete
inventory of files under the bundle root. JSON Schema validation alone is not
enough for these cross-entry and filesystem assertions; their validator result
must be recorded and sealed.

The manifest itself is not complete merely because a ZIP or directory exists. Completeness is `COMPLETE` only when all required roles are present and every referenced file has a verified digest.

## 4. Canonical hashing rules

1. Hash the exact bytes, never a parsed or reformatted interpretation.
2. Use SHA-256, lowercase hexadecimal, exactly 64 characters.
3. Use UTF-8 for text artifacts; do not normalize whitespace, line endings or Unicode before hashing.
4. Store paths as relative POSIX paths with `/`; parent traversal and absolute paths are forbidden.
5. Sort manifest entries lexicographically by relative path for canonical serialization.
6. Canonical JSON uses UTF-8, no insignificant whitespace, deterministic key ordering and no trailing newline.
7. The manifest payload digest excludes the mutable final seal fields; the final bundle digest covers the sealed manifest plus all listed bytes.
8. A digest mismatch is a hard integrity failure, even if semantic content appears unchanged.

## 5. Required integrity states

~~~text
UNSEALED
  A bundle is being assembled; it is not review evidence.

SEALED
  All required entries are present, hashes match, and the seal was completed.

INTEGRITY_FAILURE
  At least one entry is missing, substituted, changed, malformed or mismatched.

INCOMPLETE
  The bundle lacks a required role or completeness attestation.

INVALIDATED
  A previously sealed bundle was superseded or found unreliable; it must remain
  discoverable and may not be silently replaced.
~~~

Only `SEALED` permits independent review. `SEALED` does not mean that any R-FC check passed.

## 6. Required role coverage

At minimum, the manifest must account for:

- runner source and runner manifest;
- authority bundle;
- evidence-record schema;
- replay fixture catalog;
- controlled preflight scenario matrix;
- preflight check specification;
- preflight output/evidence contract and record schema;
- selected fixture/case inputs;
- preflight record;
- environment/isolation evidence;
- privacy/redaction record;
- review and sealing attestations.

If a role is not applicable, the manifest must include an explicit
`NOT_APPLICABLE` entry with a reason and without fabricated path, length or
digest fields. Omission is not equivalent to non-applicability.

## 7. Failure and invalidation rules

The sealing process must fail closed when:

- any required fingerprint is absent or malformed;
- an entry is missing, duplicated, outside the allowed root or has a path collision;
- recorded byte length differs from observed byte length;
- any SHA-256 digest differs;
- canonical serialization is not reproducible;
- the bundle contains undeclared files that affect interpretation;
- privacy, isolation or teardown evidence is missing;
- a negative or blocked result is omitted from the manifest or replaced by a summary-only status;
- independent review references a different manifest digest.

The resulting state is `INTEGRITY_FAILURE`, `INCOMPLETE` or `INVALIDATED` as applicable. No failure may be converted to readiness or PASS by editing only the summary field.

## 8. Review and preservation

The final sealed bundle must retain:

- the manifest digest;
- the exact input fingerprints;
- the seal timestamp and sealing procedure version;
- the independent reviewer identity or pseudonymous review reference;
- the reviewer’s observed manifest digest;
- any invalidation history.

Reviewers must verify the bundle from a clean copy. A reviewer may report `ACCEPTED_FOR_REVIEW`, `REJECTED`, or `REQUIRES_RESEAL`; none of these values is an R-FC PASS.

## 9. Exit criteria for GC-C1-07

GC-C1-07 is design-complete when:

- the machine-readable manifest schema validates the required envelope and role coverage;
- hashing and canonicalization rules are unambiguous;
- missing, changed, undeclared and privacy-sensitive artifacts map to hard failures;
- invalidation preserves the original bundle and negative-result fields;
- the contract explicitly separates artifact integrity from preflight readiness and R-FC PASS.

No runtime execution is required or authorized for this design step.
