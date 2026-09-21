# PMIRI GC-C1 — Independent Contract Review Report

**Review type:** Read-only contract/document review  
**Scope:** GC-C1-01 through GC-C1-07 plus Gate-C authority references  
**Review status:** FIX-FIRST  
**Runtime execution:** NONE  
**R-FC PASS:** NONE  

## 1. Verdict

The GC-C1 package is conceptually coherent and covers the intended evidence-hardening boundary, but it is not yet internally executable as one canonical contract set. The package must remain `FIX-FIRST` until the record-shape, authority-bundle and manifest-enforcement conflicts below are resolved and re-versioned.

This verdict is not an R-FC result and does not evaluate production behavior.

## 2. Review method

The review compared:

- R-FC-01 through R-FC-17 coverage between the evidence matrix and fixture catalog;
- PF-01 through PF-16 coverage between the preflight contract, check specification, scenario matrix and preflight schema;
- runner inputs/outputs against the preflight record requirements;
- sealing-contract requirements against the artifact-manifest schema;
- status vocabulary, fingerprints, negative-result preservation and independent-review boundaries.

The JSON documents parsed successfully. No runtime runner, validator or replay was invoked.

## 3. Findings

### F-01 — BLOCKER: canonical preflight record shape is contradictory

**Evidence:** `PMIRI_GC-C1-04_PREFLIGHT_VALIDATOR_CONTRACT_v0.1.md:145-164` defines flat fields such as `runner_id`, `runner_version`, `manifest_fingerprint`, `authority_bundle_fingerprint` and singular `evidence_ref`. `PMIRI_GC-C1-06_PREFLIGHT_RECORD.schema.json` instead requires nested `runner`, `inputs`, `environment` and `artifacts` objects, requires `source_fingerprint`, `matrix_fingerprint`, `privacy_record_ref` and `seal_status`, and uses `evidence_refs`.

**Impact:** A producer following C1-04 cannot validate against C1-06. The preflight output has no single canonical serialization, so its fingerprint and independent-review target are undefined.

**Required fix:** Choose one canonical record shape; update C1-04, C1-05 required-field references, C1-06 schema and the runner manifest together. Add a versioned migration note if the flat shape is intentionally retired.

### F-02 — BLOCKER: C1-04 example permits an invalid per-check result

**Evidence:** `PMIRI_GC-C1-04_PREFLIGHT_VALIDATOR_CONTRACT_v0.1.md:158-160` shows `result: PASS|BLOCKED|VALIDATION_ERROR|ISOLATION_VIOLATION`. C1-06 explicitly states that `PASS` is not a valid preflight result and its schema allows `READY`, not `PASS`.

**Impact:** The prose contract can cause an implementation or reviewer to emit a false PASS-like state, directly violating the package’s readiness-versus-R-FC distinction.

**Required fix:** Replace the example with one canonical vocabulary, preferably `READY|BLOCKED|VALIDATION_ERROR|ISOLATION_VIOLATION`, and add a cross-document vocabulary check to the review checklist.

### F-03 — BLOCKER: runtime record schema is frozen as DESIGN_ONLY

**Evidence:** `PMIRI_GC-C1-06_PREFLIGHT_RECORD.schema.json` requires top-level `status` to equal `DESIGN_ONLY`.

**Impact:** A future actual preflight record cannot represent an executed record while using the same schema. This confuses artifact lifecycle status with runtime result status and prevents a clean evidence transition.

**Required fix:** Separate schema/package status from record execution status. Permit a defined runtime vocabulary such as `RECORDED` or `EXECUTED`, while keeping the current design artifact itself marked `DESIGN_ONLY` outside the runtime record instance.

### F-04 — HIGH: artifact-manifest schema does not enforce required role coverage

**Evidence:** `PMIRI_GC-C1-07_ARTIFACT_SEALING_INTEGRITY_CONTRACT_v0.1.md:51-70` requires runner, authority, schema, catalog, matrix, preflight, environment, privacy, review and seal roles. The schema only constrains `required_roles` to a non-empty array of allowed role names; it does not require the declared minimum role set or require a matching entry for each role.

**Impact:** A manifest can validate while omitting a required artifact, defeating the completeness claim.

**Required fix:** Encode mandatory role coverage with explicit `contains` constraints or a validator rule that is itself part of the sealed contract. Require `required_roles` to match the present manifest entries.

### F-05 — HIGH: path and entry uniqueness are contractual but not machine-enforced

**Evidence:** C1-07 requires path collision detection and undeclared-file detection. The manifest schema has no uniqueness constraint for `entry_id`, `path` or role/path pairs; `uniqueItems` on `required_roles` does not solve duplicate paths across distinct entry objects.

**Impact:** Two entries may point to the same path, or a changed file may be represented ambiguously while the JSON remains schema-valid.

**Required fix:** Add explicit sealed-validator assertions for unique entry IDs, unique normalized paths, path-root containment, and complete directory inventory. Record undeclared-file failures as `INTEGRITY_FAILURE`.

### F-06 — HIGH: authority bundle identity is not closed consistently

**Evidence:** C1-01 requires exact immutable R1/R2/R3 authority references. The fixture catalog’s `authority_refs` contains only `PMIRI_v1.0_Gate_C_Accepted/00_DOCUMENTATION_AUTHORITY.md` and the C1-01 matrix. The current workspace uses a differently named uploaded authority file, and the catalog does not carry a complete R1/R2/R3 fingerprint set.

**Impact:** A future runner cannot establish that the catalog, matrix and accepted Gate-C authority chain refer to the same immutable source set.

**Required fix:** Create one canonical authority bundle manifest with exact relative paths, source archive identity and SHA-256 values; reference that bundle from the catalog, preflight spec, runner manifest and preflight record.

### F-07 — MEDIUM: NOT_APPLICABLE manifest entries still require file identity fields

**Evidence:** The C1-07 schema requires `path`, `byte_length` and `sha256` for every entry, while also allowing `presence: NOT_APPLICABLE`.

**Impact:** A genuinely absent/non-applicable role must invent a path, length and digest, weakening the meaning of non-applicability and completeness.

**Required fix:** Use conditional schemas: `PRESENT` requires path/length/hash; `NOT_APPLICABLE` requires only a reason and must reject file identity fields.

## 4. Positive consistency observations

These are observations, not PASS claims:

- The fixture catalog contains R-FC-01 through R-FC-17, each with positive and adversarial cases.
- The preflight specification and scenario matrix both cover PF-01 through PF-16.
- The package repeatedly preserves `DESIGN_ONLY`, `UNVERIFIED`, fail-closed and no-PASS boundaries.
- C1-03, C1-04, C1-05, C1-06 and C1-07 consistently require fingerprints, isolation evidence, privacy handling and independent review in principle.

## 5. Required repair order

1. Resolve the canonical preflight record shape and vocabulary (F-01, F-02, F-03).
2. Close the authority bundle and fingerprint lineage (F-06).
3. Strengthen manifest role/path enforcement and conditional non-applicability (F-04, F-05, F-07).
4. Re-run this document-only review against a new versioned package.
5. Only after review acceptance may a separate execution authorization be considered.

## 6. Boundary decision

Until the findings are repaired and independently re-reviewed:

- GC-C1 remains `DESIGN_ONLY` / `FIX-FIRST`;
- all R-FC-01 through R-FC-17 remain `UNVERIFIED`;
- no preflight or replay execution is authorized;
- Gate D and production implementation remain blocked.
