# PMIRI Gate D Round 2 — Independent Review Decision v0.4

```yaml
review_id: PMIRI-GD-R2-INDEPENDENT-REVIEW-DECISION-004
reviewer_role: independent documentary reviewer
reviewer_identity: GPT-5 Codex (OpenAI)
authoring_context_available: false
review_started_at: 2026-09-11T20:10:57Z
independence_status: INDEPENDENT
manifest_fingerprint: e87f4745975eefbbc7aa93f55befccc41184009e0777dc90ae760480981a7618
package_modified_during_review: false
decision: FIX-FIRST
acceptance_status: PENDING_AUTHORITY_DECISION
implementation_authorization: NOT_GRANTED
runtime_authorization: NOT_GRANTED
```

## Review boundary and anti-anchoring

This is a current-state documentary review only. No provider, connector, DNS,
network, parser, ingestion, migration, production, external-emission or
runtime action was performed. The manifest and every pre-existing package file
were left unchanged. The requested v0.4 decision file was absent at review
start.

The current-state pass was completed against the manifest, candidate index,
accepted Gate-C/D1 inputs, every current D2 schema/contract/matrix, v0.4
cross-field rules, v0.4 closure report, v0.4 commission, registry, profiles,
self-check and current mechanical results. A preliminary `FIX-FIRST`
determination was made before reading the prior independent decisions. The
prior decisions were then read only for historical reassessment; their
conclusions were not used as evidence for current correctness.

## Frozen manifest and complete hash evidence

The manifest was frozen by recording its current bytes and digest before
semantic review:

| Item | Result |
|---|---|
| Manifest | `PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json` |
| Raw manifest bytes | `18481` |
| Raw manifest SHA-256 | `5b7684c1be39571ff501b8f0d2d7db5b8f8ab499c1582db78c8988524a0fde9b` |
| Canonicalization | sorted object keys, compact separators, UTF-8, declared array order, no trailing newline, `manifest_fingerprint` omitted |
| Canonical input bytes | `15170` |
| Recomputed canonical SHA-256 | `e87f4745975eefbbc7aa93f55befccc41184009e0777dc90ae760480981a7618` |
| Declared manifest fingerprint | `e87f4745975eefbbc7aa93f55befccc41184009e0777dc90ae760480981a7618` |
| Candidate-member count | `48` |
| Candidate-member hash result | `48/48 MATCH` |
| Duplicate candidate paths/roles | none |
| Unlisted root-level D2 candidate files | none; the manifest itself is excluded from `candidate_members` |

The SHA-256 column below is both the manifest-declared expected digest and the
observed digest; every row was a `MATCH`.

| # | Role | Candidate member | SHA-256 | Result |
|---:|---|---|---|---|
| 1 | d2_01_contract | `PMIRI_GD-R2-01_PROVIDER_CONNECTOR_TRUST_REGISTRY_CONTRACT_v0.1.md` | `e830db432e8c63caf0e0ef193d06a4906a2a02bb41807b1c94cfb1f6321ed4ef` | MATCH |
| 2 | d2_01_trust_assertion_schema | `PMIRI_GD-R2-01_TRUST_ASSERTION.schema.json` | `7e86ff1033d6dae8c135cf17ed4ad8553091c1633f216e049593be0e46b508a1` | MATCH |
| 3 | d2_01_trust_decision_schema | `PMIRI_GD-R2-01_TRUST_DECISION.schema.json` | `23bf2adab6329e303af6eed96758d0612ad7e58f490eaf27c85793272a14676e` | MATCH |
| 4 | d2_01_connector_credential_boundary_schema | `PMIRI_GD-R2-01_CONNECTOR_CREDENTIAL_BOUNDARY.schema.json` | `ee883dfa33258c0b693f8a77b2332dc24c23b8540d94b22c27e4122ff4020492` | MATCH |
| 5 | d2_02_capability_contract | `PMIRI_GD-R2-02_CAPABILITY_FRESHNESS_INVALIDATION_CONTRACT_v0.1.md` | `c838459d78d80fee0385c4f900df96e19d3dc5370efd851f5175c1917686b557` | MATCH |
| 6 | d2_02_capability_observation_schema | `PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json` | `19b21a7129e45496d27953a71937360ca471f87dc796d013b154187595aba198` | MATCH |
| 7 | d2_02_capability_decision_schema | `PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json` | `4dc2d9aa94633ed1103497186675a9dfd03c3617f317dee6c27053fc0b6abdee` | MATCH |
| 8 | d2_03_redaction_contract | `PMIRI_GD-R2-03_REDACTION_CONSTRAINED_EGRESS_CONTRACT_v0.1.md` | `ce0df4a10c48201ea69a79d115502135349374b3b15886af097f0e0fb434acc0` | MATCH |
| 9 | d2_03_redaction_transformation_schema | `PMIRI_GD-R2-03_REDACTION_TRANSFORMATION.schema.json` | `9c4f199996f04831b3992b8515e13df6814f1080e1b62accde00353d4681efed` | MATCH |
| 10 | d2_03_typed_constraint_schema | `PMIRI_GD-R2-03_TYPED_CONSTRAINT.schema.json` | `407750f49e48b0c6bb34c94ff6cf954825ba5eceb446597e76d85c71ee0a2029` | MATCH |
| 11 | d2_03_egress_artifact_schema | `PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json` | `4b0c0c7d3a3be3ef5918252d6996da7579efdcaea0c76200daeb2cab9cf5e7a5` | MATCH |
| 12 | d2_03_obligation_transformation_matrix | `PMIRI_GD-R2-03_OBLIGATION_TRANSFORMATION_DECISION_MATRIX.json` | `b7cc0fb3ff51c7ea7227dce34e4f8ad7af7c1c80e382e8ab3f990a63a5a53f11` | MATCH |
| 13 | d2_04_network_contract | `PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md` | `12f0cb03d248617d56418b804e40d3bf1271046d351d26774554b396cf9d14e1` | MATCH |
| 14 | d2_04_connection_binding_schema | `PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json` | `b611d1558aacf9eeea8f36854ec0ca2bfbe24a3fec078457a65a230e9f66f968` | MATCH |
| 15 | d2_04_network_decision_schema | `PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json` | `86ad0712e223840b07b8a622515d3568303f39a45ae88216e70489aa730bb1d8` | MATCH |
| 16 | d2_04_resource_limits_profile_schema | `PMIRI_GD-R2-04_RESOURCE_LIMITS_PROFILE.schema.json` | `50f6baf808aa5c751028e26f3bbb9dc71cbff209338ae1dafbc15f584e4997ce` | MATCH |
| 17 | d2_04_fetched_content_lifecycle_schema | `PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json` | `11432ba0387c142d2ccd9e59411bbacbaa16dd044c04234dd75c23994acced1a` | MATCH |
| 18 | d2_05_integrated_contract | `PMIRI_GD-R2-05_INTEGRATED_DECISION_MODEL_AND_ADVERSARIAL_MATRIX_v0.1.md` | `6b1b901fb440731919ab63888801babe23f4e275e3ff5a0226eafeb99929a0e8` | MATCH |
| 19 | d2_05_integrated_envelope_schema | `PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json` | `c9e8d3793f1f2c8727c3936c2e776e4f9f654890c357960e486a805d753cd51c` | MATCH |
| 20 | d2_05_adversarial_matrix | `PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json` | `6e9b1112883ae467e3071d79cd24c60b41b99792811c0cdcb1ea0c6374173231` | MATCH |
| 21 | d2_06_decision_vocabulary | `PMIRI_GD-R2-06_DECISION_VOCABULARY_v0.1.md` | `624f1a9ad126257b731a65720af0f64fc766b8bcae1101b594619defb5ea0c74` | MATCH |
| 22 | d2_06_decision_vocabulary_schema | `PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json` | `1f9c40e45184b1540e38ed28c34cac3b91076c0da1b625413ea69451dc97d904` | MATCH |
| 23 | d2_07_policy_authority_contract | `PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_AND_FRESHNESS_CONTRACT_v0.1.md` | `c8d99592c98617c92014d18ac97f2d3a30cb62efa196e9da165b45d51719b269` | MATCH |
| 24 | d2_07_policy_authority_matrix | `PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json` | `fe43f938f71c46b3a41f7cb97f295f779ed79e8724a3ff8aea38fa5f0ae5e6fe` | MATCH |
| 25 | d2_07_policy_observation_schema | `PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json` | `461f4361f027aa9806763a859174f8e9cd1205157627cdbed8b5079bd8966fee` | MATCH |
| 26 | blocker_closure_recheck_report | `PMIRI_GD-R2_BLOCKER_CLOSURE_RECHECK_REPORT_v0.1.md` | `53a094e46e355c3672ed3e3010ea840dc886166b4db8ba03bf87ea5e78e59c70` | MATCH |
| 27 | independent_hard_recheck_protocol | `PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_PROTOCOL_v0.1.md` | `acddcbec55fb504592e1a93906f812ff5836e8be612dd3d54072e83d9b5cff63` | MATCH |
| 28 | candidate_index | `PMIRI_GD-R2_CANDIDATE_INDEX_v0.1.md` | `b913c24c60f71084f050a40fcf772434cf3397698c0c403450e582dbdf6f239b` | MATCH |
| 29 | independent_hard_recheck_report | `PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_REPORT_v0.1.md` | `bb27d868d7768948f282b390b5727d54b0e2bd816be3130dbe4cfb3f2f9027de` | MATCH |
| 30 | independent_reviewer_brief | `PMIRI_GD-R2_INDEPENDENT_REVIEWER_BRIEF_v0.1.md` | `f8f24b1334d31aac77e3c07494da2a6fd29f458accc8c89c1b4aab06fa5379af` | MATCH |
| 31 | independent_reviewer_decision | `PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.1.md` | `98fc160ab36b6a66dee0dfc8af3122fe163962dc31e187bc742eea0271bfba51` | MATCH |
| 32 | corrective_closure_report | `PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.2.md` | `65f06f5638f5656635b3829436e6902e2002570e74abae1d5cfd669b55ed2a93` | MATCH |
| 33 | cross_field_validation_rules | `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md` | `88f54734b4b22c43af2a87cdf66c69c17555814d641c5052ec951925d4d8a320` | MATCH |
| 34 | independent_recheck_commission | `PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.2.md` | `e642fd5032c33ff37acc3de03aa7467ac3fc08115e2287f76b60903f8dcd50f9` | MATCH |
| 35 | prior_hard_review_report | `PMIRI_GD-R2_HARD_CONTRACT_REVIEW_REPORT_v0.1.md` | `034646d5b88ee01636959c40d308436c722458f1ff145f56d1c577fa87137aa4` | MATCH |
| 36 | prior_hard_review_findings | `PMIRI_GD-R2_HARD_CONTRACT_REVIEW_FINDINGS_v0.1.json` | `30a17bd7bc6b31ba2226c32d88a69ef6a0b66e77eda0c1d9bba775f86fef1c91` | MATCH |
| 37 | independent_reviewer_decision_v0_2 | `PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.2.md` | `3788575def904314c85013015694b0650bed44287f8cef30fed1060671611529` | MATCH |
| 38 | corrective_closure_report_v0_3 | `PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.3.md` | `2b68ec409287d2da851410578914a2bad2c06d2f0824689d819eee879372aefd` | MATCH |
| 39 | cross_field_validation_rules_v0_3 | `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.3.md` | `243a9c3318b1a23a879fb4c605e51cc28fc3bc69bf4870b4831489981f4fa5ce` | MATCH |
| 40 | independent_recheck_commission_v0_3 | `PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.3.md` | `bac7f2dcdf1e0716e907fe10d5b9e41dbe4950f93cccef6247ead5d40b61b0d1` | MATCH |
| 41 | expected_outcome_schema | `PMIRI_GD-R2-05_EXPECTED_OUTCOME.schema.json` | `93e69b016bd0668cdbf1e0dc50db4028394fa7db07d90f9ac8f14e6ad9914592` | MATCH |
| 42 | network_canonicalization_profile | `PMIRI_GD-R2-04_NETWORK_CANONICALIZATION_PROFILE.json` | `1b254dc7be646ba6bd57344b69f53d5c17cc8d84df0ac207474897a3e45156dd` | MATCH |
| 43 | schema_resource_registry | `PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json` | `602ded0eca250fe498bc8ca9d798fa022483f42e41ebef341383cfa05c00f4a5` | MATCH |
| 44 | freshness_profile_self_check | `PMIRI_GD-R2-07_FRESHNESS_PROFILE_SELF_CHECK_v0.1.md` | `3e373a50e6dfb4b17159d9bc09df0c5c1cdc1204a5f238462d539ad6ecd00563` | MATCH |
| 45 | independent_reviewer_decision_v0_3 | `PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.3.md` | `972b4e2793fd67c46f1e858d8e893f54eb906a07b45055bc14688e43643ede12` | MATCH |
| 46 | corrective_closure_report_v0_4 | `PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.4.md` | `fc7542f878e51036e72941ff5bc860cc470a5ce279ae16dd7433dcbf8930bd13` | MATCH |
| 47 | cross_field_validation_rules_v0_4 | `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md` | `e9489d3160dde71d674922965315be2c98dfc8f4098a0a4bc366d28e5df52f63` | MATCH |
| 48 | independent_recheck_commission_v0_4 | `PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.4.md` | `00a0a84f674e7044740b8be85973f2032b962d06642eb474085aa45d3fff7cb7` | MATCH |

Accepted authority verification also passed. The Gate-C archive at
`PMIRI_ALL_DOCUMENTATION_CHECKPOINT_15/ARCHIVE_SOURCES/PMIRI_v1.0_Gate_C_Accepted.zip`
has SHA-256
`4b9057d38f3058e3c558af10034a2fbe918bcea5ebf1512f0afa40cea8a24aa7`, and
all `10/10` manifest-bound Gate-C members match. The D1 archive at
`authority_materialized/PMIRI_v1.1.1_Gate_D_R1_Accepted.zip` has SHA-256
`b4ea8dab0ad0dccb1e2a6b03cc99c8be7c0f5fe9f431db38f65a6c8f71466fbc`, and
all `14/14` manifest-bound D1 members match.

## Mechanical checks

| Check | Result |
|---|---|
| Current root D2 JSON parse | `23/23` parse |
| D2 schema files | `16` files, `16` unique `$id` values |
| Registry resources | `16/16` files exist and each file `$id` matches its registry URI |
| Schema `$ref` count | `126` total: `112` absolute PMIRI refs and `14` local fragment refs |
| Absolute PMIRI bases/pointers | Vocabulary base resolves to the registry file and all tested absolute fragments resolve |
| Freshness canonical payload | recomputed SHA-256 `604dd146196571cf7dd5d25eec7d8db066cebbeca07814ccfe647c9edd267d41`, matches matrix/self-check |
| Network profile self-excluding digest | recomputed SHA-256 `613209a8c1c03d6427872e2ed4e41722d950bcc8cd1409912296914916e7f212`, matches profile field |
| Adversarial scenarios | `34`: `17` positive and `17` adversarial; all 17 pairs present |
| Expected schema reference presence in matrix | `34/34` objects carry `expected_schema_ref` |
| Expected schema requiredness | `expected_schema_ref` is a property but is absent from the schema `/required` array |
| Provider-policy union | 10 tagged value branches exist; cross-field dimension/tag equality is stated |
| Runtime evidence | none; all matrix fixtures remain `fixture_id: null`, `runtime_status: BLOCKED` |

The mechanical result is therefore integrity-consistent but not contract-
consistent: the absolute-only registry assertion and expected-schema
requiredness assertion fail against the current schema text.

## Reassessment of IR-D2-01 through IR-D2-22

| Finding | Current status | Independent reassessment |
|---|---|---|
| IR-D2-01 | STRUCTURALLY_ADDRESSED | Gate-C lineage, source-evidence, context-intent, epistemic-ceiling and semantic-obligation refs/fingerprints are required; exact resolution remains documentary. |
| IR-D2-02 | STRUCTURALLY_ADDRESSED* | Operation, purpose, emission mode, downstream fingerprints and invalidation epoch are present; exact outbound/lifecycle equality remains open in IR-D2-25. |
| IR-D2-03 | STRUCTURALLY_ADDRESSED | Impact/action/visibility conditions, typed constraints and transformation output rules are present; no transformation was executed. |
| IR-D2-04 | STRUCTURALLY_ADDRESSED | Operation and purpose are closed in the current primary and nested fields, with fail-closed unknown handling. |
| IR-D2-05 | STRUCTURALLY_ADDRESSED | Capability observation epochs, decision observation requirements and material/profile fingerprints are present. |
| IR-D2-06 | STRUCTURALLY_ADDRESSED | Selected-target, proxy, TLS and terminal lifecycle conditions are present, subject to residual outbound binding status in IR-D2-26. |
| IR-D2-07 | STRUCTURALLY_ADDRESSED | State-dependent admission predicates, visibility values and legal transition edges are present. |
| IR-D2-08 | STRUCTURALLY_ADDRESSED | Closed state-to-action rows and trust/capability/integrated restrictions are present. |
| IR-D2-09 | FIX_REQUIRED | Typed lifecycle refs/fingerprints now exist, but purpose/origin and terminal-field equality is not representable across the current records; see IR-D2-25. |
| IR-D2-10 | STRUCTURALLY_ADDRESSED | v0.4 rules define continuous history, sequence, timestamps, terminal state and terminal event; no validator execution was performed. |
| IR-D2-11 | STRUCTURALLY_ADDRESSED | Nested capability purpose and lifecycle explicit operation use the closed vocabulary, with enclosing-operation equality stated. |
| IR-D2-12 | STRUCTURALLY_ADDRESSED | Profile ID/fingerprint fields are present and the corrected freshness payload hash matches independently. |
| IR-D2-13 | FIX_REQUIRED | Exact selected IP/family/TLS/destination/epoch formulas are stated, but outbound allow is not explicitly gated on resolved `binding_status=VALIDATED`; see IR-D2-26. |
| IR-D2-14 | FIX_REQUIRED | Scenario outcomes are exact in the matrix, but the schema does not require its own exact schema-reference field; see IR-D2-24. |
| IR-D2-15 | STRUCTURALLY_ADDRESSED | Current schema revisions and duplicate-field cleanup are consistent. |
| IR-D2-16 | STRUCTURALLY_ADDRESSED | Freshness profile self-check and matrix recomputation both produce the declared digest. |
| IR-D2-17 | FIX_REQUIRED | Typed outbound and lifecycle refs are present, but the final records do not carry all fields claimed by the exact equality rule; see IR-D2-25. |
| IR-D2-18 | FIX_REQUIRED | Mixed-DNS public-plus-denied sets are fail-closed, but the stated `DENIED_MIXED` rule also covers all-denied sets that cannot satisfy the required public selected target; see IR-D2-27. |
| IR-D2-19 | FIX_REQUIRED | Algorithm/version and epoch equations are now explicit and the profile digest matches, but URL scheme output and path/query canonicalization remain underspecified; see IR-D2-28. |
| IR-D2-20 | FIX_REQUIRED | The tagged union is closed and all matrix entries carry the field, but schema requiredness is incomplete; see IR-D2-24. |
| IR-D2-21 | FIX_REQUIRED | The registry maps all 16 schema IDs and absolute pointers, but 14 local refs contradict its absolute-only rule; see IR-D2-23. |
| IR-D2-22 | STRUCTURALLY_ADDRESSED | Ten per-dimension tagged branches and the exact `value_type = policy_dimension` cross-field rule are present; no provider observation was evaluated. |

`*` means the original finding's primary closure is present, while a current
residual is tracked separately below.

## Current independent findings

```yaml
- finding_id: IR-D2-23
  severity: BLOCKER
  status: OPEN
  area: absolute PMIRI schema URI registry and pointer resolution
  evidence_refs:
    - PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json#/base_uri_rule
    - PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json#/relative_reference_prohibited
    - PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json#/verification_requirements
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md §13 lines 391-399
    - PMIRI_GD-R2-05_EXPECTED_OUTCOME.schema.json lines 14-17,35
    - PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json line 26
  impact: The registry and v0.4 rules require every D2 $ref to be an absolute PMIRI URI, but 14 current refs are local #/$defs fragments. The current package therefore contradicts its own loader policy even though the local anchors are textually present.
  required_action: Convert all local refs to absolute PMIRI URIs rooted at the owning schema, or explicitly amend the registry to permit same-resource fragments; then rerun exact base and JSON Pointer resolution and refresh dependent hashes.
  runtime_boundary: No standards-complete schema validator or runtime loader was executed; this is a documentary resource-identity finding only.

- finding_id: IR-D2-24
  severity: BLOCKER
  status: OPEN
  area: closed expected-outcome schema binding
  evidence_refs:
    - PMIRI_GD-R2-05_EXPECTED_OUTCOME.schema.json#/required lines 30-30
    - PMIRI_GD-R2-05_EXPECTED_OUTCOME.schema.json#/properties/expected_schema_ref lines 41-42
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md §12 lines 376-382
    - PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json#/expected_outcome_contract/required_fields
  impact: Every current matrix instance includes the exact schema filename, but the schema permits a structurally valid expected outcome with that field omitted. The acceptance-bearing schema reference is therefore not closed at the schema boundary.
  required_action: Add expected_schema_ref to the expected-outcome schema required array and rerun all 34 matrix outcome checks.
  runtime_boundary: No scenario fixture or runtime expected-outcome validator was executed; all scenarios remain documentary and blocked.

- finding_id: IR-D2-25
  severity: BLOCKER
  status: OPEN
  area: exact integrated outbound/fetched-lifecycle equality
  evidence_refs:
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md §4 lines 87-100
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md §9 lines 296-304
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/properties/fetched_content_lifecycle_ref
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/properties/fetched_content_lifecycle_fingerprint
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties lines 24-44
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/required lines 7-7
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties lines 11-26
  impact: The integrated and outbound records now carry typed lifecycle refs/fingerprints, but the lifecycle record has no operation or purpose field, and the outbound record has no origin-binding, retrieval-visibility or separate admission/terminal fields. The rule therefore requires comparisons to values that are not present on both sides. Exact purpose/origin/lifecycle equality can vary by validator or be silently inferred.
  required_action: Add explicit lifecycle operation and purpose fields, and explicit outbound/integrated origin and visibility/admission bindings, or define an exact field-to-field mapping. Require equality of operation, purpose, origin, destination, admission state, visibility, terminal fingerprint and applicable epochs before external emission.
  runtime_boundary: No lifecycle record resolution, content admission, external emission or runtime equality check was performed.

- finding_id: IR-D2-26
  severity: BLOCKER
  status: OPEN
  area: outbound allow action and validated connection status
  evidence_refs:
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/binding_status line 88
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/allOf lines 102-112
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/allOf lines 49-71
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md §9 lines 228-257,267-292
  impact: The outbound schema and current cross-field rules constrain mixed-DNS and TLS conditions, but do not explicitly require the resolved connection binding referenced by an outbound ALLOW or ALLOW_WITH_CONSTRAINTS decision to have binding_status=VALIDATED. A binding carrying otherwise compatible selected/TLS fields can remain DENIED or STALE without an explicit final allow prohibition.
  required_action: Add an exact rule and schema condition that every outbound allow action resolves to binding_status=VALIDATED, a final MATCHED revalidation event, and equal final connection/policy epochs; reject all other binding statuses.
  runtime_boundary: No socket, DNS, TLS, revalidation, connection reuse or outbound decision execution was performed.

- finding_id: IR-D2-27
  severity: BLOCKER
  status: OPEN
  area: DENIED_MIXED all-denied address-set representation
  evidence_refs:
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md §9 lines 208-226
    - PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md lines 89-94
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/resolved_addresses lines 17-34
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/selected_target lines 35-44
    - PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json scenario D2-04-C
  impact: v0.4 defines DENIED_MIXED as applicable whenever at least one returned address has a DENIED_* status, including a set in which every address is denied. The connection schema always requires selected_target and requires its policy_status to be ALLOWLISTED_PUBLIC. An all-denied set therefore cannot be represented as the required typed denial record, while the matrix expects DENIED_MIXED for private-address denial.
  required_action: Define a typed no-approved-selection/denied-target branch, or make selected_target nullable when no allowlisted address exists, while preserving the rule that DENIED_MIXED can never produce an outbound allow action. Bind D2-04-C to the exact branch.
  runtime_boundary: No DNS lookup, address classification, resolver, socket or network request was performed.

- finding_id: IR-D2-28
  severity: HIGH
  status: OPEN
  area: network canonicalization target completeness
  evidence_refs:
    - PMIRI_GD-R2-04_NETWORK_CANONICALIZATION_PROFILE.json lines 8-32
    - PMIRI_GD-R2-04_NETWORK_CANONICALIZATION_PROFILE.json line 45
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties/normalized_target lines 18-22
    - PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md lines 30-58
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md lines 259-265,267-287
  impact: The pinned algorithm/version, host/port/IPv6/SNI rules and exact epoch equations are now present and the profile's self-excluding digest matches. However, the profile does not define normalized scheme output casing or path/query treatment beyond fragment and encoded-delimiter rejection, while normalized_target records only scheme, authority and optional path_class. Distinct parsers can therefore bind different canonical target representations or fetch different paths under the same authority.
  required_action: Specify scheme serialization and path/query percent-encoding, dot-segment, empty-path and query handling, or explicitly declare those components outside the canonical target; define the profile fingerprint input and rerun the profile-dependent equality checks.
  runtime_boundary: No URL parser, canonicalizer, redirect, DNS, TLS or fetch execution was performed.

- finding_id: IR-D2-29
  severity: MEDIUM
  status: OPEN
  area: capability observation value determinism
  evidence_refs:
    - PMIRI_GD-R2-02_CAPABILITY_FRESHNESS_INVALIDATION_CONTRACT_v0.1.md lines 18-28,61-62
    - PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json#/properties/observed_value line 14
    - PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json#/properties/capability_key line 13
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md §7 lines 158-174
  impact: The capability contract calls observed_value typed and treats capability facts as security-relevant, but the schema accepts any JSON value and the cross-field rules define no per-key value contract. A FRESH observation can therefore carry an emission-relevant capability claim whose documentary meaning is not closed.
  required_action: Define an exact versioned capability-key/value union or per-capability schemas, require key/value compatibility, and include the canonical typed value in the observation fingerprint.
  runtime_boundary: No provider/model/feature capability was queried or evaluated.

- finding_id: IR-D2-30
  severity: LOW
  status: OPEN
  area: trust-decision content-lifecycle vocabulary alignment
  evidence_refs:
    - PMIRI_GD-R2-01_PROVIDER_CONNECTOR_TRUST_REGISTRY_CONTRACT_v0.1.md lines 198-216
    - PMIRI_GD-R2-01_TRUST_DECISION.schema.json#/required lines 7-24
    - PMIRI_GD-R2-01_TRUST_DECISION.schema.json#/properties/content_lifecycle line 41
  impact: The trust-decision contract's output example fixes content_lifecycle to NOT_APPLICABLE, but the schema permits every lifecycle enum value and has no corresponding condition. This permits a trust decision to carry a content state that its own contract does not define, creating avoidable downstream interpretation ambiguity.
  required_action: Constrain trust-decision content_lifecycle to NOT_APPLICABLE, or document and cross-bind the additional lifecycle semantics explicitly.
  runtime_boundary: No trust evaluator, content lifecycle resolver or emission fence was executed.
```

## Boundary conclusion

The v0.4 candidate preserves the accepted Gate-C/D1 authority ceiling and
keeps implementation and runtime work blocked. The corrected freshness hash,
network profile hash, closed operation/purpose vocabulary, typed policy union,
state/action restrictions, event epoch equations and matrix coverage are
documentary strengths. They do not cure the open binding, schema-registry,
expected-outcome, all-denied representation or canonical-target gaps above.

## Verdict

FIX-FIRST

Implementation authorization remains `NOT_GRANTED`. Runtime authorization
remains `NOT_GRANTED`.
