# PMIRI — V1 Scope Lock

**Version:** 0.1  
**Status:** `PROPOSED BOUNDARY / NOT YET ACCEPTED AS PRODUCTION SCOPE`  
**Purpose:** Define the smallest useful implementation target for a future AI development phase.

## 1. Scope decision

The first implementation target is not the complete PMIRI product. It is a
small local evidence slice that proves the core value chain:

```text
local text input
    → provenance-preserving record
    → bounded retrieval
    → EvidenceSet
    → citation-preserving context
    → local typed output
```

This slice is called `PMIRI-V1-S0`. It is an implementation target and an
acceptance boundary, not a claim that the current system already implements
these capabilities.

## 2. Included in PMIRI-V1-S0

### 2.1 Data boundary

- one local owner context;
- one or more explicitly named projects;
- UTF-8 Markdown or plain-text source files;
- immutable source bytes or an equivalent content-addressed source record;
- source identity, version identity, capture time and SHA-256 fingerprint;
- project isolation at the storage and retrieval boundary;
- synthetic test data for all automated fixtures.

### 2.2 Retrieval boundary

- exact or lexical retrieval over the declared local corpus;
- explicit project/collection constraint handling;
- deterministic ordering for equal-ranked results;
- no result outside the trusted request envelope;
- an explicit empty, unknown or partial result when evidence is insufficient;
- no fabricated evidence and no silent current-state claim from an incomplete
  candidate universe.

### 2.3 Evidence and context boundary

- EvidenceItem records with source and version lineage;
- stable citation anchors or equivalent span fingerprints;
- an EvidenceSet that preserves evidence status and conflict metadata;
- a provider-neutral bounded context artifact;
- a hard context budget or explicit bound;
- typed output that distinguishes supported, partial, unknown and denied
  outcomes.

### 2.4 Interface boundary

- one local programmatic or CLI entry point;
- read-only query and inspection operations;
- structured machine-readable output;
- human-readable rendering derived from the structured result;
- no external model/provider call in S0.

## 3. Explicitly excluded

The following are outside S0 and must not be added as “small conveniences”:

- cloud connectors or external ingestion;
- provider egress or model API calls;
- write-capable agent tools;
- unrestricted web or filesystem crawling;
- data migration from an existing personal corpus;
- dense embeddings, vector databases or reranking optimization;
- graph memory, multimodal extraction or autonomous query decomposition;
- final Gate-D policy implementation;
- encryption/key-management claims beyond documenting the future boundary;
- production deployment, multi-user tenancy or operational scaling;
- changing Gate-B truth/current-state semantics or Gate-C retrieval semantics.

## 4. Non-negotiable invariants

The future implementation must preserve these invariants even in the smallest
slice:

1. a locator is not authorization;
2. a later layer cannot widen the trusted request envelope;
3. provenance cannot be dropped during retrieval, compilation or rendering;
4. an unsupported answer cannot be upgraded into a supported answer by prose;
5. partial or unknown evidence remains partial or unknown;
6. conflicts cannot be silently removed to fit a budget;
7. a provider-neutral artifact cannot be relabeled as provider-specific or
   vice versa;
8. read-only operations cannot mutate canonical truth or user-domain state;
9. external calls are absent from S0, not merely “disabled by convention”;
10. the same fixture and inputs produce the same normalized structured result.

## 5. Technology decisions intentionally left open

The following decisions are not needed to begin the documentation handoff and
must not be invented by the implementing AI without an explicit decision:

- database engine;
- object-store implementation;
- embedding model;
- vector index;
- web framework;
- MCP transport implementation;
- external provider selection;
- deployment target.

The implementing AI may choose a temporary local representation only when it
is replaceable, documented and covered by the S0 acceptance tests.

## 6. Scope-change rule

Any request that adds an excluded capability, changes a named invariant or
changes a Gate-B/Gate-C semantic must stop implementation and create a scope
decision record. The AI must not absorb it into S0 as an “improvement”.

## 7. Promotion rule

S0 acceptance does not mean:

- Gate C replay passed;
- Gate D is complete;
- production ingestion is safe;
- external provider egress is authorized;
- PMIRI is production-ready.

It means only that the smallest local evidence value chain has met its own
declared acceptance criteria.

