# PMIRI — Documentation Handoff Index

**Version:** 0.1  
**Purpose:** Navigation for the documentation-only implementation handoff

## Current authority chain

```text
00_DOCUMENTATION_AUTHORITY.md
        ↓
Gate A accepted contracts
        ↓
Gate B accepted contracts
        ↓
Gate C accepted closure package
        ↓
GC-C1 evidence-hardening contracts
        ↓
Gate D R1 accepted security core
        ↓
Gate D R2 candidate authority bundle
        ↓
this handoff package
```

The handoff package cannot override an accepted authority file. It only
converts the accepted semantics into a bounded future implementation target.

## Read in this order

1. `PMIRI_GC-C1_GATE_C_FINAL_CONSISTENCY_AUDIT_v0.2.md`
2. `PMIRI_V1_SCOPE_LOCK_v0.1.md`
3. `PMIRI_V1_VERTICAL_SLICE_ACCEPTANCE_v0.1.md`
4. `PMIRI_AI_IMPLEMENTATION_BRIEF_v0.1.md`
5. `PMIRI_DOCUMENTATION_HANDOFF_CHANGELOG_v0.1.md`

## What this package establishes

| Question | Answer |
|---|---|
| What may be implemented first? | A small local, read-only evidence slice. |
| What is the first user-visible value? | Cited, bounded retrieval from local text. |
| What is forbidden in the first slice? | Cloud/provider access, migration, embeddings, agent actions and unapproved semantic changes. |
| What proves the slice? | VS-01 through VS-12 acceptance evidence. |
| Does this close Gate C evidence? | No. GC-C1 replay remains unexecuted and R-FC remains 0/17. |
| Does this authorize production implementation? | No. |

## Archive state

```text
Gate A = ACCEPTED
Gate B = ACCEPTED
Gate C = ACCEPTED
GC-C1 = DESIGN / EVIDENCE HARDENING
Gate D R1 = ACCEPTED
Gate D R2 = CANDIDATE / INDEPENDENT RECHECK REQUIRED
Production implementation = BLOCKED
```
