# PMIRI — Strict Project Assessment

**Assessment:** 2026-09-11  
**Verdict:** Architecturally serious; operationally unproven; not production-ready  
**Strict level:** Design maturity high, executable maturity low

## 1. What project is this?

PMIRI is intended to be a **personal, local-first, provider-neutral evidence and retrieval infrastructure**. It is meant to preserve source provenance and versions, derive claims and revisions, resolve authority/conflicts, retrieve evidence, compile bounded context and deliver that context safely to external model providers.

It is not primarily:

- a chatbot;
- a vector database wrapper;
- a prompt library;
- a normal RAG demo;
- a finished second-brain product.

The intended product is closer to a **trust and evidence runtime for model-assisted personal knowledge**, with retrieval and provider delivery as downstream consumers.

## 2. Hard verdict

If judged as an architecture/specification project, PMIRI is advanced and unusually disciplined.

If judged as software that currently works, PMIRI is weak: the core runtime is not authorized, not implemented as a production system, not isolated in a verified environment, and not behaviorally validated.

The project currently has more governance surface than executable surface. That is not automatically bad, but it creates a serious risk: the documentation can make the system appear closer to completion than it actually is.

## 3. Dimension scores

These are maturity ratings, not test scores.

| Dimension | Rating | Hard interpretation |
|---|---:|---|
| Problem definition | 8/10 | Clear, difficult and technically meaningful problem. |
| Semantic architecture | 8/10 | Gates A–C establish strong boundaries and invariants. |
| Evidence governance | 7/10 | Detailed design, but still mostly unexecuted. |
| Contract consistency | 6/10 | Improved materially, but prior contradictions prove the contract set is still fragile. |
| Executable runtime | 2/10 | No verified production runtime or end-to-end vertical slice. |
| Isolation/security proof | 1/10 | Attestation is absent; current preflight is blocked. |
| Behavioral validation | 0/10 | R-FC replay is 0/17 and no PASS exists. |
| Product readiness | 1/10 | Production implementation remains blocked. |

The project is not an 80%-complete product. A defensible overall product-readiness estimate is **well below 25%**, because the missing work is on the critical path rather than cosmetic backlog.

## 4. What is genuinely good

- The project recognizes that retrieval correctness is not enough; provenance, authority, conflict, historical meaning, disclosure and egress matter.
- The design explicitly prevents “Markdown says PASS” from being treated as evidence.
- The R-FC catalog includes positive and adversarial cases for all 17 defined obligations.
- The system distinguishes readiness from behavioral success.
- Fail-closed behavior, immutable fingerprints and independent review are treated as first-class requirements.

These are design strengths. They are not proof that the runtime satisfies them.

## 5. The severe weaknesses

### A. The central system does not yet exist as a verified system

The current work demonstrates that PMIRI can describe a safe runtime. It does not demonstrate that the runtime can ingest a document, preserve its truth state, retrieve it correctly, compile it, enforce its boundaries and produce a trustworthy result.

### B. The project is trapped behind its own gates

The governance is effective at preventing premature implementation, but the project now needs to convert design into executable evidence. More contracts will not solve the main problem. The next value must come from a real clean-room run and a minimal vertical slice.

### C. The security claim is currently theoretical

There is no verified network denial, credential denial, filesystem allowlist, deterministic runtime, resource enforcement, teardown proof or privacy attestation. The latest preflight is correctly `BLOCKED`.

### D. The benchmark is designed, not validated

The 17 R-FC obligations are only test intentions until replay produces sealed artifacts and an independent reviewer accepts them. Current behavioral evidence is **0/17**.

### E. Contract complexity is already producing defects

The first independent review found contradictory preflight record shapes, an invalid `PASS` vocabulary example and lifecycle/schema problems. These were repaired, but the incident is a warning: the specification itself has become a complex system that requires automated consistency checking.

### F. There is no demonstrated user value yet

No evidence currently shows that a real user can place documents into PMIRI and reliably receive better, safer, more traceable answers than with a simpler local retrieval pipeline. Until that is demonstrated, PMIRI is an engineering program, not a product.

## 6. Current project classification

~~~text
PROJECT TYPE:
  Trust/evidence runtime for personal model-assisted knowledge

CURRENT PHASE:
  Gate C accepted; GC-C1 evidence-hardening and preflight remediation

CURRENT REALITY:
  Design-rich, runtime-poor, verification-blocked

PRODUCTION STATUS:
  Not ready

PRIMARY RISK:
  Documentation maturity is being mistaken for executable maturity
~~~

## 7. What must happen next

1. Produce real clean-room isolation evidence, not another isolation contract.
2. Run the pinned preflight and preserve a sealed result. It may legitimately remain `BLOCKED`.
3. Build the smallest local vertical slice: one project, local text/Markdown input, provenance-preserving storage, retrieval, citation and bounded context output.
4. Replay a narrow subset of R-FC cases against actual behavior.
5. Only after evidence exists, begin Gate D security/privacy policy work in a way connected to the runtime.

## 8. Final judgement

PMIRI is a **strong safety-oriented architecture effort**, but calling it a good working product today would be inaccurate. Its intellectual/design quality is ahead of its implementation by a wide margin. The project deserves continued work only if the next phase is execution and measurement—not further expansion of the document system.

The most important transition is:

~~~text
SPECIFICATION OF TRUST
        ↓
EXECUTABLE EVIDENCE OF TRUST
~~~
