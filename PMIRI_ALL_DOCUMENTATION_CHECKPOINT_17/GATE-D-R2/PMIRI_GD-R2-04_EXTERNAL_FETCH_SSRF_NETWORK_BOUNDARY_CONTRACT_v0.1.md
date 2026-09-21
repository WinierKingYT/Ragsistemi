# PMIRI — Gate D Round 2 — External Fetch, SSRF and Network Boundary Contract

**Version:** 0.2  
**Status:** `CANDIDATE / DESIGN-ONLY`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Mission

Define the security boundary for URLs, remote fetches, connector requests,
attachments and outbound network access.

An external fetch is a separate security-sensitive operation. It is not
implicitly authorized by a read-only query, a provider trust assertion or a
caller-supplied URL.

## 2. Default policy

```text
outbound network = DENY BY DEFAULT
external fetch   = DENY unless exact operation is authorized
redirects        = DENY unless each hop is revalidated
private address  = DENY
ambient secrets  = DENY
```

The allowlist is destination- and operation-specific. A general “internet
access enabled” flag is not an acceptable policy.

## 3. URL normalization and scheme policy

Before DNS or connection, the fetch boundary MUST:

- parse the URL with one pinned parser;
- reject malformed, ambiguous or unsupported URLs;
- reject userinfo credentials in the URL;
- allow only explicitly approved schemes, with HTTPS as the default external
  scheme;
- reject `file:`, `data:`, `javascript:`, `gopher:`, `ftp:` and equivalent
  local/protocol-smuggling schemes unless a separate contract explicitly
  authorizes them;
- normalize hostname casing and canonical port representation;
- reject unexpected fragments, encoded delimiters and parser-confusion forms;
- bind the normalized URL to the exact operation and destination policy.

The parser used for policy evaluation and the connector used for the actual
request must agree on the normalized authority. Parser disagreement is a
fail-closed error.

The canonical parser/normalizer is the versioned profile
`PMIRI_GD-R2-04_NETWORK_CANONICALIZATION_PROFILE.json`, profile ID
`D2-NETWORK-CANONICALIZATION-001`, algorithm version `1.0`. It fixes
IDNA2008 UTS46 non-transitional 15.1 A-label output, lowercase host and SNI,
trailing-dot removal, RFC5952 IPv6 text, HTTPS-only port 443 normalization,
userinfo/fragment/encoded-delimiter rejection and UTF-8 input handling.
Every connection and outbound decision carries the exact profile ID and
fingerprint. A validator must not substitute its library's default URL or
hostname normalization.

## 4. Network address policy

After resolving the hostname, every returned address MUST be checked against
the current network policy. By default deny:

- loopback;
- private RFC1918 and equivalent private ranges;
- link-local and metadata-service ranges;
- unspecified, multicast and reserved ranges;
- IPv4-mapped or encoded forms that resolve into denied ranges;
- local Unix/socket or platform-specific local endpoints;
- addresses outside the explicit outbound allowlist.

The policy must evaluate both IPv4 and IPv6. A hostname with one denied
address among multiple answers is not safe merely because another answer is
public.

## 5. DNS rebinding and connection binding

To prevent DNS rebinding:

1. resolve the hostname before connection;
2. validate every returned address;
3. connect only to an approved resolved address;
4. retain the resolution and destination binding for that request;
5. revalidate on redirect, retry, connection reuse and authority change;
6. fail closed if the hostname resolves to a different policy result during
   the operation.

The connection record carries `resolution_set_status`. It MUST be
`ALL_ALLOWLISTED_PUBLIC` if and only if every returned address has
`policy_status=ALLOWLISTED_PUBLIC`; otherwise it is `DENIED_MIXED` and the
binding is `DENIED` or `STALE`. A public selected address does not override a
denied address elsewhere in the returned set, and `DENIED_MIXED` cannot
produce an outbound allow action.

An application-level hostname check alone is insufficient. The actual
connection target must be bound to the approved resolution.

## 6. Redirect policy

Redirects are untrusted input. Each hop MUST:

- be parsed and normalized again;
- pass scheme, hostname, address and allowlist checks;
- preserve or re-establish the exact purpose and material policy;
- reject HTTPS-to-HTTP downgrade;
- respect a small finite redirect limit;
- reject loops and repeated equivalent targets;
- produce a new destination binding when the authority changes.

No redirect may reach a private, local, metadata or unapproved endpoint.

## 7. Response and resource limits

The fetch boundary MUST enforce:

- connect, read and total wall-time limits;
- maximum response bytes;
- maximum decompressed bytes and compression ratio;
- maximum redirect count;
- maximum header and URL lengths;
- allowed content types;
- explicit handling of missing or contradictory content type;
- bounded concurrent fetch count;
- cancellation and teardown;
- no execution of fetched content.

Content type is a validation signal, not proof of safety. Bytes remain
untrusted until parsed, classified and provenance-bound.

The exact baseline profile is
`PMIRI_GD-R2-04_RESOURCE_LIMITS_PROFILE.schema.json`, profile
`D2-FETCH-LIMITS-001`:

```yaml
max_redirect_hops: 5
max_response_bytes: 10485760
max_decompressed_bytes: 52428800
max_compression_ratio: 100
max_header_bytes: 65536
max_url_length: 8192
connect_timeout_ms: 5000
read_timeout_ms: 15000
total_timeout_ms: 30000
max_concurrent_fetches: 8
```

The profile, authority, validity window and allowed content types are
fingerprinted. A limit breach maps to `action_result=DENY`,
`content_lifecycle=ABORTED` and `reason_class=RESOURCE_LIMIT_EXCEEDED` (or
`CONTENT_TYPE_DISALLOWED` for a type policy failure).

## 8. Attachment and fetched-content handling

Provider or connector attachments MUST enter a quarantine/validation boundary.
They must not be written into canonical truth or ingested as trusted evidence
without an explicit operation.

The lifecycle record is
`PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json`. Its allowed terminal
states are the canonical content-lifecycle enum. During D2, fetched bytes have
`retrieval_visibility=NONE`, `QUARANTINE_ONLY` or `TYPED_DATA_ONLY`; there is
no direct transition to canonical truth or ordinary retrieval. Admission as
typed data requires an explicit operation, origin binding, parser result,
classification reference and a permanent prohibition on instruction-like
content influencing policy or control.

The boundary must record:

- origin and destination binding;
- request and response fingerprints;
- content type and size observations;
- validation/parser result;
- malware/content policy result where applicable;
- classification and trust state;
- whether the bytes were admitted, quarantined, rejected or discarded.

Fetched content cannot issue PMIRI instructions merely because it contains
instruction-like text.

The corrected lifecycle schema revision is `0.2`. Every non-`NOT_APPLICABLE`
content state carries an admission predicate containing the explicit operation,
origin binding, parser result, classification result, validation result,
content-policy result and permanent instruction/control-influence prohibition.
`ADMITTED_TYPED_DATA` additionally requires a typed-data schema reference and
fingerprint. Visibility is state-bound: `QUARANTINED` means
`QUARANTINE_ONLY`, `ADMITTED_TYPED_DATA` means `TYPED_DATA_ONLY`, and
`REJECTED`, `DISCARDED` or `ABORTED` means `NONE`.

The only legal lifecycle transitions are:

```text
NOT_APPLICABLE      → QUARANTINED          FETCH_COMPLETED
QUARANTINED        → ADMITTED_TYPED_DATA  ADMISSION_APPROVED
QUARANTINED        → REJECTED             REJECTED
QUARANTINED        → DISCARDED            DISCARDED
QUARANTINED        → ABORTED              ABORTED
ADMITTED_TYPED_DATA→ DISCARDED            DISCARDED
ADMITTED_TYPED_DATA→ ABORTED              ABORTED
```

There is no transition to canonical truth, trusted control text or ordinary
retrieval content. The schema rejects other state/event pairs.

The lifecycle record is a continuous history. It MUST declare
`history_start_state=NOT_APPLICABLE` and `history_terminal_state`, and its
transition array MUST either be empty for `NOT_APPLICABLE` or contain a
continuous sequence `0..n-1`: the first `from_state` is the start state, each
next `from_state` equals the previous `to_state`, timestamps are
nondecreasing, and the final `to_state` equals both `history_terminal_state`
and `admission_state`. The terminal event is fixed by the terminal state:
`FETCH_COMPLETED`, `ADMISSION_APPROVED`, `REJECTED`, `DISCARDED` or `ABORTED`.
Disconnected, reversed, duplicated or post-terminal history is invalid.

## 9. Outbound allowlisting interface

The connection evidence is serialized by
`PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json`, including each
revalidation event; the derived outbound decision is serialized by
`PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json`.

The network enforcement layer consumes a typed decision:

```yaml
outbound_network_decision:
  decision_id: <stable id>
  operation: <provider_call|connector_fetch|attachment_fetch|external_fetch>
  purpose: <canonical purpose>
  destination_binding_ref: <exact destination>
  destination_identity_ref: <exact destination identity>
  normalized_target: <redacted safe target representation>
  connection_binding_ref: <connection binding with resolver/address/TLS evidence>
  connection_binding_fingerprint: <exact connection-binding sha256>
  selected_target_resolution_ref: <exact approved resolution entry>
  selected_target_ip: <exact approved IP>
  selected_target_family: IPv4|IPv6
  tls_identity_status: MATCHED|MISMATCHED
  tls_identity_fingerprint: <exact TLS identity-binding sha256>
  connection_epoch: <connection epoch>
  invalidation_epoch: <network-policy epoch>
  freshness_profile_id: <exact policy freshness profile id>
  freshness_profile_fingerprint: <exact policy freshness profile sha256>
  purpose_binding_ref: <purpose>
  trust_decision_ref: <D2 trust decision>
  capability_decision_ref: <D2 capability decision>
  limits_profile_ref: <resource-limits profile>
  authority_manifest_fingerprint: <accepted authority bundle fingerprint>
  action_result: ALLOW|ALLOW_WITH_CONSTRAINTS|DENY|REQUIRE_REVIEW|REQUIRE_REVALIDATION|LOCAL_ONLY
  content_lifecycle: NOT_APPLICABLE|QUARANTINED|ADMITTED_TYPED_DATA|REJECTED|DISCARDED|ABORTED
  fetched_content_lifecycle_ref: <required for content-bearing fetches>
  fetched_content_lifecycle_fingerprint: <required for content-bearing fetches>
  reason_class: <canonical typed reason>
  validity_ref: <SecurityDecisionValidity>
  decision_fingerprint: <sha256>
```

`action_result` is the permission-bearing field; content handling is recorded
separately in `content_lifecycle`. The network layer must not accept an
untyped boolean or a caller-provided “safe URL” assertion as authorization.

The corrected network schemas use schema revision `0.2`. The connection
binding MUST include a reference to the exact selected resolution entry, and
that entry MUST be `ALLOWLISTED_PUBLIC`. The validator MUST resolve the
reference and compare the selected IP/family/policy status against the
resolved-address list; a mere string claim is insufficient. `EXPLICIT_PROXY`
requires `proxy_identity_ref`; `DIRECT` and `DENY` must not carry one.

The connection binding also carries the exact destination identity, network
invalidation epoch, TLS expected/verified identity references and TLS identity
binding fingerprint. The outbound decision must equal the connection's
selected resolution reference, IP, family, normalized authority, TLS identity
fingerprint, destination identity and applicable epochs. `tls.sni` must match
the normalized authority host; when TLS is `MATCHED`, verified identity must
equal expected identity. Revalidation events are ordered and contiguous; a
redirect, retry, reuse, authority change or policy-epoch change requires a
new validated binding before allow.

Revalidation events are numbered `0..n-1` and carry prior/current epochs.
The first event is `INITIAL_RESOLUTION` and its prior epochs equal its current
baseline. For `REDIRECT`, `RETRY`, `CONNECTION_REUSE` and `AUTHORITY_CHANGE`,
the current connection epoch is prior connection epoch plus one and the
invalidation epoch is unchanged. For `POLICY_EPOCH_CHANGE`, the connection
epoch is unchanged and the invalidation epoch is prior invalidation epoch plus
one. The binding epochs equal the final event epochs, and outbound epochs
must equal the binding epochs. Any `MISMATCHED` or `DENIED` event makes the
binding non-validated until a new validated binding is produced.

An outbound decision with `ALLOW` or `ALLOW_WITH_CONSTRAINTS` requires
`tls_identity_status=MATCHED`; a mismatched TLS identity cannot reach an
allow action. The terminal `content_lifecycle` is required on every network
decision, and the `connection_epoch`, network-policy `invalidation_epoch` and
freshness profile ID/fingerprint are part of the decision validity binding.
For `connector_fetch`, `attachment_fetch` and `external_fetch`, the outbound
decision MUST also carry a fetched-content lifecycle reference and fingerprint.
The resolved lifecycle's state, visibility, origin, destination and terminal
fingerprint must equal the outbound values. `provider_call` is the only
operation that permits `content_lifecycle=NOT_APPLICABLE`, and it forbids a
fetched-content lifecycle reference.

The operation enum is closed. An unknown or unsupported operation is rejected
as `INTERNAL_CONTRACT_INVALID` and cannot fall through to a default network
path.

## 10. Fail-closed rules

D2 returns `DENY` or `REQUIRE_REVALIDATION` when:

- URL parsing is ambiguous;
- scheme or authority is not allowed;
- DNS cannot be validated;
- any address is denied or outside the allowlist;
- a redirect changes authority without a new decision;
- a response exceeds a resource limit;
- content type is disallowed or contradictory;
- credentials are missing, over-scoped or unexpectedly visible;
- network policy or trust/capability evidence is stale;
- teardown cannot be established.

## 11. Exit criteria

D2-04 is design-complete only when the connection-binding and network-decision
schemas, plus positive and adversarial cases, cover URL normalization,
private-address denial, DNS rebinding, redirects, content limits, attachments,
credential boundaries and outbound allowlisting.

This candidate does not declare D2 accepted.
