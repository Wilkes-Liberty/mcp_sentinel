# Changelog

All notable changes to MCP Sentinel are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Live portable-policy deny (#150 / d.o. #3617702).** The attested
  bundle floor is now consulted on the live access path. Simulate
  already refused when the bundle named the operation, and a local
  deny could not be widened; `McpAccessChecker` (entity, create,
  config, JSON:API filter), the context schema document, GraphQL
  query/mutation gates, and governed raw SQL now call that same
  evaluation. Emergency deny and revoke of the active digest refuse
  live access. The client-facing reason is the stable code
  `policy_bundle_denied` (the digest stays on the audit row). Access
  results that consulted the floor carry `mcp_sentinel.policy_bundle`,
  invalidated on activate, revoke, rollback and emergency deny.

## [2.11.0] - 2026-08-17

### Fixed
- **Dashboard never reports all-clear before evidence is verified
  (#115 / d.o. #3616611).** The posture hero previously treated
  zero urgent-condition attention as "All clear" even when the
  audit hash chain had never been verified. Overall clear now
  requires a successful, non-stale verification. The dashboard
  distinguishes unknown, pending, stale, degraded, failed,
  unavailable and verified evidence states. A not-yet-verified,
  stale, failed or unavailable chain is a non-clear warning (or
  critical, when broken) with an actionable explanation that
  links to the audit log.

### Added
- **Portable policy bundles (#113 / d.o. #3616536).** A versioned
  bundle carries an immutable SHA-256 digest and an HMAC-SHA256 seal
  over that digest using the same audit-chain signing key as action
  manifests. Verify rejects invalid, revoked and expired documents.
  Activation attests the exact digest and keeps last-known-good for
  rollback. Simulate evaluates a candidate without executing; a local
  deny cannot be widened by an upstream allow. Revoke of the active
  digest arms emergency deny. Disconnected operation (no signing key)
  cannot mint or activate new authority. Provider-neutral: Drupal
  state is the only store. Every audit row cites the attested digest
  as `policy_bundle_digest` when a bundle is active (omitted when
  none is).
- **Off-hours and complete bulk-read anomaly signals (#116 / d.o.
  #3616612).** Administrators can define an operating-hours schedule
  (timezone, weekdays, start/end). A rule whose signal is `off_hours`
  fires on matching governed activity outside that window; a disabled
  schedule never fires. A `bulk_read` signal fires when distinct
  entity reads in the window meet the absolute threshold or a
  complete/near-complete ratio of the live collection. Existing
  count-based denied-access storm rules are unchanged. Hosted
  tenant/principal correlation remains out of scope.
- **Typed decision contract (#111 / d.o. #3616538, slice 1).**
  `McpDecision` is an immutable outcome plus a stable reason code,
  following `McpGovernanceReadinessReason`. Outcomes are `deny`,
  `allow`, `require_approval`, and `allow_with_obligations`.
  Obligations are valid only on `allow_with_obligations`. The
  approval gate can return the typed form (`decide()`) without
  changing who is gated: `requiresApproval()` and every existing
  call site keep today's allow/hold behaviour. No production path
  requires a sealed manifest.
- **Sealed action manifest (#111 / d.o. #3616538, slice 2).** When a
  gated operation is queued, the source may mint an HMAC-sealed
  `McpActionManifest` binding actor, OAuth delegation, normalized
  arguments, target type/id/uuid/revision, the active policy digest,
  preconditions, expiry and a single-use idempotency key. The seal
  uses the same audit-chain signing key the evidence guard fails
  closed on. A missing key stores nothing and does not change who is
  gated or what executes — the approval payload is still an unsealed
  string. Execution does not yet require a valid manifest.
- **Approval binds to one sealed manifest (#111 / d.o. #3616538,
  slice 3).** Approving a gated operation now requires a valid
  HMAC-sealed manifest: the seal is re-checked, expiry is enforced,
  the live target uuid/revision must still match, and the idempotency
  key is consumed once. The requester cannot approve their own
  request. Execution follows the sealed arguments, not a tampered
  payload. Config-plane actions are not a new gated class — only the
  operations already in the gate are bound.
- **Break-glass hardening (#111 / d.o. #3616538, slice 4).** A grant
  is HMAC-sealed and single-use. Uid 1 and any account that already
  holds an `is_admin` role cannot receive the role. A missing signing
  key refuses the grant. Changing break-glass settings is audited as
  `break_glass_configured`; use while elevated stays
  `config_save_break_glass`. An elevated operator cannot save or
  delete a policy profile and cannot turn `deny_publish` off.
- **Reviewer context (#111 / d.o. #3616538, slice 5).** The approve
  form shows the sealed action against the live target (operation,
  identity, field-level diff, obligations) before a decision is
  possible. A missing or invalid manifest hides the Approve action.
  Secret-looking config keys are redacted in the diff.
- **DLP as a classification-aware, tighten-only detector (#136 / d.o.
  #3617061).** A `dlp_patterns` row may declare an optional
  `classification` label. A hit of that pattern is data of that label:
  it may lower the effective egress ceiling for the rest of the
  response and is fully redacted when it exceeds the ceiling in force.
  It can never raise a ceiling, and it cannot invent one when none is
  set. Patterns without the key stay mask-only (the shipped defaults
  do not declare a label). GraphQL field results and Tool success
  context are scanned. JSON:API and REST field values, the context
  schema document, and governed drush SQL are named residuals
  (`dlp_jsonapi_unscanned`, `dlp_rest_unscanned`,
  `dlp_context_unscanned`, `dlp_drush_unscanned`) — there is no stable
  per-value rewrite hook on the first two, and the last two do not
  serialize entity field values. Classification type/field ceilings
  still refuse over-ceiling subjects on those surfaces.

## [2.10.0] - 2026-08-16

### Added
- **Secure-install verifier (#112 / d.o. #3616537).** `drush
  mcp-sentinel:verify` produces an evidence document for the claim that
  this install carries the secure, tenant-neutral floor. Posture checks
  always run (source contract, companions, keyed evidence, finite
  budgets, a role-bound policy, trust-role separation, no development
  fallback, tenant neutrality, classification). `--live` adds the
  hostile-input probes from the issue — allowed draft, denied
  publication, mass read, configuration change, live-content edit —
  without creating, updating or deleting content. Write gates are
  decided through the same `validate()`, access checker and
  unmoderated-redirect classifier the runtime uses. `skipped` fails the
  run; `n/a` does not. `--json` records module and Drupal versions, a
  secrets-redacted config digest, per-check outcomes and the managed
  residuals (prompt injection, operator trust). Persist-path proof of
  the same gates stays in the kernel suite against `config/install`.
  See `docs/verification.md`.

## [2.9.0] - 2026-08-15

### Added
- **Classification labels and per-surface egress ceilings (#109 / d.o.
  #3616540, part 2).** The source-side half of P4.8: which data classes may
  leave through which destination. A destination is the pair (server-resolved
  policy profile, governed surface); the governed drush SQL command becomes a
  first-class `McpGovernedSurface` case (`drush`) beside `tool`, `context`,
  `jsonapi` and `graphql`. Classification is configuration, not content
  inspection: `mcp_sentinel.settings` gains an ordered site-defined vocabulary
  (`classification_labels`, shipped `public < internal < restricted`), a
  global `classification_map` (rows labelling an entity type, optionally one
  bundle, optionally one field; unlabelled data carries the lowest label; the
  shipped map labels the identity/credential types the default profile
  already denies `restricted`), and `context_schema_label` (the schema
  document is metadata, `internal` by default). Policy profiles gain
  `egress_ceilings` — the highest label the profile may receive per surface;
  an absent surface key is no ceiling, so **an empty map or empty ceilings
  change nothing** (proven by an explicit regression test) and the mechanism
  ships dark until an operator labels data and sets ceilings. Enforcement
  reuses the part-1 seams and only ever denies more: entity `view`/`view
  label` access (evaluated after every hard P0.4 deny, which keeps winning),
  JSON:API filter access (refused type-wide when any row of the type exceeds
  the ceiling — a relationship-path filter is a value oracle), field view
  access and the GraphQL results alter (an over-ceiling field takes the same
  `[REDACTED]` placeholder as a redacted one), the JSON:API request seam
  (an over-ceiling routed resource type is refused for every method before
  the controller runs — a write echoes the entity) and the response seam
  (an over-ceiling type in `data`/`included` that survived to serialization
  is refused; an undecodable body under a ceiling is refused too), the raw-SQL
  guard (a table of an over-ceiling entity type is refused; over-ceiling
  fields are refused as columns like redacted ones), and the context endpoint
  and site-context tool (refused below the schema label; over-ceiling bundles
  are not described). Every HTTP refusal carries the stable structured code
  `classification_egress_denied` (403, JSON:API error document); every denial
  writes one bounded `classification_egress_denied` audit row per subject per
  request naming surface, profile, entity type/bundle/field, the two labels,
  the caller's declarations and the site/environment origin — never a value.
  A northbound request may declare `X-MCP-Declared-Ceiling` (narrow-only: the
  effective ceiling is the lower of the profile's and the declared; declaring
  higher changes nothing; malformed or unknown declarations narrow to the
  lowest label) and `X-MCP-Declared-Destination` (recorded in evidence only)
  — the wire contract drupal-mcp-connector #179 binds northbound; attested
  destinations remain the hosted residual. Ceiling-dependent access results
  vary by `route` and by the declared-ceiling header. Outside every governed
  surface the profile's strictest ceiling applies; a label outside the
  vocabulary counts as the highest when it describes data and as the lowest
  when it names a ceiling. A status-report WARNING
  (`mcp_sentinel_classification_ceilings`) names role-bound profiles that set
  no ceilings while data is labelled above the floor. Both forms grew:
  a Classification section (vocabulary, schema label, a row editor for the
  map) on the settings form and an Egress ceilings tab (one select per
  surface) on the policy-profile form. Update 10021 seeds the settings keys
  and backfills `egress_ceilings: {}` on every existing profile so exported
  configuration round-trips without drift and no read decision changes on
  upgrade.

### Changed
- **The dashboard's denial rollup counts every refusal the module writes.**
  `read_budget_denied`, `classification_egress_denied`, `config_write_denied`,
  `raw_sql_denied` and `evidence_veto` join `denied_access` and
  `rate_limit_exceeded` in `McpMetrics`; the top-agents query builds its
  placeholder list from that constant instead of a fixed pair that silently
  under-counted (#109 / d.o. #3616540).

## [2.8.0] - 2026-08-15

### Added
- **Evidence-required action veto (#110 / d.o. #3616539).** Policy profiles
  gain `evidence_required_actions` (empty by default — opt-in per profile):
  a governed mutation in a listed action class (`entity_write`,
  `entity_delete`) executes only when its evidence can commit to the *keyed*
  audit chain. Before the mutation, the new `mcp_sentinel.evidence_guard`
  refuses the action outright — with a rollback-surviving `evidence_veto` row
  and a stable reason code — when the chain is absent
  (`evidence_chain_missing`), auditing is disabled
  (`evidence_audit_disabled`), or the configured signing key does not resolve
  (`evidence_unkeyed`); no fallback to unkeyed integrity or best-effort
  logging satisfies the class. When the action may proceed, an
  `evidence_precommit` row — correlation id, principal, the validated OAuth
  consumer client id, the caller's `X-Request-Id`, policy digest, decision,
  and target — is appended inside the same transaction as the mutation, so
  both become durable together or neither does: an evidence store outage or
  append timeout aborts the save, a save that fails after its precommit
  takes the precommit down with it (no orphaned evidence), and the signing
  key is re-checked after the append so signing that degrades mid-request
  aborts the transaction too. The
  post-save `entity_save` / `entity_delete` row is the execution receipt,
  completing the precommit's correlation id. A receipt that fails once the
  mutation is already durable is recorded — exactly once per correlation id —
  in a reconciliation ledger and refused to the caller as explicit
  `evidence_uncertain`, never reported as a proven success; cron retries the
  ledger, reconciled receipts are appended marked as such, and pending
  entries raise a status-report error until they drain — visible even with
  governance disabled. Update 10020 backfills the key (empty) on existing
  profiles so exported configuration round-trips without drift.

## [2.7.0] - 2026-08-14

### Security
- **Read budgets are finite by default (#109 / d.o. #3616540, part 1).**
  Rate, result-count, and response-size mechanisms existed but shipped
  unlimited (`0`) defaults, and two governed read channels were unmeasured —
  no mass-read/exfiltration floor. A profile budget of `0` now resolves to
  the finite defaults in `mcp_sentinel.settings:read_budget_defaults`
  (500 results, 8 MiB, 600 requests/60 s, 120 collection pages/60 s); an
  explicit finite profile value always wins. On the governed JSON:API seam,
  every request consumes a per-principal request budget and collection reads
  consume a windowed page budget (429 with stable reason codes
  `read_budget_exceeded` / `page_budget_exceeded`), an absent `page[limit]`
  is pinned when the cap is below JSON:API's default page size, and a new
  response subscriber refuses over-budget governed JSON:API/GraphQL bodies
  with a 413 (`response_size_cap_exceeded`). The governed raw-SQL drush
  channel uses the same effective caps. Denials write bounded, non-sensitive
  `read_budget_denied` evidence rows. Setting
  `require_finite_read_budgets: false` is the explicit non-production
  override: it restores `0 = unlimited` and raises a permanent status-report
  warning, so a secure-install verification cannot pass with the override
  active. Governed GraphQL requests consume the same per-principal request
  budget, and both HTTP seams admit a GraphQL request under either governed
  scope (`mcp_read` or `mcp_write`) — the verb cannot select the scope on a
  shared POST endpoint, and requiring one fixed scope would refuse
  write-only tokens before the mutation gate or skip measuring their
  responses. The `/drupal-mcp/context` schema document consumes the same
  shared profile-wide request bucket. Flood accounting pins the uid as the flood identifier: the
  default identifier is the client IP, which would have let IP rotation
  multiply a principal's quota. Part 2 of d.o. #3616540 (classification-aware
  egress destinations) is tracked on the same issue.

### Changed
- `McpRateLimiter` and `McpExfiltrationGuard` now take the new
  `mcp_sentinel.read_budgets` resolver as a constructor dependency, and the
  guard exposes `effectiveResultCap()` / `effectiveResponseSizeCap()` for
  display surfaces.

## [2.6.0] - 2026-08-14

### Fixed
- **Provisioned consumers can actually mint tokens (#126 / d.o. #3616862).**
  `mcp-sentinel:agent-provision` never set `grant_types` or simple_oauth's
  default user, so its consumers satisfied the readiness contract yet failed
  every token request (`unsupported_grant_type`, then an "invalid default
  user" 500). The provisioner now enables the client_credentials grant and
  binds the tier account as the consumer's default user.

### Added
- **Declared agent principals with `mcp-sentinel:agent-reconcile`.**
  Consumers are content entities: database refreshes and copies silently
  destroy per-environment principals. Environments now declare their tiers in
  `mcp_sentinel.settings:agent_provision_tiers` ("<tier>:<env>" entries,
  typically injected per environment via a settings.php override), and the
  new command re-provisions every declared principal idempotently — wired
  into deploy and refresh tooling, a wiped principal heals on the next run.
  A declared entry that cannot be reconciled fails the run loudly; secrets
  remain outside (deploy tooling reconciles those separately).

## [2.5.0] - 2026-08-14

### Added
- **Governed composite-child creation (#122 / d.o. #3616669).** Paragraphs
  cannot be created over JSON:API at all upstream — their access handler
  allows creation only in HTML form context and stays neutral for API
  formats, collapsing to 403, so the connector's create-then-reference flow
  could never build paragraph pages. When a request is governed and its
  policy profile permits writes for the type, the create-access hook now
  grants creation of composite-child entity types (those declaring a
  revision parent). Denied types and the write gate still forbid first;
  ungoverned traffic and non-composite entity types are unchanged, and the
  referencing host save runs the full governance stack.

### Security
- **One write-precondition boundary for every governed write channel
  (#108 / d.o. #3616541).** Content locks and version preconditions were
  checked only inside the governed Tool plugins; JSON:API, GraphQL, and
  direct governed saves could bypass an active lock or silently overwrite a
  concurrent change. Every governed mutation of an existing entity —
  relationship-only writes, translations, and deletes included — now runs
  one shared contract: an active lock held by a **different** server-resolved
  principal denies the write and the delete (`content_lock_conflict`), and a
  save whose loaded copy is no longer the stored default revision is refused
  instead of overwriting the concurrent change (`stale_version_conflict`).
  Validated seams get a 422 via the new `McpWriteConflict` constraint; the
  unvalidated seam aborts with a rollback-surviving evidence row. Lock
  ownership is bound to the authenticated actor — the acting principal's own
  lock never blocks it, and the Tool plugins now use the same owner-aware
  check (bulk delete included, which previously skipped locks entirely).
  Ungoverned human traffic is never gated.

### Changed
- **The `entity_save` audit row is written after the save commits, not at
  presave.** A row is no longer recorded for a save that aborts (evidence of
  writes that never happened), the row's id is the real entity id for
  creates, and governed updates carry an execution receipt: the checked lock
  state, the loaded revision the precondition was verified against, and the
  final target revision.

### Fixed
- **Refusal evidence now survives the storage rollback.** The in-place-denial
  row from the unmoderated forward-revision gate (and every new
  write-precondition refusal) is written via a post-transaction callback:
  the abort rolls back the enclosing entity transaction, which previously
  discarded the evidence row along with the save.
- **Human publication authority preserved for already-published unmoderated
  content (#107 / d.o. #3616542).** A governed agent edit of an
  already-published entity with no moderation workflow no longer mutates the
  live revision (previously the edit landed in the live default revision and
  the presave backstop then forced the entity unpublished — content changed
  and taken down in one save). Revisionable types store the edit as an
  unpublished forward (non-default) revision: the live revision is unchanged
  and stays published, and an `unmoderated_forward_revision` evidence row
  names both revisions. Types that cannot carry a forward revision are
  refused with a stable message — a 422 on validated seams (JSON:API, REST,
  forms), an aborted save plus an `unmoderated_in_place_denied` evidence row
  on the unvalidated seam. Pure takedown (unpublish) and ungoverned traffic
  are unchanged.

## [2.4.0] - 2026-08-13

### Security
- **Fail-closed governed source contract (#106 / d.o. #3616543).** Governed
  Tool, context, JSON:API, and GraphQL product paths now share one typed
  readiness decision and deny when required server/bridge/OAuth/audit/Tool
  registration or designated Consumer→active owner→role-bound policy wiring is
  missing. Ordinary human Drupal traffic remains outside this boundary.

### Added
- **Bounded authenticated readiness endpoint.** `GET /drupal-mcp/readiness`
  reports `contract_ready` plus a stable non-secret reason. The response
  explicitly does not claim policy effectiveness, verified evidence, or
  overall posture.
- **Rollback-safe Tool and agent provisioning.** Production setup requires
  OAuth by default and preflights every Tool; agent provisioning owns the
  Consumer/account/profile designation but never creates or rotates secrets.
- **CI: No AI attribution gate.** Pull requests fail when commits, the
  PR title, or the PR body credit AI with authorship (shared Wilkes & Liberty
  drop-in). Covers server-side paths that local hooks cannot see.

### Fixed
- **PHPStan: `McpAuditLogger::verifyChain()` return shape.** Document the full
  `audit_chain` `verify()` array (including seal/verified_from keys).
- **CI: the attribution gate no longer fails on clean commits.** The stripper
  compared each commit message against a copy that had gained a trailing newline,
  so every commit looked modified and the run ended with `strip count > 0 but tip
  unchanged`.


### Changed
- **CI: the attribution check is now the shared workflow.**
  `.github/workflows/attribution.yml` becomes a thin caller pinned to
  `Wilkes-Liberty/shared-ci@v1`, and the vendored `.github/scripts/` copies are
  removed. One implementation for every repository makes copy drift structurally
  impossible instead of merely detectable. The trust property is unchanged:
  the scripts that judge a pull request are fetched from the shared repository
  at the exact commit the pin resolved to, so a pull request still cannot
  supply the code that decides whether it passes.


## [2.3.0] - 2026-07-31

### Security
- **Break-glass conduct audit (#94 / d.o #3614177).** Config saves made while a
  live `mcp_admin` grant is active are audited as `config_save_break_glass`
  (object name, changed key names only, grant id, acting uid), including the
  self-concealing case of setting `audit_enabled: false`. Ordinary admins
  without a grant are unchanged. If the audit write fails, the save is refused.
- **Live-grant posture revalidation (#89 / d.o #3614165).** On cron, if
  `mcp_admin` is missing, `is_admin`, or holds allowlist extras, all active
  grants are force-revoked with audit reason `role_posture_unsafe`. Narrower
  shells alone do not force-revoke.

### Added
- **People → Roles warning for `mcp_admin` (#91 / d.o #3614166).** Editing the
  break-glass role shows that it is time-boxed elevation, lists the allowlist,
  and links to the Status report.

### Changed
- **Documented empty/narrow break-glass edge and dual-edit rule (#92, #93 /
  d.o #3614167, #3614168).** Approval README and CONTRIBUTING state that a
  subset (including empty) still grants with Status WARNING only, and that
  `ALLOWED_PERMISSIONS` must stay identical to the optional role YAML (kernel
  test remains the blocking check).

## [2.2.0] - 2026-07-31

### Upgrading

**`drush mcp-sentinel:break-glass` will now refuse on sites whose `mcp_admin` role is
`is_admin` or holds permissions outside the shipped allowlist.** Previously it granted
regardless. Read this before you need it, because the moment you find out otherwise is an
emergency.

That refusal is the point — a time-boxed "emergency" role that silently means *every*
permission was never a bounded control — but it does mean break-glass stops working until
the role is corrected. Check the status report after upgrading: it now reports an ERROR for
an `is_admin` or over-permissioned `mcp_admin`, and a WARNING when the role is missing
shipped permissions.

The module ships a correct role in the approval submodule's `config/optional`. Note that
`config/optional` **will not overwrite an existing role**, so a site that already has
`mcp_admin` must reconcile it by hand — the shipped YAML is the reference, and it must stay
identical to `McpBreakGlassManager::ALLOWED_PERMISSIONS`.

### Security
- **Break-glass grant-time permission allowlist (#87).**
  `McpBreakGlassManager::ALLOWED_PERMISSIONS` is the elevation ceiling. Grant
  refuses when `mcp_admin` holds any permission outside that set (including
  `approve mcp sentinel operations`). A proper subset still grants. The optional
  role YAML must stay identical to the constant.
- **Status report drift for `mcp_admin` (#88).** ERROR when the role holds
  allowlist extras (same refuse as grant); WARNING when it is missing shipped
  permissions (incomplete operator shell). Missing role and `is_admin` remain
  ERROR.

### Added
- **Enumerated `mcp_admin` break-glass role (approval submodule) (#78).** The
  role is no longer left to the site as an `is_admin` superuser. Optional config
  ships a non-admin role with five permissions: access administration pages,
  view the administration theme, access site reports, view mcp sentinel audit
  log, and administer mcp sentinel. **Excluded by design:** approve mcp sentinel
  operations (separation of duties — a standing second person holds approve),
  and every escape-hatch permission the default policy forbids. Agent capability
  changes stay on the policy profile, not this role.

### Fixed
- **Break-glass grants fail closed when `mcp_admin` is `is_admin` or missing
  (#78).** Grant refuses with an explicit message; the status report reports
  ERROR. A time-boxed "emergency" role that silently means every permission is
  not a control.
- **`McpAuditLogger::verifyChain()` PHPStan return shape.** The `@return` now
  matches `AuditChainLoggerInterface::verify()` (includes `reason` and the
  `unkeyed_*` keys). Callers already treat the shape as growing; the sealed
  old shape failed static analysis against current audit_chain.

## [2.1.0] - 2026-07-30

### Added
- **Environment-scoped role-permission acknowledgements.** A grant that is
  legitimate on one environment and a violation on another can now be recorded
  as `role_id:permission@environment` (for example
  `mcp_config_editor:administer site configuration@dev`). Unscoped
  `role_id:permission` entries keep working on every environment. The
  environment name is read from `$settings['mcp_sentinel.environment']` in
  settings.php — never from config — so a grant allowed on one environment
  cannot travel with a config export. With no environment declared, a scoped
  acknowledgement does not apply and the violation is reported (fail closed).
  `VIOLATION_IS_ADMIN` stays outside this: an is_admin role cannot be
  acknowledged into compliance.
- **`SECURITY.md`** with a private disclosure route. Notes that Drupal Security
  Team advisory coverage is not yet in place, so reports go to the maintainers
  for now.
- **`/.github` is `export-ignore` in `.gitattributes`**, so Actions workflows no
  longer ship inside the drupal.org release tarball.

### Changed
- **Rewrote `CONTRIBUTING.md` for a public project.** It previously contained
  only an internal Jira-key branch/commit policy and a pointer to a private
  repo. Contributors now get coding standards, tests, changelog, and security-
  reporting guidance modeled on the other published modules. Internal tracker
  keys stay out of public history.

### Fixed
- **The 2.0.0 upgrade no longer takes the site down when `audit_chain` is not already
  enabled.** `mcp_sentinel.audit_logger` held a required reference to
  `audit_chain.logger`, so the natural sequence —

  ```bash
  composer require drupal/mcp_sentinel:^2.0
  drush updatedb
  ```

  — put the new code on the site before anything could install the dependency. The
  container then could not compile:

  ```
  The service "mcp_sentinel.audit_logger" has a dependency on
  a non-existent service "audit_chain.logger".
  ```

  The front end returned 500 and drush could not be used to recover, because drush needs
  the same container. Rolling back made it worse: at 1.13 `audit_chain` is only a
  transitive requirement, so `composer require ^1.13` removed it. Anyone running a
  routine `composer update` followed by `drush updatedb` in a deploy took production
  down, with an error naming a service rather than a module to enable.

  Four changes, because documenting the ordering is not a fix:

  - the service reference is optional (`@?audit_chain.logger`), so the container builds;
  - `McpAuditLogger` fails **closed** — a governed write with no chain throws naming the
    module, rather than succeeding unaudited. A governance module that quietly stops
    recording is the failure it exists to prevent;
  - `hook_requirements()` reports the missing module at ERROR on the status report;
  - `drush updatedb` self-heals: whichever update hook is reached first installs
    `audit_chain`. Update 10016 does it before migrating (it runs earlier and used to
    throw, which would have stopped the self-heal ever reaching the sites that needed
    it); update 10017 covers sites with no legacy audit table for 10016 to migrate.

  `docs/UPGRADE.md` documents the ordering as well, for anyone landing 2.0.0 or 2.0.1
  specifically. A new kernel test installs the module without `audit_chain` and asserts
  the container compiles and every path fails honestly — the state is reproduced rather
  than described.
- **Update 10016 no longer leaves the moved audit settings behind as silent
  no-ops.** It copied `audit_hash_key`, `audit_encryption_profile` and
  `siem_enabled` into `audit_chain.settings` but left the originals in
  `mcp_sentinel.settings`. Nothing read them; the settings form already wrote
  straight to `audit_chain.settings`. Editing the leftovers — or a config
  export that still contained them — looked like a successful key rotation and
  was not. 10016 now clears them after the copy; a new update 10018 clears
  them for sites that already ran 10016; they are gone from the install YAML
  and the config schema. The form still presents SIEM streaming (and the hash
  key / encryption profile) under Audit Logging — that is the right place for
  the operator — and records them only in `audit_chain.settings`.
  `getEditableConfigNames()` now declares `audit_chain.settings` so the form
  matches what `submitForm()` actually writes.
- **PHPStan is green again on `1.x`.** The workflow installs `phpstan/phpstan:^2` and
  `mglaman/phpstan-drupal:^2` unpinned, so a new release started reporting eight errors on
  code nobody had touched — a green badge that decayed on its own rather than a regression
  anyone introduced. Narrowed access-result types in tests, removed always-true
  `assertIsArray()` calls, and dropped a dead `?? []`.

## [2.0.1] - 2026-07-30

### Changed
- **`composer.json` now declares `"php": ">=8.3"`.** It previously specified no PHP
  constraint at all, so the effective floor came only from whatever core happened to
  require, leaving the supported surface implied rather than stated. Composer will now
  refuse an install below 8.3 with a clear message instead of failing further down the
  dependency graph.

### Fixed
- **The governed raw-SQL command could not work on a site with a table prefix.**
  `McpRawSqlGuard` builds its allowlist from `TableMappingInterface::getTableNames()`, which
  returns *logical* table names carrying no prefix. `McpSentinelSqlCommands::sqlQuery()` then
  executed the operator's statement literally, and Drupal applies the site's table prefix to
  `{table}` syntax and to nothing else.

  So on a prefixed install there was no input that worked: an unprefixed statement passed
  governance and then failed to execute, and a hand-prefixed one was refused as an unknown
  table. The command now rewrites the entity tables the guard resolved into `{table}` form
  before executing, so the same operator input works on prefixed and unprefixed sites and
  still matches the allowlist. Single-quoted literals are copied through untouched, using
  the same pattern the guard uses to blank them, so `WHERE title = 'from node_field_data'`
  is left alone. A table the rewrite cannot brace — identifier quoting, which the guard
  strips before its own check — is a refusal rather than a passthrough.

  This surfaced as two drupalcode-only test failures. Drupal's kernel tests apply a table
  prefix on MySQL but isolate SQLite with an attached database, where an unprefixed name
  still resolves — so the suite passed on every SQLite venue and failed only where the
  defect was real.

- **`readonly` injected services were a fatal on every supported PHP below 8.4.**
  `McpWebhookWorker` and `McpApprovalDecisionForm` declared their injected services
  `readonly`. Both inherit `DependencySerializationTrait` from a parent — `PluginBase` and
  `FormBase` — and on PHP < 8.4 that trait's `__wakeup()` cannot reinitialize a readonly
  property declared in a child class, because it is out of the declaring scope. A queue
  worker is serialized into the queue and woken on the other side; Drupal caches form
  objects and unserializes them on rebuild. So the database connection, HTTP client and
  approval executor came back unusable at the point of use rather than at the point of the
  mistake. `menu_autopilot` 1.0.1 fixed the identical defect on a form.

  This had been latent: the property widening that made these `protected` (fixing the
  companion "does not support private properties" rule) is what let the readonly rule
  become visible, and it only reports on PHP below 8.4 — which is the whole supported range
  below the current ceiling.

- **The `mcp_sentinel_server` unit suite errored on the entire Drupal 10.6 lane.**
  `ToolScopeResolverTest` carried `#[DataProvider]` and `#[Group]` attributes with no
  matching annotations. Drupal 10.6 pins PHPUnit to `^9.6`, which predates PHP 8 attributes
  and ignores them rather than erroring — so it collected the test with no data sets and
  called a three-argument method with none:
  `ArgumentCountError: Too few arguments ... 0 passed and exactly 3 expected`. Four kernel
  tests in the submodules were likewise missing `@runTestsInSeparateProcesses` next to the
  attribute. All six now carry both spellings.

  `^10.6` is a declared support claim, and this suite has never passed there. Nothing could
  see it: GitHub did not run the submodule suites at all, and the drupalcode previous-major
  lane has never built.

- **Expired break-glass grants were never revoked on SQLite sites, and nothing said so.**
  `McpBreakGlassManager::reapExpired()` selected the grants to revoke with
  `->condition('revoked', FALSE)`. An entity query passes its condition value to the
  database layer unchanged, and only the pgsql driver casts booleans there (working
  around [PHP #48383](https://bugs.php.net/bug.php?id=48383)). SQLite does not: a PHP
  `FALSE` binds as a string, becomes `''`, and `revoked = ''` matches no row whose stored
  value is `0`. MySQL hid the same defect by coercing `''` to `0`.

  So on SQLite the cron reaper found nothing, revoked nothing, raised no error, and the
  time-boxed `mcp_admin` role stayed granted indefinitely — an expiry mechanism reporting
  success while doing nothing. The second occurrence failed the other way:
  `hasOtherActiveGrant()` used the same condition, so it answered "no other grant" every
  time, and a user who renewed a grant before the first lapsed had the role pulled out
  from under the renewal. Both now bind the stored integer.

  Neither had ever run anywhere. `McpBreakGlassTest` errored on a container problem
  before reaching its assertions, and the GitHub test lane does not run the submodule
  suites at all — so the one venue that could have caught this was reporting a different
  failure instead. The overlapping-grant case had no test; it has one now.

- **The drupalcode pipeline was red on `1.x` and on the released 2.0.0 tag.** Four of the
  six failing jobs are addressed here. `phpcs` reported one
  `Squiz.Arrays.ArrayDeclaration.CloseBraceNewLine` in `McpRoleAssertions`. `cspell`
  reported twenty issues from vocabulary the raw-SQL work introduced; the real terms are
  now in the project dictionary, and one coinage in the update-hook message — a made-up
  word rather than vocabulary — now reads "not re-chained". `phpstan` reported six
  `DependencySerializationTrait does not support private properties`: `McpWebhookWorker`
  and `McpApprovalDecisionForm` inherit the trait and could not have their injected
  services restored after a serialize round-trip, so they are now `protected readonly`.
  `phpunit` errored twice because `McpBreakGlassTest` called
  `installSchema('audit_chain', …)` without listing `audit_chain` in `$modules`;
  `KernelTestBase` does not resolve `info.yml` dependencies, so the container failed to
  compile before `setUp()` ran. That was test-only — the module declares the dependency
  and real installs resolve it.

  The redness was ours, not an upstream CI-template change: the first red pipeline is the
  commit that edited `.gitlab-ci.yml`, and `phpcs` and `phpunit` were still green in it.

- **The Drupal 10.6 test lane could not build, so `^10.6` was advertised and never
  exercised** (d.o [#3613940](https://www.drupal.org/project/mcp_sentinel/issues/3613940)).
  CI ran against current core only; opting the previous-major and previous-minor jobs in
  showed 11.3 passing 520/520 and 10.6 failing at `composer` with exit 2 —
  `drupal/mcp_server` sits in `require-dev` and needs PHP ^8.3, while the shared templates
  pin that lane to Drupal 10's *minimum* PHP (8.1). Because the build stage failed,
  `phpunit (previous major)` never started and reported nothing at all, so the lane
  contributed no signal while appearing to exist.

  The `^10.6` claim itself was never false — 10.6 supports PHP 8.3 and the module runs
  there. What was broken was the ability to *verify* it. That lane now runs on PHP 8.3, a
  supported and representative 10.6 configuration.

  **Correction to an earlier draft of this entry**, which said the runtime requirements
  carried no 8.3 constraint and that a 10.6 site on PHP 8.1 would install and run fine. That
  was wrong in two independent ways, and a PHP floor is a support claim, so it is corrected
  here rather than quietly edited:

  - `drupal/simple_oauth ^6.1` is a **runtime** requirement, not a test-only one. It pulls
    `league/oauth2-server` and `lcobucci/jwt`, both declaring
    `php: ~8.2.0 || ~8.3.0 || ~8.4.0 || ~8.5.0`. PHP 8.1 cannot resolve at all.
  - The module's own code uses typed class constants (`public const string NAME = …`), which
    are PHP 8.3 syntax. On 8.1 or 8.2 that is a parse error — the module does not merely
    fail to install, it cannot load.

  So `>=8.3` is not a narrowing for CI's convenience; it is what the code requires. The open
  question was only ever 8.2 versus 8.3, and reaching 8.2 would mean dropping those type
  declarations while Drupal 11.3 — this module's D11 floor — requires 8.3 regardless. That
  trade is tracked rather than settled here.

  One limit stays recorded in `.gitlab-ci.yml` rather than papered over: `drupal/mcp_server`
  sits in `require-dev` and needs PHP ^8.3, so the `mcp_sentinel_server` tests could not run
  below 8.3 even if the rest of the module could.

## [2.0.0] - 2026-07-29

**Breaking.** This release takes a new required dependency and moves three
settings and one table out of this module. Sites upgrade cleanly — update 10016
migrates the audit entries and copies the settings across — but anything
automating those config keys, or querying `mcp_sentinel_audit_log` directly,
has to change.

| Was | Is now |
|-----|--------|
| `mcp_sentinel.settings:audit_hash_key` | `audit_chain.settings:hash_key` |
| `mcp_sentinel.settings:audit_encryption_profile` | `audit_chain.settings:encryption_profile` |
| `mcp_sentinel.settings:siem_enabled` | `audit_chain.settings:stream_enabled` |
| `mcp_sentinel_audit_log` table | `audit_chain_log`, channel `mcp_sentinel` |
| SIEM message `mcp_sentinel_audit_event` | `audit_chain_event` |

Requires [`drupal/audit_chain`](https://www.drupal.org/project/audit_chain)
`^1.0.1`. `McpAuditLogger`'s public methods are unchanged; its constructor is
not, so anything instantiating it directly rather than using the service must
be updated.

### Added
- **A policy profile now asserts that its governed roles hold no escape-hatch
  permission** (#65). A profile constrained what the agent could do through the
  MCP channel and said nothing about what its Drupal role could do outside it —
  and the module could not see the difference. Found live: an agent role held
  `bypass file gate` alongside 18 profile permissions, which meant gated
  private files were fetchable straight off `/system/files/…` with no MCP
  request, so no policy, no redaction and no audit row. The profile still
  reported its deny lists and redactions on the dashboard the whole time.
  Profiles now carry `forbidden_role_permissions` (shipped populated, so the
  protection is inherited rather than authored) and
  `acknowledged_role_permissions`, so a deliberate grant is *recorded in
  exported configuration* instead of being tolerated by deleting the rule that
  caught it. Violations raise a critical dashboard condition, an ERROR on the
  status report, a non-zero exit from the new `drush mcp-sentinel:role-audit`
  (the deploy gate — run it after `config:import`), and an audit-chain entry
  the moment a role save introduces one.

  Two things decide whether the check is worth anything, and both are covered:
  it resolves **effective** permissions, so a bypass granted to `authenticated`
  — held by every governed role while appearing in none of their permission
  arrays — is caught and attributed correctly; and an `is_admin` role is
  reported as its own violation rather than scanned, because its permission
  array is empty by design while it implicitly holds everything. The settings
  form and profile form now **refuse** to govern an admin role at all. One
  already configured is still governed at runtime and reported loudly —
  dropping it would leave the agent's traffic ungoverned, which is worse.
### Fixed
- **Raw SQL is no longer a hole straight through the policy profile** (#64).
  An agent reaching `drush sql:query` over the connector's SSH bridge read the
  database underneath the entity API: no `denied_entity_types`, no
  `redacted_fields`, no DLP, and nothing in the audit log — so a `profile`
  entity denied by every shipped profile was still readable through
  `profile__field_nda_date`, and a private-file path was still listable out of
  `file_managed`. Adding entity types to the deny list never could have fixed
  it, and neither could a hook: `sql:query` caps its bootstrap below the level
  at which Drupal discovers module command files, so no module code runs on
  that path at all. Raw SQL now runs only through
  `drush mcp-sentinel:sql-query`, a module-provided command where the profile
  applies — refused outright unless the profile opts in with the new
  `allow_raw_sql` (**off by default and after upgrade**), refused when the
  statement touches a denied entity type, a non-entity table, or a redacted
  field's column, and written to the tamper-evident chain with its statement
  text whether it was permitted or refused. Enabling it is now an exported,
  reviewable decision instead of an inherited default. The governed path is
  deliberately much narrower than `sql:query` — single `SELECT`s over entity
  tables, no expressions, no `SELECT *` on a table carrying a redacted column —
  and the trust model in `README.md` now states plainly that shell access
  (`sql:cli`, `sql:dump`, `php:eval`) is outside Drupal governance entirely,
  which it had previously been silent about.
### Changed
- **The tamper-evident audit chain moved into its own project**
  (`drupal/audit_chain`, #66). It was a general-purpose facility living inside
  an AI-governance module: hash-chained, optionally encrypted, independently
  verifiable — and wanted by personnel-record reads, permission grants,
  configuration changes and break-glass logins, none of which should have to
  install MCP governance to get it. The name was actively misleading to an
  enterprise buyer evaluating audit posture.

  `McpAuditLogger` keeps its entire public surface and is now the MCP policy in
  front of the shared chain: which operations are suppressed, what a change diff
  contains, how redaction and DLP apply. Callers and submodules need no change.

  `mcp_sentinel_update_10016()` migrates existing entries. It copies the signing
  key and encryption profile into `audit_chain.settings` **first** — a keyed
  chain read under a different key is indistinguishable from a tampered one —
  then copies the rows verbatim, `prev_hash` and `row_hash` exactly as written,
  under an empty channel. They are deliberately **not** re-chained: hashes
  recomputed by a migration prove only that the migration ran, and would
  silently repair a chain broken beforehand. The old table is left in place to
  drop by hand after `drush audit-chain:verify` confirms the chain still holds.

  Retention and every read path cover that legacy channel alongside the current
  one, so the audit log, the dashboard counts and the anomaly rules do not
  appear to lose their history the moment the update runs.

## [1.13.0] - 2026-07-26

### Fixed
- **A declared signing key that cannot be resolved now refuses the delivery
  instead of silently sending unsigned** (d.o #3613291, #56). An endpoint
  with no `secret_key` still sends unsigned by design; one whose configured
  Key entity is missing or resolves to an empty value is misconfigured, and
  1.12.x sent every such delivery without `X-MCP-Signature` — silently
  voiding an explicitly configured security control. The worker now fails
  the row terminally as `failed_key` naming the key, and the status report
  pre-flights every enabled endpoint's key so the misconfiguration is
  visible before a single delivery is attempted.

## [1.12.1] - 2026-07-26

### Fixed
- **The in-place publish-gate violation now actually refuses the JSON:API
  vector** (d.o #3613146). 1.12.0 attached the violation to
  `moderation_state`, but JSON:API filters violations to the fields present
  in the PATCH payload — and this bypass is by definition a payload without
  `moderation_state`, so the violation was silently dropped and the request
  returned 200 (caught by the GitLab functional pipeline; the kernel suite
  validates without filtering and stayed green). The violation is now
  reported at the entity level, which survives the filter on every path.

## [1.12.0] - 2026-07-26

### Fixed
- **A save that keeps a published moderation state can no longer replace the
  live revision of published content** (d.o #3613146, #51). Under a
  deny-publish profile, a PATCH omitting `moderation_state` read as "no
  transition" and mutated the default revision in place — observed in
  production as bulk in-place edits of published nodes with no forward
  revision and nothing for a human to approve. Any save targeting a published
  state is now publish-class; the 422 names the remedy (submit the edit with
  `moderation_state: draft` to create a forward revision for human review).
  In-place edits of *unmoderated* published entities remain allowed — there
  is no forward-revision workflow to redirect them into; sites wanting that
  strictness deny writes for the type.
- **Webhook deliveries are never sent through a redirect** (d.o #3613242,
  #52). The worker now disables redirect following — a 301/302 re-issues the
  signed POST as a bodyless GET at a host the SSRF pin never validated — and
  a 3xx answer fails terminally as `failed_redirect` with the `Location`
  recorded, so the delivery log names the misconfigured URL instead of a bare
  405 after five useless retries.
- **Rows stranded `in_progress` by a dead worker are reclaimed on cron**
  (d.o #3613242). A claim older than an hour is reset to `pending` with the
  attempt counter bumped, so an interrupted delivery retries instead of
  hanging forever outside every scan.

### Added
- **Permanent delivery failures now warn on the status report**
  (d.o #3613242). Accumulated `failed`/`failed_ssrf`/`failed_redirect` rows
  produce a hook_requirements() warning with the count, the newest failure
  time, and a link to the delivery log — 1968 dead deliveries once sat
  invisible for a month.

## [1.11.0] - 2026-07-23

### Added
- **The settings page now links to the governance dashboard and audit log.** Settings live
  under Configuration and the dashboard under Reports, so an operator configuring the module
  had no path to the dashboard — it was easy to miss. A small links row at the top of the
  settings form now points to both, shown only to users who can view them. The dashboard's
  quick-actions strip already links back to Settings. Discoverability only; no behaviour or
  schema change, and the conventional Reports/Configuration placement is unchanged.

### Fixed
- **Direct paragraph edits no longer bypass the publish gate (GitHub #46).** Under a
  deny-publish profile, a direct JSON:API write to a paragraph whose current revision was
  pinned by a published host's default revision changed the live page in place — an
  effective publish with no moderation transition, since composite children are exempt from
  the ordinary publish gate. Such a write is now treated as publish-class. When it can be
  drafted safely (a single, moderated, published host), the edit is saved as a new paragraph
  revision and a host **draft** revision is created that re-pins to it: the published
  revision is left untouched, so the live page never changes, and the edit lands as a
  reviewable draft. When it cannot be drafted safely (multiple hosts, a nested chain, an
  unmoderated host, or no non-published state within the profile's `max_moderation_state`),
  the write is refused with a 422 rather than mutated in place. The host-cascade case — a
  governed node save re-saving its own paragraphs — is unaffected, and the per-type
  `entity_rules.paragraph.allow_publish` override opts a site out. Every redirect and refusal
  is audited. Behavioural fix only: no config schema change, and no config export is
  required. Needs Content Moderation, Paragraphs, and Entity Reference Revisions; a no-op on
  sites without them.

## [1.10.0] - 2026-07-22

### Added
- **Per-entity-type publish overrides: `entity_rules.<type>.allow_publish`.** The publish
  gate's scope is now tunable in site config, both directions: a present `allow_publish`
  overrides the global `deny_publish` for that entity type only (relax one type, or gate
  one sensitive type while publishing stays open globally). Absent means the global flag
  decides, so defaults are unchanged and fail closed. This follows the
  `entity_rules.<type>.allow_delete` precedent and keeps posture decisions in config —
  visible in config export and audit — instead of module code.

  Motivating case: redirect module dev-1.x made Redirect publishable (`enabled` is the
  published key), so the gate began governing redirects by fall-through and every
  agent-created redirect arrived disabled. Sites that consider a redirect's `enabled`
  flag routing metadata (its agent-risk axis is the target, which
  `deny_external_redirects` constrains) can now set
  `entity_rules.redirect.allow_publish: true`. Sites that consider an enabled redirect
  editorial go-live change nothing.

### Fixed
- **The presave backstop's forced unpublish is audited and logged, never silent.** When
  the deny-publish backstop flips a governed, unvalidated save to unpublished, it now
  writes a `publish_gate_backstop` audit row and a watchdog warning naming the entity and
  the per-type exemption. Previously the flip was invisible — the create reported
  success, the entity was disabled, and nothing logged; on one production site that
  accumulated five dead redirects in two weeks before anyone noticed.

## [1.9.0] - 2026-07-16

This release makes the module's core-compatibility claim true. `^10.3 || ^11` was fiction in
both directions: the module could not run below Drupal 11.2 at all, while the metadata
advertised branches that were EOL. Anyone on Drupal 11.0 or 11.1 — inside the released `^11`
claim — had a module that fataled on the first write it was installed to govern. The real
working range is now `^10.6 || ^11.3`, and every floor in it is exercised by CI.

### Added
- **Drupal 10.6 and 11.3 are tested, not just claimed ([#35]).** `info.yml` declared
  `^10.3 || ^11` while the suite could only ever run on 11 — half the support claim had never
  been verified. CI now runs the **floor of each declared range and the ceiling**: Drupal 10.6
  / PHP 8.3 / PHPUnit 9.6, Drupal 11.3 / PHP 8.3, and Drupal 11 (11.4) / PHP 8.4. All three
  collect the same 364 tests, so the claim is enforced rather than asserted.

  The suite is written with PHP 8 attributes, which only PHPUnit 10+ reads, while every
  `drupal/core-dev` in the 10.x range hard-requires PHPUnit `^9.6` — and 9.6 does not error on
  an attribute it cannot parse, it **ignores** it. The suite therefore carries the equivalent
  annotations (`@group`, `@dataProvider`, `@runTestsInSeparateProcesses`) alongside its
  attributes: 9.6 reads the annotations, 10/11 read the attributes.

  The new leg also **asserts the test count** rather than the exit status. Getting here took
  three green-but-empty runs: a matrix leg that scheduled zero jobs, a runner handed two
  directories when PHPUnit 9.6 accepts only one (it ran 62 of 364 tests and reported `OK`), and
  a version probe that printed PHPUnit's version as Drupal's. All three passed. An exit code
  only says the tests that ran passed; it cannot say which ran — so the step now counts the
  testcases in the JUnit output and fails below a floor.

  Each leg also **asserts the core version it resolved**. `^11.3` means ">=11.3 <12", so a leg
  named 11.3 built from its own name installed 11.4 and quietly retested the ceiling — green,
  while the range it existed to protect was covered by nothing. Floors now pin their minor
  (`~10.6.0`, `~11.3.0`) and the ceiling floats (`^11`), and a leg whose resolved core does not
  match its name fails.

- **CI runs the test suite ([#32]).** The module had 364 tests and nothing executed them: CI was
  CodeQL, `composer audit`, a CHANGELOG gate and Dependabot auto-merge, so a PR could go green,
  merge and ship while the suite was broken. For a module whose job is enforcing a security
  boundary, "the tests pass if someone remembers" is the wrong guarantee. A new `Tests` workflow
  runs PHPUnit (Unit + Kernel) on every PR and on push to `1.x`. It also adds a blocking `phpcs`
  job (`Drupal`, `DrupalPractice`).

  The workflow installs the **working copy** via a Composer path repo and asserts the symlink
  resolved, so a silent fallback to the released package cannot let the suite pass against code
  nobody changed. Functional tests need a webserver and are not run yet; that is a deliberate
  first step.

### Changed
- **Core requirement `^10.3 || ^11` → `^10.6 || ^11.3`.** Both halves named dead branches.
  Drupal 10.3 has been EOL since 2025-06-16, and `^11` claimed 11.0 (EOL 2025-06-16), 11.1
  (EOL 2025-12-10) and 11.2 (EOL 2026-06-17). Per upstream's lifecycle the only live branches
  are **10.6** and **11.3** (both EOL 2026-12-16) and **11.4** (EOL 2027-07-07), so those are
  what the module claims.

  Support stays as wide as upstream supports — orgs upgrade slowly and a narrow floor
  discourages adoption — but no wider: an EOL branch is not a kindness to advertise. Applies to
  `composer.json`, to the main module plus the `server`, `graphql` and `approval` submodules,
  and to the `README` / `INSTALL` requirements — which kept advertising "Drupal 10.3+ or 11",
  the very claim this release corrects, and which are the text the drupal.org project page
  mirrors.

  **Upgrading:** sites on Drupal 11.0–11.2 will not receive this release. Those branches are
  EOL upstream, and the module never actually worked on 11.0 or 11.1 — see the fatal below.
  Move to 11.3+ or to 10.6.

### Fixed
- **The module fataled on every governed entity update on Drupal 10.6, 11.0 and 11.1 ([#35]).**
  `mcp_sentinel.module` called `EntityInterface::getOriginal()`, which core only added in
  **11.2**. Below that the method does not exist, so a governed update raised
  `Call to undefined method ...::getOriginal()` — on the first write the module was there to
  govern. 11.0 and 11.1 are inside the released `^11` claim, so this affected published
  releases and not only the new floor. Access to the pre-save original now goes through
  `McpAuditLogger::originalOf()`, which uses the modern API where it exists and the property it
  replaced where it does not.
- **Entity types were invisible below Drupal 11.1 ([#35]).** The three entity types were
  declared with PHP attributes, but attribute-based entity type discovery arrived in **11.1**;
  below it `EntityTypeManager` uses `AnnotatedClassDiscovery` and reads annotations only. An
  attribute is not ignored gracefully there — the entity type simply never exists, and every
  service touching it fails (176 errors on the 10.6 leg). The types are declared with
  annotations, which both discovery mechanisms read. Annotations are deprecated in Drupal 11
  and removed in 12; each class documents that this converts back when the floor reaches 11.1.
- **`McpDenyExternalRedirectValidatorTest` never actually ran ([#32]).** All 7 tests errored on
  `No schema for views.view.redirect`: the `redirect` module ships `views.view.redirect` in
  `config/install`, so `installConfig(['redirect'])` required the `views` module — and, once
  added, `image`, `options` and more via `user`'s config — to satisfy an admin listing these
  tests never render. The class now installs only the config it needs and adds the `path_alias`
  entity schema that resolving an `internal:`/`entity:` target consults. The open-redirect gate
  has therefore been untested since it shipped in 1.7.0; it passes.
- **`composer audit` never ran on push ([#32]).** Its trigger targeted branch `1.0.x`, which does
  not exist on this repo — the branch is `1.x`. (`1.0.x` survives on the drupalcode mirror, where
  it is still HEAD, which is likely where the value came from.) Only the `pull_request` trigger
  had ever fired.
- Two long-line PHPCS warnings, so the new standards gate passes on a clean tree.

[#32]: https://github.com/Wilkes-Liberty/mcp_sentinel/issues/32
[#35]: https://github.com/Wilkes-Liberty/mcp_sentinel/issues/35

## [1.8.0] - 2026-07-15

### Fixed
- **`deny_publish` no longer silently unpublishes side-effect entities ([#30]).** The
  presave publish-gate fired on every `EntityPublishedInterface` saved during a governed
  request — not only the entity the agent targeted. Ten entity types implement that
  interface on a standard install, and most are not editorial content. Pathauto mints a
  `path_alias` as a side effect of saving a node, and Paragraphs saves referenced items:
  both were stored unpublished. An unpublished alias does not resolve, so the page lost
  its canonical URL; unpublished paragraphs are invisible to anonymous users, so a
  published page rendered its content to nobody. The agent never touched those entities,
  never asked to publish anything, and the write returned `200 OK`.

  On one production site this had silently hidden **85 paragraphs across 17 published
  pages** and orphaned **56 path aliases**. It looked correct to an authenticated editor;
  only anonymous visitors saw the gap.

  The gate now asks `McpModerationGate::governsPublishedStatus()`, which excludes
  **composite children** (anything declaring `entity_revision_parent_type_field`, such as
  paragraphs — never published in their own right, and saved as a side effect of the
  host) and **routing metadata** (`path_alias` — its status means "is this alias active",
  and the aliased path's own access still applies). The rule is structural rather than a
  list of known module names, and it fails closed: an unfamiliar publishable entity type
  stays governed.

- **A denied publish on an unmoderated entity is now reported, not silently reverted
  ([#30]).** The `McpDenyPublish` constraint previously covered only moderated entities;
  unmoderated ones were left to the presave backstop, which forced `status` to 0 and let
  the write return success. A caller could not distinguish a refusal from a publish, and
  neither could anything built on top. The constraint now applies the same go-live rule
  to both paths — deny only when the entity is being published and was not already
  published — and reports a violation at `status`, surfacing as a 422 through JSON:API
  and REST exactly as the moderated path does. `mcp_sentinel_entity_presave()` keeps the
  `status=0` backstop for saves that never validate (custom code, Drush): the constraint
  reports, the presave enforces.

### Changed
- **`mcp_sentinel_media_create` now creates media unpublished under a deny-publish
  profile.** Media is published by default, which the publish gate correctly reads as a
  go-live the agent never requested. The tool now states the invariant it always relied
  on — an agent uploads, a human publishes — instead of depending on the presave backstop
  to rewrite the status afterwards.

### Upgrading
- A write that previously returned `200 OK` with the entity quietly unpublished now
  returns **422**. That is the point of the fix, but clients that send `status: true` (or
  rely on an entity type's published-by-default) and treat the silent unpublish as
  success will start seeing errors. Set the published state explicitly on create.
- Entities already unpublished by the old behaviour do not self-heal. Sites adopting this
  release should audit for publishable entities that a governed agent touched —
  paragraphs referenced by published nodes, and paths whose aliases are all unpublished —
  and republish them. Note that `entity_reference_revisions` pins a revision: repairing a
  paragraph needs `setNewRevision(FALSE)` or the host keeps rendering the old one.

[#30]: https://github.com/Wilkes-Liberty/mcp_sentinel/issues/30

## [1.7.0] - 2026-07-14

### Added
- **Open-redirect / phishing guard (`deny_external_redirects`).** A new policy-profile
  control blocks a governed agent from creating or updating a `redirect` entity whose
  destination points off-domain — closing an open-redirect vector where an agent could
  turn the site's own domain into a phishing springboard (e.g. `/login →
  https://evil.example/login`). Enforced by a new `McpDenyExternalRedirect` validation
  constraint attached to the `redirect` entity type; validation is the only seam that
  sees the incoming target value (same rationale as `McpDenyPublish`), which field
  edit-access on a JSON:API/REST write does not. The constraint reads
  `redirect_redirect->uri`, treats `internal:`, `entity:`, `base:`, and relative targets
  as always-allowed, and denies only a fully external URL whose host is outside the
  allowlist. **Secure by default:** `deny_external_redirects` defaults to `TRUE`, and
  existing profiles missing the key resolve to `TRUE`. An optional
  `allowed_redirect_hosts` list permits specific external hosts; when empty, the site's
  own host(s) — derived from the request host and `trusted_host_patterns` — are the
  implicit allowlist. The constraint is attached only when the `redirect` module is
  installed, so sites without it are unaffected. Configurable per profile at
  Configuration governance → *Deny off-domain redirects*; `mcp_sentinel_update_10013()`
  backfills the safe defaults onto existing profiles. New `McpDenyExternalRedirectValidatorTest`
  kernel coverage.

## [1.6.1] - 2026-07-05

### Fixed
- **Moderated publish gate no longer blocks `published → draft`.** The deny-publish
  gate for moderated content moved from `hook_entity_field_access()` ('edit') to a new
  `McpDenyPublish` validation constraint. JSON:API and REST check field edit-access
  against the entity's *stored* field value, so the old field-access gate saw a node's
  current `moderation_state` rather than the incoming target and wrongly forbade every
  `moderation_state` write on an already-published node — including a legitimate
  transition back to `draft` (agents could not stage published pages as drafts for
  review; each PATCH returned a 403). The constraint runs on the parsed entity with the
  new value, so it denies only a genuine go-live (a transition *into* a published state,
  or creating already-published content) and returns a clean 422, while allowing
  `published → draft`, `draft → draft`, `published → archived`, and in-place edits of
  already-published content. The human-publish invariant is unchanged: a deny-publish
  agent can never transition content into a published state over JSON:API/REST. The
  unmoderated `status`-flag path continues to be enforced by the presave fallback in
  `mcp_sentinel_entity_presave()`.

### Added
- `McpPublishGateJsonApiTest` functional regression test exercising the publish gate over
  real JSON:API `PATCH`/`POST` requests (published→draft allowed; draft→published and
  create-published denied with 422; non-publish field edits on published content allowed),
  plus a `McpDenyPublishValidatorTest` kernel test for the new constraint.

## [1.6.0] - 2026-07-05

### Added
- **Break-glass grants list** — `/admin/reports/mcp-sentinel/grants` (+ dashboard tab + Reports
  menu link). Read-only view of all active time-boxed `mcp_admin` grants; previously visible
  only in the database.
- **Approval settings form** — `/admin/config/services/mcp-sentinel/approval` lets site admins
  edit `gated_operations` and the break-glass TTL without touching YAML; `configure:` wired in
  `mcp_sentinel_approval.info.yml`.
- `hook_help` implementations for `mcp_sentinel_approval` and `mcp_sentinel_graphql`; small
  `mcp_sentinel_server.module` with `hook_help` matching the module's existing procedural
  pattern.
- `README.md` for the `mcp_sentinel_approval`, `mcp_sentinel_graphql`, and `mcp_sentinel_server`
  submodules.
- `#description` field-level help on the four core policy-profile gates (allow read / write /
  delete / GraphQL mutations) and several settings fields (audit logging, read logging,
  retention, anomaly detection, webhook retention).
- `mcp-sentinel:agent-provision` and `mcp-sentinel:break-glass` added to the README Drush
  command table.
- `McpApprovalAdminUiTest` functional test: settings form saves `gated_operations` + TTL,
  permission-gated (403 without `administer mcp sentinel`), grants list shows an active grant.
- New `content-auditor` provisioning tier (`drush mcp-sentinel:agent-provision content-auditor`):
  the read-only sibling of `content` — the content-editor role with only the `mcp_read` scope,
  so write tools are unreachable at the scope layer. Pair with the connector's `auditor` preset
  for content reports and audits.

### Fixed
- **The config-write approval veto is now actually delivered.** `McpConfigSetTool` dispatched
  its `McpDestructiveActionEvent` with no event name, so it was delivered under the event's
  class name while the `mcp_sentinel_approval` subscriber listens on
  `McpDestructiveActionEvent::NAME` — the listener never fired and a gated config write
  proceeded even when it should have been queued for human approval. It now dispatches under
  the event NAME, so gated config writes are held for approval. The `mcp-sentinel:break-glass`
  Drush command had the identical nameless-dispatch bug (it fail-closed to an error instead of
  queuing a grant request) and is fixed the same way. Added a kernel regression test,
  `McpDestructiveActionEventTest`, covering the config-veto seam (the bulk-delete seam was
  already covered by `McpDestructiveOpEventTest`).

## [1.5.1] - 2026-07-04

### Fixed
- Test-suite fixes so the CI pipeline passes; **no functional or API change from 1.5.0**
  (shipped module code is identical). Updated `McpPolicyResolverOauthTest` to expect the
  1.5.0 `agent_scopes` default that now includes `mcp_config_read`, and removed a redundant
  always-false guard in the tool-scope derivation test that static analysis flagged.

## [1.5.0] - 2026-07-04

### Changed
- **Tool OAuth scopes are now derived from the plugin, not a hand-maintained table.**
  `mcp_sentinel_server` derives each registered tool's required scope from the plugin's
  own declarations — its `ToolOperation` (read vs modifying, via
  `ToolOperation::isModifying()`) and a new `ConfigScopeToolInterface` marker (config vs
  content domain) — replacing the parallel per-tool scope map that could drift from the
  plugin. Config **reads** (`config_get`, `config_list`) now require a dedicated read-only
  `mcp_config_read` scope; config **write** (`config_set`) keeps `mcp_config`. This lets a
  read-only auditor identity read configuration with no config-write capability. Sites must
  ship the `mcp_config_read` scope, a read-only role, and a matching policy profile (see
  INSTALL/README).

### Added
- **`ConfigScopeToolInterface`** — marker implemented by the config tools to declare the
  config scope domain; `ToolScopeResolver` maps `(domain × operation)` to the OAuth scope.
- The shipped `mcp_sentinel.settings` default `agent_scopes` now includes `mcp_config_read`
  so a read-only auditor token (carrying only that scope) is recognised on the governed agent
  channel. Sites that override `agent_scopes` must add `mcp_config_read` to keep the config
  tools reachable.
- **`auditor` provisioning tier** — `drush mcp-sentinel:agent-provision auditor` provisions a
  read-only config auditor (`mcp_config_auditor` role, `mcp_config_read` scope only); the
  `developer` and `admin` tiers also gain `mcp_config_read` so they retain config read.

## [1.4.0] - 2026-06-29

### Added
- **Per-entity-type destructive overrides on policy profiles (`entity_rules`).**
  A profile's global `allow_delete` / `allow_write` flags remain the default for
  every entity type, but an `entity_rules` map can now override them for one type
  at a time, e.g.

  ```yaml
  entity_rules:
    taxonomy_term:
      allow_delete: true
  ```

  The effective permission resolves as
  `entity_rules[type].allow_delete ?? allow_delete` (and the parallel
  `?? allow_write`). This lets an operator open delete for a single low-risk type
  (e.g. `taxonomy_term`, for taxonomy maintenance) while the global no-delete
  guarantee holds for node, media, paragraph, menu, redirect, file, and every
  other type. New entity methods `getEntityRules()`,
  `allowsDeleteForEntityType()`, and `allowsWriteForEntityType()` implement the
  override-then-fallback resolution, and `McpAccessChecker` consults them on the
  write and delete paths (the core-access hook and the bulk tool alike).
- The per-type delete overrides are editable in the profile UI at **Allowed
  operations → Per-entity-type delete overrides**, and the effective rule map is
  reported by `mcp_sentinel_security_policy` (surfaced to the connector as
  `entityRules` in `drupal_security_info`).

### Notes
- This is the *Sentinel* gate only — the Drupal role permission (e.g.
  `delete terms in <vocabulary>`) remains an independent second gate; a delete
  requires **both**.
- No Integration Contract change (contract v1.0-compatible); OAuth scopes,
  identity header, and server-authoritative authz are unchanged.
- No update hook: the new `entity_rules` field defaults to empty, so existing
  profiles are unchanged and behave exactly as before until a rule is added.
- Governance unchanged: server-authoritative authz, attribution, tamper-evident
  audit, DLP/redaction, the config-scope isolation, and the DEV-113 publish gate
  are untouched.

## [1.3.0] - 2026-06-29

### Changed
- **The publish gate is now value-aware on the JSON:API/REST write path.**
  Previously, a deny-publish profile forbade **every** edit to `moderation_state`
  (and `status`) via `hook_entity_field_access`, which also blocked the
  non-publish editorial transitions a content role grants — the agent could not
  set `draft`, `submit_for_review`, `restore`, or `archive` through the connector
  (it received `403 — Publishing is denied by MCP Sentinel`). The gate now inspects
  the **target value** and forbids only a transition to a *published* state
  (`moderation_state`) or a publish via the `status` flag (`status = TRUE`);
  non-publish transitions and unpublishing are allowed. The human-publish
  guarantee is unchanged — any published-state target is still denied with the
  same clear message, and a generic access probe (no pending value) defers to the
  value-bearing write-time check. (DEV-113)

### Added
- **`mcp_sentinel.moderation_gate`** service (`McpModerationGate`) — the single
  source of truth for "does this transition publish?" Both the field-access gate
  and `McpWorkflowTransitionTool` use it, so the JSON:API write path and the
  server-tool path agree on exactly which transitions are go-live. It is
  conservative: only a known, published target state counts as a publish.

### Notes
- No Integration Contract change — OAuth scopes (`mcp_read` / `mcp_write` /
  `mcp_config`), identity header, and server-authoritative authz are unchanged;
  this is contract v1.0-compatible.
- Governance unchanged: server-authoritative authz, attribution, tamper-evident
  audit, DLP/redaction, and the content-tier config-scope isolation are untouched.

## [1.2.0] - 2026-06-27

### Security
- Isolated the configuration tools behind a dedicated **`mcp_config`** OAuth scope.
  `mcp_sentinel_config_get`, `mcp_sentinel_config_list`, and `mcp_sentinel_config_set`
  now require `mcp_config` instead of `mcp_read` / `mcp_write`, so a content-tier token
  (holding only `mcp_read` / `mcp_write`) can no longer read or write Drupal configuration
  through MCP — config management is now isolated to the dev/config tier (the `developer`
  and `admin` tiers in `mcp-sentinel:agent-provision`, which already grant `mcp_config`).
  The transport-layer scope gate is in addition to the existing `allow_config_read` /
  `allow_config_write` / `denied_config_types` policy gates.

### Changed
- `mcp_config` is now part of the default `agent_scopes` so a token carrying only that
  scope is still recognized on the governed agent channel.

> **Upgrade action.** After updating, re-run `drush mcp-sentinel:setup`
> to re-tag the config tools with `mcp_config`. Ensure your config/dev consumer holds the
> `mcp_config` scope (the `oauth2_scope` entity must exist) and that content-tier consumers
> do **not**. Any consumer that previously called the config tools with only `mcp_write`
> will now be denied until granted `mcp_config`.

## [1.1.0] - 2026-06-26

### Security
- Hardened the default `denied_entity_types` to block secret-, governance-, and
  credential-bearing entity types — `oauth2_token`, `key`, `consumer`,
  `encryption_profile`, `mcp_tool_config`, `mcp_policy_profile` — in addition to `user`.
  Because a profile with an empty `allowed_entity_types` means "allow all (minus the
  denylist)", these were previously reachable by any profile with write access. New
  installs get the hardened default; `mcp_sentinel_update_10012()` additively merges the
  list into existing profiles (idempotent; operator-added denies are preserved).

### Fixed
- **CI (phpunit)**: `GraphqlFieldResultsAlterTest` saved `mcp_sentinel.settings` without
  installing the `mcp_sentinel_audit_log` schema, so the `ConfigEvents::SAVE` audit subscriber
  errored on a missing table (2 errors on the drupal.org pipeline, red since 1.0.0-beta5).
  `setUp()` now installs the audit-log schema, matching the sibling kernel tests. Test-only —
  no runtime change.

## [1.0.0] - 2026-06-26

First **stable** release. Promotes the `1.0.0-alpha1` … `1.0.0-beta6` pre-release
series to a stable 1.0.x line under semantic versioning. There are **no code changes
since `1.0.0-beta6`** — this tag marks API stability for the governance surface
(policy-profile fields, MCP tools, events, and Drush commands). Supported core:
`^10.3 || ^11`. Headline scope of the 1.0.0 line, consolidated from the pre-release
entries below:

### Added
- **Two-persona, environment-keyed configuration governance**: per-tier
  `McpPolicyProfile` capabilities (`allow_config_read`, `allow_config_write`,
  `denied_config_types`), governed config MCP tools (`mcp_sentinel_config_get` /
  `_list` / `_set`), and a `ConfigEvents::SAVE` hard-deny + audit subscriber.
- **Publish gate**: agent-authored content lands unpublished (`deny_publish`,
  `max_moderation_state`), with a `status = 0` fallback for unmoderated types.
- **Approval workflow + break-glass**: `mcp_sentinel_approval` gates `delete`,
  `config_import`, and `module_disable`; time-boxed, approval-gated `mcp_admin`
  elevation (never standing).
- **Tamper-evident audit**: HMAC-SHA256 audit hash chain, at-rest audit-metadata
  encryption (`real_aes` encryption profile), DLP redaction, anomaly detection, SIEM
  streaming, and reliable governance webhooks.
- **Admin UX**: dashboard + settings menu links and an in-form setup guide.

See the `1.0.0-beta*` / `1.0.0-alpha*` sections below for full per-release detail.

## [1.0.0-beta6] - 2026-06-26

### Fixed
- **PHP 8.4 compatibility**: the audit-log CSV export (`McpAuditController::buildCsvResponse()`)
  called `fputcsv()` without the `$escape` argument, which PHP 8.4 deprecates — under the
  test deprecation handler this errored, and on PHP 8.4 sites the export would emit a
  deprecation notice. The separator/enclosure/escape are now passed explicitly (no change to
  output). Fixes the red `McpAuditFilterExportTest` CSV jobs in CI.
- **Test**: `McpDashboardTest::testDashboardRendersForPermittedUser` granted the test user
  `access site reports` so the core Reports index (`/admin/reports`) renders; previously the
  page 403'd and the dashboard menu-link assertion failed. Added an explicit 200 assertion so
  the cause is obvious if it regresses.

## [1.0.0-beta5] - 2026-06-26

### Added
- **Configuration governance (two-persona, environment-keyed least privilege).**
  A new layer that governs configuration operations and content publishing under
  the resolved policy profile, additive and default-off:
  - **Profile fields** (`McpPolicyProfile`): `allow_config_read`,
    `allow_config_write`, `denied_config_types` (name-prefix denylist),
    `deny_publish`, and `max_moderation_state`. All default to the safe value
    (config off, publishing denied); existing profiles are backfilled by
    `mcp_sentinel_update_10011()`. A new "Configuration governance" tab on the
    policy-profile form edits them.
  - **Config access seam**: `McpAccessChecker::checkConfigAccess()` mirrors the
    entity-access pattern (master switch, IP allowlist, denylist, read/write
    gates). Three new governed MCP tools — `mcp_sentinel_config_get`,
    `mcp_sentinel_config_list`, `mcp_sentinel_config_set` — registered via
    `drush mcp-sentinel:setup`. Config reads/lists honor `audit_log_reads`.
  - **Hard-deny config subscriber**: a `ConfigEvents::SAVE` subscriber audits
    every governed config save (`config_save`, with a redaction/DLP-aware diff
    via `McpAuditLogger::computeConfigDiff()`) and hard-denies — reverting the
    persisted value and throwing — a governed write to a `denied_config_types`
    name, closing the direct-`Config::save()` bypass.
- **Publish gate.** Agent-authored content lands unpublished unless a profile
  opts in. Enforced at the `mcp_sentinel_workflow_transition` tool (value-aware:
  blocks transitions to a published state and beyond `max_moderation_state`),
  with `hook_entity_field_access` (`edit` on `moderation_state`/`status`) and an
  `entity_presave` `setUnpublished()` fallback as defense in depth.
- **Approval coverage for config/admin ops.** `gated_operations` now defaults to
  `delete`, `config_import`, `module_disable`. A non-entity
  `McpDestructiveActionEvent` + subscriber queue these for human approval, and
  `McpApprovalExecutor` replays `config_import` and `module_disable` on approval.
- **`mcp-sentinel:agent-provision <tier> --env`** drush command — idempotently
  provisions a tier's role, dedicated agent account, and OAuth consumer (one
  source of truth so connector/Keychain/consumer cannot drift). Secrets remain a
  human action.
- **Time-boxed `mcp_admin` break-glass.** The admin role is never standing:
  `mcp-sentinel:break-glass <uid>` raises an always-gated approval request; on
  approval the role is granted with a TTL (`break_glass_ttl_seconds`) and
  recorded as an `mcp_admin_grant` entity, then auto-revoked by
  `mcp_sentinel_approval_cron()`.
- **`config_governance` status guard.** `McpUrgentConditions` emits a critical
  condition (surfaced on the dashboard and as a non-zero `mcp-sentinel:status`
  exit) when config write is reachable but governance is not live — never fail
  open.

## [1.0.0-beta4] - 2026-06-22

### Fixed
- Drupal.org GitLab CI was red on `1.0.x` (phpcs, phpstan, phpunit). All fixes
  are in code introduced by the fail-loud requirement plus one type-hint:
  - **phpunit** — `McpRequirementsTest` invoked `mcp_sentinel_requirements()`
    directly, which uses the `REQUIREMENT_*` severity constants from
    `core/includes/install.inc`; that file is loaded by core before runtime
    requirements run but not in a kernel test, causing "Undefined constant
    REQUIREMENT_WARNING". The test now loads `install.inc` in `setUp()`. It also
    installs the `path_alias` entity schema, because the warning the hook builds
    renders a settings link via `Url::fromRoute()`, which resolves path aliases
    (a latent failure the undefined-constant error had been masking).
  - **phpstan** — `McpSentinelServerCommands::setup()` type-hinted the
    `mcp_tool_config` entity with the optional `mcp_server_tool_bridge` module's
    concrete class, which static analysis cannot resolve (6 errors). Retyped to
    `\Drupal\Core\Config\Entity\ConfigEntityInterface`.
  - **phpcs** — fixed three 81-char lines in `mcp_sentinel.install` and a
    non-capitalized doc-comment short description in `McpRequirementsTest`.

### Added
- Admin menu links for the governance **dashboard** (`/admin/reports/mcp-sentinel`,
  under Reports) and the **settings** form (`/admin/config/services/mcp-sentinel`,
  under Configuration → Web services). Both were previously reachable only by direct
  URL or local-task tabs, so the dashboard never appeared in the Reports listing and
  the settings form never appeared in the Web services group. Access is unchanged —
  each link inherits its route's existing permission requirement
  (`mcp_sentinel.links.menu.yml`).
- A collapsed, unobtrusive **"Setup & configuration guide"** on the settings form
  (`McpSettingsForm`): a short site-builder quickstart (install → register tools →
  make requests governable → define a policy profile → configure a signing Key),
  linking to policy profiles, the Keys UI, and the shipped `README.md` / `INSTALL.md`
  / `API.md`. It is a curated quickstart, not a copy — the README and `hook_help()`
  remain the source of truth.
- CI: Slack release notification (`.github/workflows/release-notify.yml`) — posts to the
  maintainers' release channel on release tags; no-ops without the `SLACK_WEBHOOK_RELEASES` secret.
- Fail-loud runtime requirement (`mcp_sentinel_requirements('runtime')`): the
  status report now raises a WARNING ("MCP Sentinel: not governing any request")
  when the module is enabled but governance can never engage — i.e. both
  `agent_scopes` and `agent_oauth_clients` are empty and the local-dev role
  fallback is not usable (so `McpOauthContext::isAgentChannel()` can never fire),
  or no `mcp_policy_profile` exists (so `McpPolicyResolver::resolve()` always
  returns NULL). The check mirrors the real governance decision and links to the
  settings form. This closes the silent no-op footgun where the module fails open
  without telling the operator.
- CI: Dependabot patch/minor PRs now auto-merge once checks pass (majors still
  reviewed), via the org reusable workflow
  (`.github/workflows/dependabot-automerge.yml` calls the shared
  `dependabot-automerge.yml` in `Wilkes-Liberty/.github`).
- Adopted the shared **Integration Contract v1.0** (published by the companion
  connector at `docs/integration-contract.md`). The connector's `X-MCP-Client`
  label is now recorded in the audit log — log-only, as the `mcp_client`
  metadata field, never an enforcement signal. `docs/CONNECTOR.md` documents the
  contract surface (log-only client identity, `mcp_read`/`mcp_write` scopes, the
  `/drupal-mcp/context` endpoint, and server-authoritative authorization keyed on
  role + scopes). Compatibility: mcp_sentinel ≥ 1.0 ↔ drupal-mcp-connector ≥ 0.6.
- Adopted the organization governance baseline for GitHub. Added a CHANGELOG
  check (`.github/workflows/changelog.yml`, with a `no-changelog` bypass label)
  and CHANGELOG autoupdate (`.github/workflows/changelog-autoupdate.yml`), both
  calling the shared reusable workflows in `Wilkes-Liberty/.github`. Added
  Dependabot (`.github/dependabot.yml`) for the `composer` and `github-actions`
  ecosystems on a weekly schedule. Added a non-blocking PHP dependency audit
  (`.github/workflows/composer-audit.yml`) that runs `composer audit` on pull
  requests and on pushes to `1.0.x`; CodeQL is intentionally omitted as it does
  not support PHP.

### Changed
- CI: the CHANGELOG check now exempts Dependabot PRs automatically (author
  `dependabot[bot]`), so dependency bumps no longer need a changelog entry or the
  `no-changelog` label.
- **OAuth scope machine ids standardized to underscores: `mcp:read` →
  `mcp_read`, `mcp:write` → `mcp_write`.** This is a **contract change**.
  Governance matches the scope *name* carried on a validated token against
  `mcp_sentinel.settings:agent_scopes`; the install default, the settings-form
  default, the `mcp-sentinel:setup` tool→scope tags, and all docs now use the
  underscore form so token, tagging, and governance agree end-to-end. **Action
  required for existing installs that created colon-form scopes:** rename your
  `Oauth2Scope` entities (and any consumer `scopes`) and update
  `agent_scopes` to the underscore form. See `docs/UPGRADE.md`.
- Renamed all references to the companion connector to its final public name
  **`drupal-mcp-connector`** (formerly published under its working name; repo
  `Wilkes-Liberty/drupal-mcp-connector`, npm `drupal-mcp-connector`). The
  `X-MCP-Client` label default is now `drupal-mcp-connector/<version>`.
- CI: made the GitHub-mirror workflows self-contained instead of calling reusable
  workflows in the private `Wilkes-Liberty/.github` repo. A public repository
  cannot use reusable workflows from a private one, so every PR run was failing at
  startup ("workflow file issue"). `changelog.yml` and `dependabot-automerge.yml`
  now inline their logic (no external repo dependency, so forks work too);
  `changelog-autoupdate.yml` is removed (it required an org GitHub App). Also
  dropped the `composer` Dependabot ecosystem — the Drupal contrib deps live on
  packages.drupal.org, not Packagist, so Dependabot could not resolve them.
- Docs clarity: INSTALL.md now states the underscore scope form is the default
  (most sites need no change) and links the colon-form migration section directly;
  added an "agent discovery" pointer to the `/drupal-mcp/context` endpoint after
  OAuth setup. docs/CONNECTOR.md clarifies that `mcp_server_oauth` is optional
  (per-tool transport-layer scope enforcement) and is not required for governance.

## [1.0.0-beta3] - 2026-06-02

### Fixed
- Drupal.org CI code-quality jobs: added project words for CSpell, fixed the
  Stylelint CSS property order, removed a redundant ESLint `'use strict'`, and
  wrapped a PHPCS line-length warning. No functional change.

### Changed
- Module, composer, and project-page descriptions updated to the current
  governance feature set.

## [1.0.0-beta2] - 2026-06-02

### Added
- Reusable in-form multi-row list editor trait.
- Live policy-preview summary on the profile form; refreshes via AJAX when gate or cap fields change.
- McpMetrics dashboard-data service (`mcp_sentinel.metrics`): read-only, window-bounded aggregation over the existing audit, webhook, approval, anomaly, and config stores.
- McpUrgentConditions service (`mcp_sentinel.urgent_conditions`): evaluates critical/warning conditions (broken hash chain, unresolvable encryption profile, governance off with recent traffic, unresolvable webhook signing key) plus the operator broadcast.
- McpChartRenderer service (`mcp_sentinel.chart_renderer`): renders metric series as charts with a self-contained inline-SVG fallback and an optional `drupal/charts` upgrade (added to composer `suggest`).
- Governance dashboard at `/admin/reports/mcp-sentinel` (`McpDashboardController`): urgent-conditions banner, posture hero, status tiles, chain-integrity card, top-agents and denied-by-policy panels, quick actions, and an active-controls strip — each widget guarded so a failing metric degrades gracefully. Local-task tabs (Dashboard · Audit log · Webhook deliveries · Approvals) navigate the report surface.
- Six dashboard charts (audit volume with anomaly markers, allowed-vs-denied, operation mix, top agents, denied reasons, webhook health) via `McpChartRenderer`, with a server-rendered time-window toggle (`?window=24h|7d|30d`, default 24h) and click-to-drill links into the filtered audit / webhook logs.
- CSRF-protected **Verify chain now** dashboard action (`mcp_sentinel.verify_chain`): re-runs `verifyChain()` and writes `@state` `mcp_sentinel.last_verify` in the same shape as the Drush command, then redirects to the dashboard with a status message.
- Site-wide **critical** urgent banner via `hook_page_top()`: shown on admin pages (only to users with *View MCP Sentinel audit log*) so a broken hash chain or unresolvable signing key is seen even off the dashboard, with per-user dismissal (private tempstore) via a CSRF-protected endpoint. Warning/info conditions remain dashboard-only.

### Changed
- Audit log listing moved from `/admin/reports/mcp-sentinel` to `/admin/reports/mcp-sentinel/audit` (the base path is now the governance dashboard); the route name `mcp_sentinel.audit_log` and the export route are unchanged.
- Settings form reorganized into vertical tabs; added a dashboard operator-broadcast message.
- DLP patterns edited via an add/remove row table (config storage unchanged).
- Anomaly rules edited via an add/remove row table (config storage unchanged).
- Webhook endpoints edited via a dynamic add/remove editor (config storage unchanged).
- Policy-profile form grouped into vertical tabs (Identity · Allowed operations · Entity scope · Redaction · Rate limits &amp; quotas · Network/IP).
- Audit log listing: colored status/operation badges, per-row expandable metadata (`<details>`), prominent CSV/JSON export buttons, and a mini volume/allowed-vs-denied chart strip at the top (reusing `McpChartRenderer` + `McpMetrics`).
- Webhook delivery log: colored status badges (sent/failed/pending/failed_ssrf), per-row expandable payload/response (`<details>`), a status + endpoint filter form (`McpWebhookFilterForm`), and a CSRF-protected prune action.
- Approval queue: age and reason columns, a status filter, and a conditional "Approvals" dashboard tab (shown when `mcp_sentinel_approval` is enabled).

## [1.0.0-beta1] - 2026-06-02

> Hardening, test-coverage, and documentation work over `1.0.0-alpha2`
> (Phase 5). Additive only — no breaking changes. Notably closed a JSON:API
> entity-create governance bypass and three holistic-security-review findings.

### Security
- **Webhook SSRF guard now covers IPv6-only (AAAA) hosts (F17).**
  `McpWebhookWorker::validateAndResolveHost()` resolved only IPv4 A records, so a
  hostname with ONLY an AAAA record (e.g. resolving to `::1` or `fd00::/8`)
  slipped through unpinned and let cURL connect to a private IPv6 at send time.
  The worker now also resolves AAAA records, runs every resolved IP (v4 and v6)
  through the internal-range guard, blocks fail-closed if ANY resolved address is
  internal, and pins a public IPv6 via `CURLOPT_RESOLVE` using the bracketed
  `host:port:[ipv6]` format. HTTPS enforcement is unchanged.
- **IP allowlist now enforced at the write tools' `checkAccess()` (F15).** The
  three read tools gated the IP allowlist in `checkAccess()`, but the four write
  tools (`McpNodeOperationsTool`, `McpBulkOperationsTool`, `McpMediaUploadTool`,
  `McpWorkflowTransitionTool`) only checked the permission, so an IP-blocked
  governed agent could probe tool availability and the early-return error paths
  skipped the per-entity IP gate. Each write tool's `checkAccess()` now resolves
  the profile and, when governed and `isClientIpAllowed()` fails, returns
  `AccessResult::forbidden()` with `max-age 0`. Ungoverned accounts are unaffected.
- **JSON:API filter-access denials now carry cache contexts (cache-bleed fix,
  F16).** `McpAccessChecker::getJsonApiFilterAccess()` returned forbidden results
  without the `user.roles` + `oauth2_scopes` cache contexts every other governed
  result attaches, so the filter-access cache could serve a governed deny to a
  non-governed account (or vice-versa). Forbidden results now add those contexts
  plus the settings/profile cache tags, and are `max-age 0` when the profile has a
  non-empty `allowed_ips` list.
- **JSON:API entity creation is now governed (closed a write-plane bypass).**
  `hook_entity_access` does not fire for entity CREATE, so JSON:API `POST` (new
  entity) — routed through `_entity_create_access` → `hook_entity_create_access` —
  previously bypassed the write gate, the allowed/denied entity-type policy, and
  the IP allowlist. The module now implements `mcp_sentinel_entity_create_access`,
  delegating to a shared `McpAccessChecker::checkCreateAccess()` that enforces the
  master switch, IP allowlist, entity-type allow/deny policy, and write gate with
  the same cacheability rules. Create-access governance now matches existing-entity
  (PATCH/DELETE) semantics.
- **JSON:API IP allowlist now covers collections, not just individual resources.**
  The IP gate fired via `hook_entity_access` (individual `/{uuid}` reads) but the
  collection endpoint is governed by `hook_jsonapi_entity_filter_access`, which
  only checked entity-type allow/deny — so a governed agent from a disallowed IP
  could still enumerate collections. The IP allowlist is now enforced for ALL
  governed JSON:API traffic (collection, individual, and writes) at the
  `McpJsonApiPageLimitSubscriber` (`KernelEvents::REQUEST`) seam, which denies
  (403) when `isClientIpAllowed()` fails. Empty `allowed_ips` imposes no
  restriction; the individual-entity path remains gated by `hook_entity_access`
  (defence in depth).

### Added (tests)
- **GraphQL governance** (`mcp_sentinel_graphql`): redaction, DLP masking, and
  result-cap coverage for the field-results-alter hook, plus mutation/query
  gating and blocked-operation auditing.
- **Content tools**: behavioral kernel coverage for the node-operations,
  media-upload, and workflow-transition tools, and the content-lock, security-
  policy, and site-context tools.
- **OAuth agent-channel end-to-end** (`McpOauthChannelTest`): the role-fallback
  governed path enforces write gates over real HTTP, non-governed users are
  unaffected, successful governed writes are audited, and the OAuth-primary model
  ignores the `mcp_api` role when the fallback is disabled.
- **JSON:API write governance** (`McpJsonApiWriteGovernanceTest`,
  `McpContentToolGovernanceTest`): governed `POST`/`PATCH` blocked when
  `allow_write=FALSE` (403) and allowed when on, read-gate enforcement,
  denied-type and disallowed-IP blocks, the `page[limit]` cap via the live
  subscriber (400), and a non-governed admin bypassing Sentinel gates.
- **Phase 4 controls, functional** (`McpPhase4ControlsFunctionalTest`):
  rate-limit blocks after threshold; exfiltration page-cap returns 400 over real
  HTTP; IP allowlist denies an out-of-CIDR client (and permits when unrestricted);
  the anomaly detector fires on seeded audit rows and the dispatcher runs cleanly.
- **Governed-request harness trait** (`McpGovernedRequestTrait`): HTTP Basic auth
  and query-string support for the functional suite.
- **Server submodule registration** (`McpServerRegistrationTest`): every base
  Tool plugin is discoverable by `plugin.manager.tool`, instantiates without
  error, is covered by the `McpSentinelServerCommands::TOOLS` constant, and uses
  an `mcp:*` scope.
- **Drush commands** (`McpDrushCommandsTest`): all six base commands exercised
  directly — `audit-verify` (clean → success, tampered → failure), `webhook-prune`,
  `lock-clear`, `audit-purge`, `webhook-replay`, and `status`.
- **Update-hook chain 10001–10010** (`McpUpdateHookChainTest`): each hook
  individually (idempotency, schema and config end-state) plus a full-chain
  integration test that confirms the audit hash chain stays intact across the
  whole update path.
- **Uninstall cleanliness** (`McpUninstallTest`): the `mcp_sentinel_*` tables,
  module config (settings + all profiles), and `mcp_api` role are all removed,
  leaving no orphaned footprint.
- **Field-access redaction** (`McpFieldAccessRedactionTest`): governed agent on a
  redacted field is forbidden, non-governed users are neutral, non-view
  operations are not redacted, and results always carry the `user.roles` +
  `oauth2_scopes` cache contexts.
- **Create-access + cache invariants** (`McpAccessCheckerTest`,
  `McpIpAllowlistTest`): `checkCreateAccess()` write-gate, denied-type, allowlist,
  and master-switch cases, and `max-age 0` on all forbidden branches when
  `allowed_ips` is non-empty.

### Documentation
- Added `mcp_sentinel_help()` (`hook_help`) — a routed overview page at
  `/admin/help/mcp_sentinel` covering the trust model, capabilities, submodules,
  and links to the settings and audit routes.
- Added `INSTALL.md` (install steps, dependencies, submodule enablement, the
  OAuth/connector pointers, and the reverse-proxy requirement for IP allowlisting)
  and `API.md` (the `McpDestructiveOpEvent` veto seam, the `McpEntityEvent`
  audit/webhook seam, the Tool plugin contract, the policy-profile entity, and
  the public services).
- README: added a consolidated admin-routes and Drush-command reference, pointers
  to `INSTALL.md`/`API.md`, and a note explaining why `composer.json` keeps
  `minimum-stability: dev` (the dev-only `drupal/mcp_server` has no stable tag).
- Clarified the external tool-count claims: the README "66 tools" now
  unambiguously refers to the external `drupal-mcp-connector` Node connector (66
  connector tools across 9 modules), not Sentinel's own plugins; the
  `composer.json` suggest for `drupal/mcp_tools` cites that project's own count
  (222 tools across 34 submodules).

## [1.0.0-alpha2] - 2026-06-02

### Added
- **Per-profile IP allowlisting:**
  - A new `allowed_ips` field on every `mcp_policy_profile` config entity accepts
    a sequence of IPv4/IPv6 addresses and CIDR blocks. An empty list means no
    restriction (any IP permitted); this is the safe default and the value set by
    `update_10010` on all existing profiles.
  - `McpAccessChecker::checkEntityAccess()` now enforces the allowlist as an
    early-return check before operation gates. The client IP is obtained via
    Symfony's trusted-proxy-aware `Request::getClientIp()` — never from raw
    `X-Forwarded-For`/`X-Real-IP` headers — so an attacker who forges an allowed
    IP in a header cannot bypass the allowlist unless the connecting proxy is
    already in Drupal's `reverse_proxy_addresses` list.
  - IPv4/IPv6 single-address and CIDR matching is done by
    `Symfony\Component\HttpFoundation\IpUtils::checkIp()`, which is bundled with
    Drupal and handles both address families and prefix notation correctly.
  - The policy profile add/edit form gains an *IP allowlist* fieldset with a
    validated textarea (one IP or CIDR per line). Each line is validated on save
    with `filter_var()` plus CIDR prefix-length range checks; malformed entries
    are rejected. The field description documents the reverse-proxy requirement.
  - **Trusted-proxy requirement (IMPORTANT):** IP allowlisting requires Drupal's
    reverse-proxy settings to be correctly configured in `settings.php`
    (`$settings['reverse_proxy'] = TRUE` and `$settings['reverse_proxy_addresses']`).
    Without those settings, `getClientIp()` returns the proxy's IP rather than the
    real client's. The README documents this prominently. An empty `allowed_ips`
    list (the default) disables IP enforcement and is always safe to leave in place
    if trusted proxies are not configured.
  - Scope: enforcement covers the entity-access layer (`McpAccessChecker`,
    `hook_entity_access`) as well as `McpContentLockTool`, `McpSecurityPolicyTool`,
    `McpSiteContextTool`, and the `/drupal-mcp/context` endpoint. All governed
    paths enforce the same IP gate via a shared
    `McpAccessChecker::isClientIpAllowed()` helper — a single canonical
    implementation.
  - **Cache safety:** when a profile has a non-empty `allowed_ips` list, EVERY
    `AccessResult` returned by `checkEntityAccess()` is marked `max-age 0`
    (uncacheable). Client IP is not a Drupal cache context; a cached "allowed"
    result could be re-served to a later request from the same account but a
    different, disallowed IP. The `/drupal-mcp/context` response carries
    `Cache-Control: no-store` for the same reason.
  - The IP gate is applied strictly to governed requests (accounts for which a
    policy profile resolves). Ungoverned cookie-session traffic is never affected.
  - `update_10010` backfills `allowed_ips: []` on all existing profiles during a
    `drush updb` run.
- **Anomaly detection & alerting:** cron-evaluated rules over the MCP audit log
  stream. The new `McpAnomalyDetector` service (`mcp_sentinel.anomaly_detector`)
  evaluates all enabled anomaly rules on each cron run. Each rule specifies an
  `operation_pattern`, a `window_seconds` lookback, and a `count threshold`. When
  the count of matching rows within the window meets or exceeds the threshold,
  the rule fires. Patterns use an exact `=` match by default, so a pattern like
  `entity` does not silently match both `entity_save` and `entity_delete`; append
  `*` to opt in to prefix matching (`entity*` matches everything starting with
  `entity`). Alerts are dispatched through up to three channels via the new
  `McpAlertDispatcher` service (`mcp_sentinel.anomaly_alert_dispatcher`): the
  `mcp_sentinel` logger channel (warning-level; on by default), email (configured
  via `anomaly_alert_email`; disabled when empty), and webhook (enqueues an
  `mcp.anomaly.alert` event through the `McpWebhookQueueManager`, inheriting
  retry/SSRF/HMAC — enabled via `anomaly_alert_webhook`). Alert storms are
  prevented by mandatory debounce: a rule fires at most once per
  `debounce_seconds` (default 3600), stored in `@state` under
  `mcp_sentinel.anomaly_last_alert.{rule_id}`. Zero enabled rules ship by
  default — operators opt in per-site to avoid false positives during content
  imports. `update_10009` seeds the anomaly settings on existing installs. The
  settings form gains an *Anomaly detection* fieldset for enabling detection,
  configuring alert channels, and managing rules via a pipe-delimited textarea.
  - **Governed denied_access auditing:** to give the detector a reliable signal,
    all governed Tool plugins (`McpBulkOperationsTool`, `McpNodeOperationsTool`,
    `McpWorkflowTransitionTool`, `McpMediaUploadTool`) now write a `denied_access`
    audit row whenever a governed agent is denied by policy (`McpAccessChecker`)
    or core entity access. In `McpBulkOperationsTool`, one row is written per
    denied entity ID, so an agent hammering N forbidden deletes produces N rows —
    the correct input for a `denied_access_storm` count-threshold rule. The
    `audit_log_reads` toggle is intentionally ignored; `denied_access` is a
    security event logged whenever `audit_enabled` is true. Each row carries
    `tool`, `entity_type`, `id`, `operation`, and `reason` in its metadata. Scope
    is the explicit Tool execution path; JSON:API/GraphQL denial-logging is a
    future enhancement.
- **Reliable webhooks — queued delivery with retry/backoff, multiple endpoints,
  per-event filtering, delivery log + replay, and an SSRF guard:** webhook
  delivery moved off the old fire-and-forget `httpClient->requestAsync()` path
  (which silently lost notifications if PHP exited before the promise settled)
  onto the Drupal queue system. `McpEventDispatcher::dispatch()` keeps its public
  signature, but now enqueues via the new `McpWebhookQueueManager`
  (`mcp_sentinel.webhook_queue_manager`): for each enabled endpoint whose event
  filter matches, it writes a `pending` row to the new
  `mcp_sentinel_webhook_delivery` table and pushes an item onto the
  `mcp_sentinel_webhook_delivery` queue.
  - **Multiple endpoints + per-event filtering:** the new `webhook_endpoints`
    setting is a sequence of `{id, label, url, secret_key, events[], enabled}`
    maps. An endpoint receives only events whose name is in its `events` list
    (empty = all events). HTTPS is required.
  - **Retry + exponential backoff:** the `McpWebhookWorker` QueueWorker
    (`id: mcp_sentinel_webhook_delivery`, cron time 30 s) POSTs the signed body
    and, on a non-2xx response or network error, schedules a retry — 5 attempts
    with backoff intervals of 30 s, 5 min, 30 min, 2 h, 8 h. The delivery row's
    `next_attempt` gates early sends (not-yet-due rows are requeued unchanged);
    after the 5th attempt the row is marked `failed`. A row already `sent` (or
    terminally `failed`/`failed_ssrf`) short-circuits with no HTTP call, so a
    duplicate queue item or concurrent worker can never double-send.
  - **SSRF guard (two layers):** Layer 1 at enqueue time rejects non-HTTPS URLs
    and obvious internal literals (`localhost`, `127.*`, `0.0.0.0`, `::1`).
    Layer 2 runs in the worker at send time (DNS can rebind after enqueue):
    literal IPs are validated directly and hostnames are resolved via
    `gethostbynamel()`, blocking any address in a private/loopback/link-local/
    reserved range (RFC1918 `10/8`, `172.16/12`, `192.168/16`, link-local
    `169.254/16`, loopback `127/8` + `::1`, unique-local `fc00::/7`, etc.);
    blocked rows are marked `failed_ssrf`. A global `allow_internal_webhook_urls`
    flag (default `FALSE`) disables Layer 2 only for legitimate internal-network
    deployments; HTTPS enforcement always applies.
  - **HMAC signing:** the body is signed with HMAC-SHA256 using the endpoint's
    Key-resolved secret and sent in the `X-MCP-Signature: sha256=…` header.
  - **Delivery log UI + replay:** a report at
    `/admin/reports/mcp-sentinel/webhooks` (permission `administer mcp sentinel`)
    lists recent deliveries with status, attempts, last response code and next
    attempt. A CSRF-protected **Replay** action (and `drush
    mcp-sentinel:webhook-replay <id>`) resets a `failed`/`sent` row to `pending`,
    attempts `0`, and re-queues it.
  - **Retention/prune:** the `webhook_delivery_retention_days` setting (default
    30) bounds table growth; `drush mcp-sentinel:webhook-prune` and `hook_cron`
    delete rows older than the window.
  - **Migration:** `update_10007` creates the delivery-log table; `update_10008`
    seeds the retention/opt-out defaults and migrates a legacy single
    `webhook_url`/`webhook_secret_key`/`webhook_enabled` into one
    `webhook_endpoints` entry (legacy keys retained for review). The settings
    form gains a *Reliable webhooks* section managing endpoints, retention and
    the internal-URL opt-out, and keeps the legacy single-endpoint fields visible
    with a deprecation notice.
- **Per-profile exfiltration guards (result-count, response-size, JSON:API page
  ceiling):** each `mcp_policy_profile` now carries `result_count_cap` (default
  `0` = unlimited) and `response_size_cap` (default `0` = unlimited) fields. A
  cap of `0` short-circuits the guard; no overhead on unlimited profiles. The
  new `McpExfiltrationGuard` service (`mcp_sentinel.exfiltration_guard`) enforces
  both caps at three seams:
  - **Tool output** — `McpBulkOperationsTool` truncates the `succeeded` result
    list to `result_count_cap` before returning `ExecutableResult::success()`.
    When truncation occurs, `_result_truncated: true` and `_result_cap: <n>` are
    added to the result data so the agent is never silently misled. The
    `response_size_cap` is also enforced at this seam: because all write
    operations have already executed, the payload is **truncated** (not
    rejected) to fit under the cap — returning failure after a completed write
    batch would misreport success as failure and could trigger agent retries that
    toggle publish/unpublish state. When size truncation occurs, `_size_truncated:
    true` and `_size_cap: <n>` are added; the success message notes the
    truncation. Pure-read tools may still use `checkResponseSizeCap()` which
    returns `ExecutableResult::failure()` before any data is materialised.
  - **JSON:API page ceiling** — a `KernelEvents::REQUEST` subscriber
    (`McpJsonApiPageLimitSubscriber`, priority -20) intercepts `page[limit]`
    parameters for governed agents, throwing HTTP 400 before the query runs.
    Path matching uses `str_contains('/jsonapi/')` rather than
    `str_starts_with('/jsonapi/')` so that URL-language-negotiated paths such as
    `/en/jsonapi/node/article` are correctly governed. Non-positive `page[limit]`
    values (0, negative, non-numeric) are passed through without a cap comparison
    and left for JSON:API's own parameter validation. Note:
    `hook_jsonapi_resource_params_alter` does NOT exist in Drupal 11.3 core;
    this subscriber is the correct implementation path.
  - **GraphQL multi-value field lists** — `hook_graphql_compose_field_results_alter`
    in `mcp_sentinel_graphql.module` truncates field result lists to
    `result_count_cap` as a third pass after field-name redaction and DLP
    masking. Non-governed requests are unaffected.
  The profile add/edit form gains an *Exfiltration guards* fieldset exposing both
  cap fields. Recommended starting values: 500 result items / 2 097 152 bytes
  (2 MB). `update_10006` backfills both fields on existing
  profiles to `0` (unlimited). Ungoverned requests are never capped.
- **Per-profile rate limiting & quotas via core flood:** each `mcp_policy_profile`
  now carries `rate_limit_requests` (default `0` = unlimited) and
  `rate_limit_window` (default `60` seconds) fields. When `rate_limit_requests`
  is non-zero, the `McpRateLimiter` service (`mcp_sentinel.rate_limiter`)
  enforces the limit using Drupal's core `@flood` service. The flood key is
  `mcp_sentinel.profile.{profile_id}.{uid}` — keyed on the server-resolved
  authenticated UID only, preventing key-cycling bypass attacks. A `0` request
  limit short-circuits before touching flood. Enforcement fires at the top of
  all four governed Tool plugins: `mcp_sentinel_node_operations`,
  `mcp_sentinel_bulk_operations`, `mcp_sentinel_media_create`, and
  `mcp_sentinel_workflow_transition`. Over-limit calls log an audit row with
  operation `rate_limit_exceeded` and return a failure result equivalent to
  HTTP 429. The profile add/edit form gains a *Rate limits* fieldset with the
  two new fields. `update_10006` backfills the fields on existing profiles:
  `rate_limit_window` defaults to `60` (so that setting
  `rate_limit_requests > 0` on an upgraded profile takes effect immediately);
  `rate_limit_requests`, `result_count_cap`, and `response_size_cap` default
  to `0` (unlimited). Recommended prod starting point: 300 requests / 60 s
  window.
- **Tamper-evident audit log with HMAC hash chain + `audit-verify`:** every
  audit row stores a `prev_hash` (the preceding row's hash) and `row_hash`
  (HMAC-SHA256 of `prev_hash | canonical-JSON` when `audit_hash_key` is set to a
  Key entity ID, plain SHA-256 as a zero-config fallback). Any insertion,
  deletion, or modification of a historical row breaks the chain; run
  `drush mcp-sentinel:audit-verify` to detect it (exits non-zero if broken). The
  canonical includes the forensic columns `entity_label`, `ip_address`, and
  `user_agent` in fixed key order, and the read-latest-then-insert critical
  section is serialized via Drupal's lock service to prevent races under
  concurrent writes. `update_10003` adds the two columns; `update_10004` adds the
  `audit_hash_key` setting.
- **Redaction-aware change diffs in the audit log:** governed entity updates now
  include a `changes` map (`{field: {old, new}}`) in the audit metadata,
  capturing exactly what changed. Fields listed in the resolved policy profile's
  `redacted_fields` are stored as `[REDACTED]` (both old and new values), so
  sensitive field values never appear in the audit trail. Unchanged fields and
  internal revision-bookkeeping fields are omitted. Values are capped at 255
  characters and at most 50 fields are recorded per event.
- **Filterable audit log UI with CSV/JSON export:** the
  `/admin/reports/mcp-sentinel` listing now exposes a GET-based filter form
  (operation, entity type, UID, date range). A new
  `/admin/reports/mcp-sentinel/export` route (permission
  `view mcp sentinel audit log`) streams the filtered log as a CSV download by
  default or a JSON array when `?format=json` is requested. All metadata reads
  in the controller flow through `McpAuditLogger::decodeMetadata()`, the accessor
  seam that transparently decrypts at-rest-encrypted rows.
- **SIEM streaming via a dedicated logger channel:** when the *Enable SIEM
  streaming* setting (`siem_enabled`) is turned on, every successful audit write
  also emits an `info`-level record to the dedicated `mcp_sentinel_audit`
  logger channel. The message is the stable string `mcp_sentinel_audit_event`
  (suitable for log-aggregator grouping); all variable data is in a structured
  context array: `operation`, `uid`, `entity_type`, `bundle`, `entity_id`,
  `timestamp`, `row_hash`. Route the channel to syslog (via the core Syslog
  module or Monolog) to stream structured audit events to a SIEM without
  database polling. See the README for configuration details.
- **DLP value-pattern redaction + partial masking (opt-in):** a new
  `McpDlp` service scans governed field values against configurable PII
  patterns (email, US phone, SSN, 16-digit credit card, plus unlimited
  site-defined custom patterns) and either fully redacts matches
  (`[REDACTED]`) or applies partial masking (last-4 chars kept, rest
  replaced with `*`). Scanning is **off by default** (`dlp_enabled: false`);
  enable and configure under *Configuration → Web services → MCP Sentinel →
  Data Loss Prevention*, including a *Custom DLP patterns* textarea
  (`label|regex|mask` per line, validated on save). `update_10005` adds the new
  settings to existing installs.
  - **V1 wired output paths:** (a) GraphQL Compose field output (via
    `mcp_sentinel_graphql_graphql_compose_field_results_alter` in the
    `mcp_sentinel_graphql` submodule) and (b) the audit change-diff capture
    (`McpAuditLogger::computeChangeDiff`). JSON:API/REST per-value scanning
    is deferred to a future release (no stable per-value normalizer alter
    hook exists in Drupal core).
  - **Regex convention:** patterns store the PCRE body WITHOUT delimiters
    (e.g. `[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`). The service wraps
    each pattern in `#...#i` delimiters at runtime. Invalid patterns are
    silently skipped with a warning logged to the `mcp_sentinel` channel.
- **Approval-workflow submodule (`mcp_sentinel_approval`, optional):** an
  opt-in human-approval gate for governed destructive operations. When enabled,
  the base bulk-operations tool dispatches a veto-capable `McpDestructiveOpEvent`
  before each delete; the submodule's subscriber queues a pending
  `mcp_approval_request` content entity and vetoes execution, so the target is
  left intact and reported to the agent as *queued for approval*. Operators with
  the new **Approve MCP Sentinel operations** permission review the queue at
  `/admin/reports/mcp-sentinel/approvals` and approve or deny requests; approving
  replays the stored operation (re-checking the approver's delete access) and
  writes an `approval_decision` audit row. Gated operations are configurable
  (`gated_operations`, default `[delete]`). The base module has no dependency on
  the submodule — when it is absent the event is never vetoed and destructive
  operations proceed unchanged.

### Security
- **Optional at-rest encryption of audit metadata:** when
  `audit_encryption_profile` is set to an Encryption Profile entity ID (from
  drupal/encrypt), the `metadata` column of every new audit row is encrypted at
  rest. Reads transparently decrypt via the `decodeMetadata()` accessor with
  graceful fallback to plain JSON for pre-encryption rows, so no data migration
  is required when enabling encryption on an existing install. The hash chain
  continues to hash plaintext canonical content (encryption only affects
  storage), so `drush mcp-sentinel:audit-verify` remains reliable. An encryption
  failure at runtime logs a warning and falls back to storing plaintext for that
  row (audit entries are never dropped). drupal/encrypt is now a required
  dependency.

### Fixed
- **Non-string entity labels no longer fatal the audit logger:** for config
  entities (and some content entities) `$entity->label()` returns a
  `TranslatableMarkup` object rather than a string. The audit logger passed it
  straight to `substr()`, which throws a `TypeError` under PHP 8.x — turning a
  legitimate governed save/delete into a fatal inside
  `hook_entity_presave()`/`hook_entity_delete()`. The label is now cast to a
  string before truncation.
- **Approval executor hardening (`mcp_sentinel_approval`):** replay and
  identity-safety guards on `McpApprovalExecutor`. `approve()`/`deny()` throw if
  the request is not pending (no double execute / duplicate audit row);
  `approve()` validates the stored target entity type via `hasDefinition()`
  before loading storage; a missing approver delete-access on a still-present
  target leaves the request **pending** (no longer mislabelled approved) while
  genuinely unexecutable cases (target gone, unknown type, UUID mismatch) are
  recorded approved with `executed=false` plus a truthful `reason`; and the
  queued target is bound by **UUID** as well as id so a reused id cannot delete
  the wrong entity.
- **Bulk tool fail-closed dispatch:** in `McpBulkOperationsTool`, a throwable
  from the destructive-op event dispatch is now treated as a veto (the id is
  reported as *queued*), so a dispatcher-level error can never let a gated
  delete proceed or be miscounted as failed.
- **DLP fail-open on PCRE runtime error:** `McpDlp::replaceMatches()` detects a
  NULL return from `preg_replace`/`preg_replace_callback` (e.g. on a
  backtrack-limit hit) and returns the **original value unchanged** instead of
  silently coercing NULL to `''`, logging a warning. Previously a PCRE error
  would blank the field value.
- **DLP partial mode fully masks short matches:** in partial masking mode a
  match whose length is ≤ 4 characters (equal to `PARTIAL_KEEP`) is now
  **fully replaced with `*`** instead of returned verbatim; longer matches keep
  last-4 semantics.
- **DLP `us_phone` regex matches no-separator format:** `(555)123-4567` (closing
  area-code paren with no following separator) is now matched (the separator
  after `)` is optional).

### Notes
- Pre-1.0 and in active development. Track planned work and report issues in the
  [drupal.org issue queue](https://www.drupal.org/project/issues/mcp_sentinel).

## [1.0.0-alpha1] - 2026-06-01

### Added
- Security presets and operation gates: master on/off switch plus independent
  read / write / delete / GraphQL-mutation toggles.
- `mcp_policy_profile` config entity for per-agent governance policy (operation
  gates, entity allow/deny lists, field redaction, role bindings, weight).
  Resolved by role with a `default` profile fallback; `update_10002` migrates
  existing flat settings. Full admin UI at
  `/admin/config/services/mcp-sentinel/profiles`.
- `McpPolicyResolver` service: `isGoverned(account)` and `resolve(account)` —
  OAuth-channel-primary governance detection and role-based profile resolution
  with deterministic highest-weight tie-break.
- `McpOauthContext` service (`mcp_sentinel.oauth_context`) — reads the
  server-validated OAuth agent channel (consumer `client_id` + token scopes)
  for the current request. Single seam between MCP Sentinel and simple_oauth.
- `agent_oauth_clients`, `agent_scopes`, `governed_role_fallback` settings in
  `mcp_sentinel.settings` (schema + install defaults). Controls the OAuth
  channel detection; role fallback defaults to `false`.
- Field-level redaction unified across JSON:API/REST (stripped) and GraphQL
  (`[REDACTED]`) via `hook_entity_field_access` and the `user.roles` +
  `oauth2_scopes` cache contexts.
- Audit logging of every MCP entity operation and GraphQL query/mutation, with
  configurable retention and automatic pruning.
- Content locks with TTL-based expiry to prevent agents from overwriting content
  a human is editing.
- HMAC-SHA256-signed, HTTPS-only webhooks fired on MCP-driven entity changes.
- `/drupal-mcp/context` (rich site-schema endpoint) and `/drupal-mcp/health`
  (status probe) controllers; the `mcp_api` role created on install.
- Governed Tool API plugins: site context, security policy, content lock, node
  create/update, media create, workflow transition, and bulk operations.
- `mcp_sentinel_server` submodule — registers the Tool plugins with `mcp_server`
  and wires per-tool OAuth scopes (`drush mcp-sentinel:setup` / `:teardown`).
- `mcp_sentinel_graphql` submodule — mutation/read gating, field redaction, and
  audit for the GraphQL Compose endpoint, plus a GraphQL SDL discovery tool.
- Base Drush commands: `mcp-sentinel:status`, `:audit-purge`, `:lock-clear`.
- `docs/CONNECTOR.md` — the connector ↔ Drupal contract: grant type, token
  endpoint, per-environment Consumer + scopes + TTL runbook, agent policy
  profile values, and end-to-end verification procedure.
- `phpcs.xml.dist`, `phpstan.neon.dist` (level 6), and unit/kernel/functional
  test coverage.

### Security
- MCP governance triggers on the **validated OAuth agent channel**
  (consumer/scope on the request's access token), not on role alone. An admin's
  direct cookie-session Drupal UI is never governed; only token-bearing agent
  traffic is governed and audited.
- Per-tool `mcp:read`/`mcp:write` scope enforcement via `mcp_server_oauth`
  third-party settings on each `mcp_tool_config`. Run
  `drush mcp-sentinel:setup` to apply.
- Governed redaction and entity-access decisions vary by both `user.roles` and
  `oauth2_scopes` cache contexts, preventing agent-channel responses from being
  served to cookie-session requests for the same user.
- Governance also triggers on the agent's **authenticated roles** as a
  configurable local-dev fallback (`governed_role_fallback`, default `false`),
  not the spoofable `X-MCP-Client` header. An agent cannot bypass policy by
  omitting the header; a non-agent user cannot be governed by adding it.
- The HMAC webhook signing secret is resolved from a **Key** entity
  (`webhook_secret_key`) instead of being stored as plaintext in exported
  configuration. `update_10001` migrates any existing plaintext secret into a
  Key. drupal/key is a required dependency.
- The `/drupal-mcp/context` endpoint does not disclose the Drupal version.

### Fixed
- `allow_read` is enforced on JSON:API/REST reads (the `view` operation was
  previously ungated outside GraphQL).
- `McpContentLock::isLocked()` no longer writes (deletes expired rows) on every
  read; expired locks are excluded by a query condition and reaped by cron.
- Uninstalling the module now removes the `mcp_api` role it creates on install.

[Unreleased]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/2.11.0...1.x
[2.11.0]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/2.10.0...2.11.0
[2.10.0]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/2.9.0...2.10.0
[2.7.0]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/2.6.0...2.7.0
[2.6.0]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/2.5.0...2.6.0
[2.5.0]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/2.4.0...2.5.0
[1.0.0-beta4]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-beta3...1.0.0-beta4
[1.0.0-beta3]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-beta2...1.0.0-beta3
[1.0.0-beta2]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-beta1...1.0.0-beta2
[1.0.0-beta1]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-alpha2...1.0.0-beta1
[1.0.0-alpha2]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-alpha1...1.0.0-alpha2
[1.0.0-alpha1]: https://git.drupalcode.org/project/mcp_sentinel/-/tags/1.0.0-alpha1
