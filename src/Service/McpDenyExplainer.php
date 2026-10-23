<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpDenyExplanation;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Names the policy rule behind a deny and whether widening is appropriate.
 *
 * Fail-closed and secret-free. Never auto-widens an allowlist or denylist.
 * The formatted suffix is operator-facing (audit row and logs). Callers
 * receive callerMessage() only (DEV-966).
 */
final class McpDenyExplainer {

  /**
   * Generic caller-facing deny. No rule id, reason, or explainer suffix.
   */
  public const CALLER_MESSAGE = 'MCP access is denied.';

  /**
   * Entity types that must stay denied even when an allowlist is edited.
   */
  private const CREDENTIAL_TYPES = [
    'user',
    'oauth2_token',
    'key',
    'consumer',
    'encryption_profile',
  ];

  /**
   * Denied_access fingerprints already written for the current request.
   *
   * @var array<string, true>
   */
  private array $written = [];

  /**
   * Entity type+id and type+id+operation subjects for this request.
   *
   * @var array<string, true>
   */
  private array $recordedSubjects = [];

  /**
   * Request object-id the fingerprints belong to.
   */
  private mixed $writtenFor = NULL;

  /**
   * Constructs the explainer.
   *
   * @param \Psr\Log\LoggerInterface|null $logger
   *   Operator log channel. NULL in unit tests.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger|null $auditLogger
   *   HMAC audit chain. NULL in unit tests or the deploy window.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder|null $holder
   *   Sealed principal for this request. NULL when unknown.
   * @param \Symfony\Component\HttpFoundation\RequestStack|null $requestStack
   *   Current request, used to name the surface and dedupe one deny.
   */
  public function __construct(
    private readonly ?LoggerInterface $logger = NULL,
    private readonly ?McpAuditLogger $auditLogger = NULL,
    private readonly ?McpPrincipalContextHolder $holder = NULL,
    private readonly ?RequestStack $requestStack = NULL,
  ) {}

  /**
   * Builds a structured explanation from a deny reason string.
   *
   * @param string $reason
   *   Access-result reason or tool failure text. Must not contain secrets.
   * @param string|null $profileId
   *   Active policy profile id when known.
   *
   * @return \Drupal\mcp_sentinel\Value\McpDenyExplanation
   *   The explanation.
   */
  public function explain(string $reason, ?string $profileId = NULL): McpDenyExplanation {
    $profileHint = $profileId !== NULL && $profileId !== ''
      ? ' Edit policy profile "' . $profileId . '".'
      : ' Edit the active MCP policy profile.';

    if (str_contains($reason, 'reserved_identity_argument')
      || str_contains($reason, 'must not carry identity or tenant keys')) {
      return new McpDenyExplanation(
        'reserved_identity_argument',
        'identity argument rejected',
        FALSE,
        'Remove identity and tenant keys from tool arguments. Tenant and principal come only from the token.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'missing_tenant_claim')
      || str_contains($reason, 'require a tenant claim')) {
      return new McpDenyExplanation(
        'missing_tenant_claim',
        'tenant claim missing',
        FALSE,
        'Issue the agent token with a tenant claim. Never pass tenant as a tool argument.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'missing_dispatcher')
      || str_contains($reason, 'principal-context dispatcher is required')) {
      return new McpDenyExplanation(
        'missing_dispatcher',
        'principal dispatcher missing',
        FALSE,
        'Wire mcp_sentinel.principal_context_dispatcher and rebuild the container. A missing dispatcher is a stale cached container, not a missing caller token.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'reseal_refused')
      || str_contains($reason, 'cannot reseal')
      || str_contains($reason, 'already sealed')) {
      return new McpDenyExplanation(
        'reseal_refused',
        'principal reseal refused',
        FALSE,
        'A subrequest cannot change the sealed principal. Queue and Drush open a deny-only overlay per item.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'lookalike_check_unavailable')
      || str_contains($reason, 'requires ext-intl Spoofchecker')) {
      return new McpDenyExplanation(
        'lookalike_check_unavailable',
        'look-alike check unavailable',
        FALSE,
        'Install PHP ext-intl so Spoofchecker can detect reserved-key look-alike spellings. Governed calls fail closed until it is present.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'non_idp_issuer')
      || str_contains($reason, 'sole issuer')) {
      return new McpDenyExplanation(
        'non_idp_issuer',
        'non-IdP issuer',
        FALSE,
        'Paladin is the sole issuer for governed tools. Sealed tokens are refused by provenance or by iss urn:mcp-sentinel:sealed-token.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'required_scope_missing')
      || str_contains($reason, 'exact required OAuth scope')) {
      return new McpDenyExplanation(
        'required_scope_missing',
        'required OAuth scope missing',
        FALSE,
        'Mint a token that includes the exact required scope. Do not drop the scope check.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'principal_killed')) {
      return new McpDenyExplanation(
        'principal_killed',
        'agent kill switch',
        FALSE,
        'An operator must un-kill this principal before it may run again.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'missing_principal')
      || str_contains($reason, 'verified principal')) {
      return new McpDenyExplanation(
        'missing_principal',
        'verified principal missing',
        FALSE,
        'Issue a Paladin token with iss, sub, and azp or act.sub. Drupal uid is not a subject.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'classification_egress_denied')) {
      return new McpDenyExplanation(
        'classification_egress_denied',
        'classification egress ceiling',
        FALSE,
        'Lower the content classification or raise the profile ceiling only if a human intends that egress. Classification only ever denies more.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'policy_bundle_denied')) {
      return new McpDenyExplanation(
        'policy_bundle_denied',
        'attested policy bundle floor',
        FALSE,
        'Local deny cannot be widened by an upstream allow. Roll back or replace the attested bundle as an operator.',
        'Stay denied.',
      );
    }

    foreach (McpGovernanceReadinessReason::cases() as $code) {
      if (str_contains($reason, $code->value)) {
        return new McpDenyExplanation(
          $code->value,
          'source-governance contract',
          FALSE,
          $code->nextStep(),
          'Stay denied until the named gate is fixed. Do not widen an allowlist as a substitute.',
        );
      }
    }

    if (preg_match("/Entity type '([^']+)' is denied by MCP Sentinel/", $reason, $matches)) {
      $type = $matches[1];
      $credential = in_array($type, self::CREDENTIAL_TYPES, TRUE);
      return new McpDenyExplanation(
        'entity_type_denied',
        'entity-type denylist',
        !$credential,
        $credential
          ? 'Keep "' . $type . '" on the denylist. Credential-bearing types must stay denied.'
          : 'A human may remove "' . $type . '" from denied_entity_types if that type is editorial.' . $profileHint,
        $credential ? 'Stay denied.' : 'Human review only.',
      );
    }
    if (preg_match("/Entity type '([^']+)' is not in the MCP Sentinel allowlist/", $reason, $matches)) {
      $type = $matches[1];
      $credential = in_array($type, self::CREDENTIAL_TYPES, TRUE);
      return new McpDenyExplanation(
        'entity_type_allowlist',
        'entity-type allowlist',
        !$credential,
        $credential
          ? 'Do not add "' . $type . '" to the allowlist. Credential-bearing types stay out of agent scope.'
          : 'A human may add "' . $type . '" to allowed_entity_types if that type is editorial.' . $profileHint,
        $credential ? 'Stay denied.' : 'Human review only.',
      );
    }
    if (str_contains($reason, 'is denied by MCP Sentinel') && str_contains($reason, 'Configuration')) {
      return new McpDenyExplanation(
        'config_prefix_denied',
        'denied_config_types prefix denylist',
        FALSE,
        'Prefix denylist always wins. Do not remove secret-bearing prefixes such as key., encrypt., simple_oauth., or consumer.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'Write operations are disabled')) {
      return new McpDenyExplanation(
        'allow_write',
        'write gate',
        TRUE,
        'A human may enable writes on the policy profile for an editorial type. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'Read operations are disabled')) {
      return new McpDenyExplanation(
        'allow_read',
        'read gate',
        TRUE,
        'A human may enable reads on the policy profile. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'Delete operations are disabled')) {
      return new McpDenyExplanation(
        'allow_delete',
        'delete gate',
        TRUE,
        'A human may enable delete on the policy profile. Destructive ops may still need approval. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'Source IP not permitted')) {
      return new McpDenyExplanation(
        'ip_allowlist',
        'IP allowlist',
        TRUE,
        'A human may add this operator network to allowed_ips. Do not empty the list in production to skip the gate.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'MCP access is disabled')) {
      return new McpDenyExplanation(
        'module_disabled',
        'master switch',
        FALSE,
        'Turn on Enable MCP API access in MCP Sentinel settings. Do not widen a profile to bypass the master switch.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'no governance profile')) {
      return new McpDenyExplanation(
        'no_governance_profile',
        'governance profile',
        FALSE,
        'Assign a policy profile to this account. Do not widen an allowlist as a substitute.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'publishing is not permitted')
      || str_contains($reason, 'deny_publish')) {
      return new McpDenyExplanation(
        'deny_publish',
        'publish gate',
        TRUE,
        'A human publisher must publish. A human may turn off deny_publish on the profile if agents may go live.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'Rate limit exceeded')
      || str_contains($reason, 'request budget exceeded')
      || str_contains($reason, 'page budget exceeded')) {
      return new McpDenyExplanation(
        'rate_limit',
        'rate or read budget',
        TRUE,
        'Retry after the window, or a human may raise the profile budget. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'exceeds the MCP Sentinel cap')
      || str_contains($reason, 'response size cap')) {
      return new McpDenyExplanation(
        'response_size_cap',
        'response size cap',
        TRUE,
        'Narrow the query, or a human may raise the profile response_size_cap. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'tenant_mismatch')) {
      return new McpDenyExplanation(
        'tenant_mismatch',
        'tenant resource boundary',
        FALSE,
        'The sealed network tenant does not own this resource. Never pass tenant as a tool argument.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'Scheduled transition is not permitted')) {
      return new McpDenyExplanation(
        'scheduled_transition',
        'scheduled publish transition',
        TRUE,
        'A human may raise max_moderation_state or allow the scheduled transition on the profile.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'secret-bearing') || str_contains($reason, 'holds secrets')) {
      return new McpDenyExplanation(
        'secret_bearing_config',
        'secret-bearing configuration',
        FALSE,
        'Do not write key material or secret-bearing config names through a governed tool.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'config validation')
      || str_contains($reason, 'has no schema')
      || str_contains($reason, 'schema validation failed')) {
      return new McpDenyExplanation(
        'config_validation',
        'config write validation',
        TRUE,
        'Fix the named property paths or schema. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'denied by policy') || str_contains($reason, 'Denied by MCP Sentinel') || str_contains($reason, 'Not in MCP Sentinel allowlist')) {
      return new McpDenyExplanation(
        'policy_default',
        'policy profile',
        TRUE,
        'Inspect the active policy profile allow/deny lists and operation gates. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    // Named so operators do not get the unspecified fallback.
    if (str_contains($reason, 'graphql_operation_type')) {
      return new McpDenyExplanation(
        'graphql_operation_type',
        'unsupported GraphQL operation kind',
        FALSE,
        'Use query, mutation, or subscription. Other GraphQL operation kinds stay denied.',
        'Stay denied.',
      );
    }

    return new McpDenyExplanation(
      'unspecified',
      'policy profile',
      FALSE,
      'Inspect the audit log and the active policy profile. Do not widen an allowlist without a named rule.',
      'Stay denied until the rule is identified.',
    );
  }

  /**
   * Appends the explanation to a deny reason without duplicating it.
   *
   * Operator-facing only. Never send this string to a caller.
   *
   * @param string $reason
   *   Original deny reason.
   * @param string|null $profileId
   *   Active policy profile id when known.
   *
   * @return string
   *   Reason plus a non-secret rule suffix.
   */
  public function annotate(string $reason, ?string $profileId = NULL): string {
    if (str_contains($reason, '[rule:')) {
      return $reason;
    }
    return $reason . ' ' . $this->explain($reason, $profileId)->format();
  }

  /**
   * Generic deny the caller is allowed to see.
   */
  public function callerMessage(): string {
    return self::CALLER_MESSAGE;
  }

  /**
   * Logs the operator explainer, audits, and returns the generic caller deny.
   *
   * Every caller-facing deny must go through this method (DEV-966).
   *
   * @param string $reason
   *   Original deny reason. Written to the operator log and HMAC row.
   * @param string|null $profileId
   *   Active policy profile id when known.
   * @param bool $audit
   *   FALSE when the caller already wrote an HMAC row for this deny.
   * @param string|null $entityType
   *   Entity type of the refused subject, when known.
   * @param string|null $entityId
   *   Entity id of the refused subject, or '(new)'.
   * @param string|null $operation
   *   Entity operation that was refused, when known.
   *
   * @return string
   *   CALLER_MESSAGE. Never the annotated reason.
   */
  public function refuse(
    string $reason,
    ?string $profileId = NULL,
    bool $audit = TRUE,
    ?string $entityType = NULL,
    ?string $entityId = NULL,
    ?string $operation = NULL,
  ): string {
    $annotated = $this->operatorNotice($reason, $profileId);
    if ($audit) {
      $this->writeDeniedAccess(
        $reason,
        $annotated,
        $profileId,
        $entityType,
        $entityId,
        $operation,
      );
    }
    return self::CALLER_MESSAGE;
  }

  /**
   * Whether refuse() already wrote a denied_access row for this request.
   *
   * Tools that call $entity->access() after a pre-check skip their own
   * HMAC row when the access hook already recorded the deny. With no
   * current request (a queue worker) this is always FALSE so denials
   * are not collapsed across jobs.
   *
   * @param string|null $entityType
   *   Entity type to match, or NULL for any deny this request.
   * @param string|null $entityId
   *   Entity id to match.
   * @param string|null $operation
   *   Entity operation to match, or NULL for any operation.
   *
   * @return bool
   *   TRUE when this request already has a refuse() HMAC row.
   */
  public function recordedThisRequest(
    ?string $entityType = NULL,
    ?string $entityId = NULL,
    ?string $operation = NULL,
  ): bool {
    $request = $this->requestStack?->getCurrentRequest();
    if ($request === NULL) {
      return FALSE;
    }
    if ($this->writtenFor !== spl_object_id($request)) {
      return FALSE;
    }
    if ($entityType === NULL && $entityId === NULL) {
      return $this->written !== [];
    }
    $subject = ($entityType ?? '') . "\0" . ($entityId ?? '');
    if ($operation !== NULL && $operation !== '') {
      $subject .= "\0" . $operation;
    }
    return isset($this->recordedSubjects[$subject]);
  }

  /**
   * Writes one denied_access row with the rule, explain, and principal.
   *
   * AccessResult construction must still return forbidden when the chain
   * is not installed (kernel tests without the audit schema).
   *
   * @param string $reason
   *   Original deny reason. Must not contain secrets.
   * @param string $explain
   *   Annotated operator suffix already logged.
   * @param string|null $profileId
   *   Active policy profile id when known.
   * @param string|null $entityType
   *   Entity type of the refused subject, when known.
   * @param string|null $entityId
   *   Entity id of the refused subject, or '(new)'.
   * @param string|null $operation
   *   Entity operation that was refused, when known.
   */
  private function writeDeniedAccess(
    string $reason,
    string $explain,
    ?string $profileId,
    ?string $entityType = NULL,
    ?string $entityId = NULL,
    ?string $operation = NULL,
  ): void {
    if ($this->auditLogger === NULL) {
      return;
    }
    $request = $this->requestStack?->getCurrentRequest();
    $explanation = $this->explain($reason, $profileId);
    $surface = $request !== NULL
      ? McpGovernedSurface::fromPath($request->getPathInfo())
      : NULL;
    $meta = [
      'tool' => $surface instanceof McpGovernedSurface ? $surface->value : 'entity_access',
      'reason' => $reason,
      'explain' => $explain,
      'rule' => $explanation->ruleId,
    ];
    if ($entityType !== NULL && $entityType !== '') {
      $meta['entity_type'] = $entityType;
    }
    if ($entityId !== NULL && $entityId !== '') {
      $meta['id'] = $entityId;
    }
    if ($operation !== NULL && $operation !== '') {
      $meta['operation'] = $operation;
    }
    if ($profileId !== NULL && $profileId !== '') {
      $meta['profile'] = $profileId;
    }
    $ctx = $this->holder?->get();
    if ($ctx !== NULL) {
      try {
        $meta['principal_key'] = $ctx->principalKey();
        $meta['human_key'] = $ctx->humanKey();
        $meta['iss'] = $ctx->issuer();
        $meta['sub'] = $ctx->subject();
        $meta['tenant'] = $ctx->tenant();
      }
      catch (McpPrincipalKeyException $e) {
        $meta['principal_key'] = 'unverified';
        $meta['human_key'] = 'unverified';
        $meta['principal_unverified'] = $e->reasonCode;
      }
    }
    else {
      // refuse() runs before a principal is sealed when the
      // dispatcher service is missing. The row still names the
      // principal slot so it is not mistaken for a verified denial.
      $meta['principal_key'] = 'unverified';
      $meta['human_key'] = 'unverified';
    }

    // A queue worker has no request; never collapse those writes.
    if ($request === NULL) {
      $this->emitDeniedAccess($meta);
      return;
    }

    $requestId = spl_object_id($request);
    if ($requestId !== $this->writtenFor) {
      $this->written = [];
      $this->recordedSubjects = [];
      $this->writtenFor = $requestId;
    }
    $hasSubject = $entityType !== NULL && $entityType !== ''
      && $entityId !== NULL && $entityId !== '';
    $subject = ($entityType ?? '') . "\0" . ($entityId ?? '');
    $fingerprint = $explanation->ruleId . "\0" . $reason . "\0"
      . ($entityType ?? '') . "\0" . ($entityId ?? '') . "\0"
      . ($operation ?? '');
    if (isset($this->written[$fingerprint])) {
      return;
    }
    $this->written[$fingerprint] = TRUE;
    if ($hasSubject) {
      $this->recordedSubjects[$subject] = TRUE;
      if ($operation !== NULL && $operation !== '') {
        $this->recordedSubjects[$subject . "\0" . $operation] = TRUE;
      }
    }
    $this->emitDeniedAccess($meta);
  }

  /**
   * Appends one denied_access row, swallowing a missing chain.
   *
   * @param array<string, mixed> $meta
   *   HMAC metadata. Must not contain secrets.
   */
  private function emitDeniedAccess(array $meta): void {
    if ($this->auditLogger === NULL) {
      return;
    }
    try {
      $this->auditLogger->logAlways('denied_access', $meta);
    }
    catch (\Throwable $e) {
      $this->logger?->error('MCP Sentinel denied_access write failed: @m', [
        '@m' => $e->getMessage(),
      ]);
    }
  }

  /**
   * Annotates the reason, writes it to the operator log, and returns it.
   *
   * @param string $reason
   *   Original deny reason.
   * @param string|null $profileId
   *   Active policy profile id when known.
   *
   * @return string
   *   Reason plus a non-secret rule suffix.
   */
  public function operatorNotice(string $reason, ?string $profileId = NULL): string {
    $annotated = $this->annotate($reason, $profileId);
    $this->logger?->notice('MCP Sentinel deny: @explain', [
      '@explain' => $annotated,
    ]);
    return $annotated;
  }

}
