<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Dispatches a tool handler as handler(args, ctx).
 *
 * Identity and tenant come only from the frozen token context. The
 * reserved-key and principal checks run on the exact argument array
 * passed to the handler / doExecute() — never a raw HTTP body. A
 * network or sealed-token HTTP call without a tenant claim fails
 * closed. Every denial writes a denied_access audit row that carries
 * the verified principal keys (or an unverified marker). Denial rows
 * are always written; audit_enabled gates allow rows only.
 */
final class McpPrincipalContextDispatcher {

  /**
   * Deny-row reason under a job overlay. Never sent to the caller.
   */
  private const OVERLAY_DENY_REASON = 'job_overlay';

  /**
   * Caller-facing refusal used for both a missing principal and a kill.
   *
   * A killed principal must not produce a distinct signal (DEV-846).
   */
  public const GENERIC_REFUSAL = 'A verified principal context is required.';

  /**
   * Constructs the dispatcher.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextFactory $factory
   *   Builds the frozen context from the validated token.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   Request stack used to key the write-once holder.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextGuard $guard
   *   On/off switch (always on outside PHPUnit injection).
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   Write-once sealed context for this request.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Writes denied_access rows.
   * @param \Psr\Log\LoggerInterface $logger
   *   Fallback when a denial audit write fails.
   * @param \Drupal\mcp_sentinel\Service\McpKillEnforcerInterface $killSwitch
   *   Kill registry checked on every admit() before doExecute.
   */
  public function __construct(
    private readonly McpPrincipalContextFactory $factory,
    private readonly RequestStack $requestStack,
    private readonly McpPrincipalContextGuard $guard,
    private readonly McpPrincipalContextHolder $holder,
    private readonly McpAuditLogger $auditLogger,
    private readonly LoggerInterface $logger,
    private readonly McpKillEnforcerInterface $killSwitch,
  ) {}

  /**
   * Runs handler($args, $ctx) after the identity/tenant preflight.
   *
   * @param callable(array<string, mixed>, \Drupal\mcp_sentinel\Value\McpPrincipalContext): mixed $handler
   *   The tool handler. Receives arguments and the frozen context.
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments (the exact handler/doExecute map).
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   * @param list<string> $reservedExceptions
   *   Declared schema input names that may be exempted.
   * @param array<string, array{allow?: list<string>, refuse?: list<string>}> $nestedMapRules
   *   Field-definition rules for named nested maps (e.g. fields).
   *
   * @return mixed
   *   Whatever the handler returns.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   Reserved identity keys, missing principal, or missing tenant.
   */
  public function dispatch(
    callable $handler,
    array $arguments,
    string $toolId = 'mcp_principal_dispatch',
    array $reservedExceptions = [],
    array $nestedMapRules = [],
  ): mixed {
    $ctx = $this->admit(
      $arguments,
      $toolId,
      $reservedExceptions,
      $nestedMapRules,
    );
    return $handler($arguments, $ctx);
  }

  /**
   * Preflight + seal for the exact values about to reach doExecute().
   *
   * @param array<string, mixed> $arguments
   *   The array ToolBase::execute() will pass to doExecute().
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   * @param list<string> $reservedExceptions
   *   Declared schema input names that may be exempted.
   * @param array<string, array{allow?: list<string>, refuse?: list<string>}> $nestedMapRules
   *   Field-definition rules for named nested maps (e.g. fields).
   *
   * @return \Drupal\mcp_sentinel\Value\McpPrincipalContext
   *   The sealed context.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and the call is not allowed.
   */
  public function admit(
    array $arguments,
    string $toolId,
    array $reservedExceptions = [],
    array $nestedMapRules = [],
  ): McpPrincipalContext {
    if ($this->holder->inJobScope()) {
      $this->assertNotKilled($toolId);
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        self::GENERIC_REFUSAL,
        self::OVERLAY_DENY_REASON,
      );
    }
    $this->sealOnceFromRequest($toolId);
    $this->assertArgumentsAllowed(
      $arguments,
      $toolId,
      $reservedExceptions,
      $nestedMapRules,
    );
    // Hand out the sealed slot only. Never fall back to a rebuild
    // from attributes that may have been replaced since the seal.
    $sealed = $this->holder->get();
    if (!$sealed instanceof McpPrincipalContext) {
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        self::GENERIC_REFUSAL,
      );
    }
    $this->assertContextAllowed($sealed, $toolId);
    $this->assertNotKilled($toolId, $sealed);
    return $sealed;
  }

  /**
   * Refuses reserved identity keys, a missing principal, or tenant.
   *
   * Uses the sealed context, or seals once from the current request
   * when nothing is sealed. Never rebuilds from live attributes
   * after a seal, and never inherits identity under a job overlay.
   *
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   * @param list<string> $reservedExceptions
   *   Declared schema input names that may be exempted.
   * @param array<string, array{allow?: list<string>, refuse?: list<string>}> $nestedMapRules
   *   Field-definition rules for named nested maps (e.g. fields).
   * @param list<string> $requiredScopes
   *   Any-of OAuth scopes the sealed token must carry. Empty skips
   *   the check. A context with no granted scopes (role-fallback /
   *   fixture) is also skipped so local-dev sessions stay on the
   *   readiness fallback path.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and the call is not allowed.
   */
  public function assertDispatchAllowed(
    array $arguments,
    string $toolId,
    array $reservedExceptions = [],
    array $nestedMapRules = [],
    array $requiredScopes = [],
  ): void {
    if ($this->holder->inJobScope()) {
      $this->assertNotKilled($toolId);
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        self::GENERIC_REFUSAL,
        self::OVERLAY_DENY_REASON,
      );
    }
    $this->sealOnceFromRequest($toolId);
    $this->assertArgumentsAllowed(
      $arguments,
      $toolId,
      $reservedExceptions,
      $nestedMapRules,
    );
    $sealed = $this->holder->get();
    if (!$sealed instanceof McpPrincipalContext) {
      // Behind the guard so disableForTest() admits a missing
      // principal and the surface deny tests can go red.
      if (!$this->guard->required()) {
        return;
      }
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        self::GENERIC_REFUSAL,
      );
    }
    $this->assertContextAllowed($sealed, $toolId);
    $this->assertNotKilled($toolId, $sealed);
    $this->assertScopesAllowed($sealed, $toolId, $requiredScopes);
  }

  /**
   * Refuses reserved identity keys in the exact handler argument map.
   *
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   * @param list<string> $reservedExceptions
   *   Declared schema input names that may be exempted.
   * @param array<string, array{allow?: list<string>, refuse?: list<string>}> $nestedMapRules
   *   Field-definition rules for named nested maps (e.g. fields).
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and a reserved key is present.
   */
  private function assertArgumentsAllowed(
    array $arguments,
    string $toolId,
    array $reservedExceptions,
    array $nestedMapRules = [],
  ): void {
    if (!$this->guard->required()) {
      return;
    }
    try {
      $reserved = McpPrincipalContext::reservedKeysIn(
        $arguments,
        $reservedExceptions,
        $nestedMapRules,
      );
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->deny($toolId, $e->reasonCode, $e->getMessage());
    }
    if ($reserved !== []) {
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        'Tool arguments must not carry identity or tenant keys ('
        . implode(', ', $reserved)
        . '). Identity comes from the validated token context.',
      );
    }
  }

  /**
   * Seals once from the current request when the holder is empty.
   *
   * Callers run this before reserved-key checks so a denial row can
   * name the sealed principal. Never rebuilds from live attributes
   * after a seal.
   *
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the request cannot be sealed.
   */
  private function sealOnceFromRequest(string $toolId): void {
    $request = $this->requestStack->getCurrentRequest();
    if ($this->holder->get() !== NULL || $request === NULL) {
      return;
    }
    try {
      $this->holder->seal($this->factory->fromCurrentRequest(), $request);
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->writeDenialAudit($toolId, $e->reasonCode);
      throw $e;
    }
  }

  /**
   * Refuses a context with no tenant on a network call or no principal.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $ctx
   *   The context the handler would receive.
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and the context is not allowed.
   */
  private function assertContextAllowed(McpPrincipalContext $ctx, string $toolId): void {
    if (!$this->guard->required()) {
      return;
    }
    if ($ctx->fromSealedToken()
      || $ctx->issuer() === McpSealedTokenManager::ISSUER) {
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::NON_IDP_ISSUER,
        'Paladin is the sole issuer for governed tools (DEV-843).',
      );
    }
    if ($ctx->isNetwork() && $ctx->tenant() === '') {
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
        'Network calls require a tenant claim on the validated token (DEV-839).',
      );
    }
    try {
      McpPrincipalKey::fromClaims($ctx->keyClaims());
    }
    catch (McpPrincipalKeyException $e) {
      $this->deny(
        $toolId,
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        'A verified principal is required (iss, sub, and azp or act.sub): '
        . $e->reasonCode
        . '.',
      );
    }
  }

  /**
   * Refuses a token whose granted scopes miss every required name.
   *
   * Empty $requiredScopes, or a context that granted none, skips so
   * role-fallback and kernel fixture principals stay on readiness.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $ctx
   *   The sealed context.
   * @param string $toolId
   *   Surface or tool id for the audit row.
   * @param list<string> $requiredScopes
   *   Any-of required scope names.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and no required scope is granted.
   */
  private function assertScopesAllowed(
    McpPrincipalContext $ctx,
    string $toolId,
    array $requiredScopes,
  ): void {
    if (!$this->guard->required() || $requiredScopes === [] || $ctx->scopes() === []) {
      return;
    }
    foreach ($requiredScopes as $scope) {
      if (in_array($scope, $ctx->scopes(), TRUE)) {
        return;
      }
    }
    $this->deny(
      $toolId,
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      'The token is missing the exact required OAuth scope.',
    );
  }

  /**
   * Sealed context for the current request. Never a live rebuild.
   *
   * Inside a job overlay this refuses: the overlay hides the request
   * and never holds a caller-built context.
   */
  public function context(): McpPrincipalContext {
    if ($this->holder->inJobScope()) {
      $this->assertNotKilled('mcp_principal_context');
      $this->deny(
        'mcp_principal_context',
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        self::GENERIC_REFUSAL,
        self::OVERLAY_DENY_REASON,
      );
    }
    $sealed = $this->holder->get();
    if ($sealed instanceof McpPrincipalContext) {
      $this->assertNotKilled('mcp_principal_context', $sealed);
      return $sealed;
    }
    $this->deny(
      'mcp_principal_context',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      self::GENERIC_REFUSAL,
    );
  }

  /**
   * Sealed context tools must read. Never the request attribute.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When nothing is sealed or the sealed context has no subject.
   */
  public function sealedContext(): McpPrincipalContext {
    $ctx = $this->holder->get();
    if ($ctx instanceof McpPrincipalContext && $ctx->subject() !== '') {
      return $ctx;
    }
    throw new McpPrincipalContextDeniedException(
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      self::GENERIC_REFUSAL,
    );
  }

  /**
   * Writes a denied_access row with verified keys or an unverified marker.
   *
   * Written through logAlways(), the same as break-glass: a principal
   * denial is recorded even when audit_enabled is off. The principal is
   * the sealed context when one is visible; under an overlay it is an
   * empty deny-only context. X-MCP-Client is not set here. The logger
   * records it as mcp_client, labeled self-reported only.
   */
  public function writeDenialAudit(string $toolId, string $reasonCode): void {
    $this->logDenial($toolId, $reasonCode, $this->auditContext());
  }

  /**
   * Writes one denied_access row for $ctx.
   *
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   * @param string $reasonCode
   *   Denial reason.
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $ctx
   *   Principal recorded on the row.
   */
  private function logDenial(
    string $toolId,
    string $reasonCode,
    McpPrincipalContext $ctx,
  ): void {
    $metadata = self::denialAuditMetadata($toolId, $reasonCode, $ctx);
    $carried = $this->holder->carriedPrincipal();
    if ($carried !== NULL) {
      $metadata['principal_key'] = 'unverified';
      $metadata['human_key'] = 'unverified';
      $metadata['principal_unverified'] = 'carried_queue_key';
    }
    $this->auditLogger->logAlways('denied_access', $metadata);
  }

  /**
   * Denial context with no principal.
   *
   * @return \Drupal\mcp_sentinel\Value\McpPrincipalContext
   *   An empty context.
   */
  private function emptyDenialContext(): McpPrincipalContext {
    return new McpPrincipalContext('', '', '', '', [], '', [], FALSE);
  }

  /**
   * Metadata for a principal-context denial.
   *
   * @return array<string, string>
   *   Audit metadata including principal_key / human_key or unverified.
   */
  public static function denialAuditMetadata(
    string $toolId,
    string $reasonCode,
    McpPrincipalContext $ctx,
  ): array {
    $meta = [
      'tool' => $toolId !== '' ? $toolId : 'unknown_tool',
      'entity_type' => 'principal',
      'id' => $ctx->subject() !== '' ? $ctx->subject() : 'unverified',
      'operation' => 'dispatch',
      'reason' => $reasonCode,
    ];
    try {
      $keys = McpPrincipalKey::fromClaims($ctx->keyClaims());
      $meta['principal_key'] = $keys['principalKey'];
      $meta['human_key'] = $keys['humanKey'];
      $meta['iss'] = $ctx->issuer();
      $meta['sub'] = $ctx->subject();
      $meta['tenant'] = $ctx->tenant();
      $parts = explode(McpPrincipalKey::SEPARATOR, $keys['principalKey']);
      $meta['actor'] = $parts[2] ?? '';
    }
    catch (McpPrincipalKeyException $e) {
      $meta['principal_key'] = 'unverified';
      $meta['human_key'] = 'unverified';
      $meta['principal_unverified'] = $e->reasonCode;
      $meta['unverified_reason'] = $reasonCode;
      if ($ctx->issuer() !== '') {
        $meta['iss'] = $ctx->issuer();
      }
      if ($ctx->subject() !== '') {
        $meta['sub'] = $ctx->subject();
      }
      if ($ctx->azp() !== '') {
        $meta['azp'] = $ctx->azp();
      }
      if ($ctx->tenant() !== '') {
        $meta['tenant'] = $ctx->tenant();
      }
    }
    return $meta;
  }

  /**
   * Context for a denial row. Never a live request rebuild.
   *
   * The sealed context when one is visible. Otherwise an empty
   * deny-only context: no identity from request attributes.
   */
  private function auditContext(): McpPrincipalContext {
    $held = $this->holder->get();
    if ($held instanceof McpPrincipalContext) {
      return $held;
    }
    return $this->emptyDenialContext();
  }

  /**
   * Whether a request principal is visible outside any job overlay.
   *
   * A local operator command has none. A deny-only overlay hides any
   * request seal and never inherits identity.
   */
  public function hasSealedContext(): bool {
    return !$this->holder->inJobScope()
      && $this->holder->get() instanceof McpPrincipalContext;
  }

  /**
   * Writes a denied_access row and throws.
   *
   * An audit outage must not replace the denial. The caller still
   * receives the access exception and can return 403 or a non-zero
   * exit instead of an uncaught 500. A failed write is logged.
   *
   * $auditReason may differ from $reasonCode so a kill records
   * principal_killed on the row while the caller still sees the
   * generic missing-principal refusal (DEV-846).
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   */
  private function deny(
    string $toolId,
    string $reasonCode,
    string $message,
    ?string $auditReason = NULL,
  ): never {
    $rowReason = $auditReason ?? $reasonCode;
    try {
      $this->logDenial($toolId, $rowReason, $this->auditContext());
    }
    catch (\Throwable $e) {
      $this->logger->error(
        'Principal-context denial audit write failed (@reason): @message',
        [
          '@reason' => $rowReason,
          '@message' => $e->getMessage(),
        ],
      );
    }
    throw new McpPrincipalContextDeniedException($reasonCode, $message);
  }

  /**
   * Refuses a killed sealed or carried principal with a generic deny.
   *
   * Behind the principal-context guard so a red run that injects
   * disableForTest() does not enforce the kill (DEV-846).
   *
   * @param string $toolId
   *   Real tool plugin id for the audit row.
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext|null $ctx
   *   Sealed context when one is visible.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   */
  private function assertNotKilled(string $toolId, ?McpPrincipalContext $ctx = NULL): void {
    if (!$this->guard->required()) {
      return;
    }
    $carried = $this->holder->carriedPrincipal();
    if (!$this->killSwitch->isContextKilled($ctx, $carried)) {
      return;
    }
    $this->deny(
      $toolId,
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      self::GENERIC_REFUSAL,
      McpKillSwitch::DENY_REASON,
    );
  }

}
