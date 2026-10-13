<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;
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
   * Constructs the dispatcher.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextFactory $factory
   *   Builds the frozen context from the validated token.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   Request stack used to key the write-once holder.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextGuard $guard
   *   On/off switch (always on outside PHPUnit injection).
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   Write-once sealed context for this request or CLI job.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Writes denied_access rows.
   */
  public function __construct(
    private readonly McpPrincipalContextFactory $factory,
    private readonly RequestStack $requestStack,
    private readonly McpPrincipalContextGuard $guard,
    private readonly McpPrincipalContextHolder $holder,
    private readonly McpAuditLogger $auditLogger,
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
    $this->assertArgumentsAllowed(
      $arguments,
      $toolId,
      $reservedExceptions,
      $nestedMapRules,
    );
    $ctx = $this->factory->fromCurrentRequest();
    $request = $this->requestStack->getCurrentRequest();
    try {
      if ($this->isCliJob($request)) {
        $this->holder->sealForJob($ctx);
      }
      elseif ($request !== NULL) {
        $this->holder->seal($ctx, $request);
      }
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->writeDenialAudit($toolId, $e->reasonCode);
      throw $e;
    }
    // Validate and hand out the context the holder actually sealed. When
    // the request subscriber sealed first, that is the request-boundary
    // context, not a rebuild from attributes that may have been replaced
    // since. The holder only accepts an equal-identity reseal, so the
    // tenant and key checks below apply to what the handler receives.
    $sealed = $this->holder->get() ?? $ctx;
    $this->assertContextAllowed($sealed, $toolId);
    return $sealed;
  }

  /**
   * Leftover Drupal CLI/Drush/queue request, or no request at all.
   *
   * Drush and queue workers keep a process-lifetime bootstrap request
   * on the stack. That object is not an inbound HTTP call, so a second
   * message must go through sealForJob() (resetForJob() required).
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The current request, or NULL when the stack is empty.
   *
   * @return bool
   *   TRUE when the holder must seal via sealForJob().
   */
  private function isCliJob(?Request $request): bool {
    if ($request === NULL) {
      return TRUE;
    }
    return PHP_SAPI === 'cli'
      && $request === $this->requestStack->getMainRequest();
  }

  /**
   * Refuses reserved identity keys, a missing principal, or tenant.
   *
   * Checks the arguments and the context that would be handed out: the
   * sealed one when the holder has it, else a build from the request.
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
   *   When the guard is on and the call is not allowed.
   */
  public function assertDispatchAllowed(
    array $arguments,
    string $toolId,
    array $reservedExceptions = [],
    array $nestedMapRules = [],
  ): void {
    $this->assertArgumentsAllowed(
      $arguments,
      $toolId,
      $reservedExceptions,
      $nestedMapRules,
    );
    $this->assertContextAllowed(
      $this->holder->get() ?? $this->factory->fromCurrentRequest(),
      $toolId,
    );
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
    $reserved = McpPrincipalContext::reservedKeysIn(
      $arguments,
      $reservedExceptions,
      $nestedMapRules,
    );
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
   * Frozen context for the current request (factory rebuild, not the slot).
   */
  public function context(): McpPrincipalContext {
    return $this->factory->fromCurrentRequest();
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
      'A verified principal context is required.',
    );
  }

  /**
   * Writes a denied_access row with verified keys or an unverified marker.
   *
   * Written through logAlways(), the same as break-glass: a principal
   * denial is recorded even when audit_enabled is off. The principal is
   * the sealed context when one is held, else a build from the request.
   * X-MCP-Client is not set here. The logger records it as mcp_client,
   * labeled self-reported only.
   */
  public function writeDenialAudit(string $toolId, string $reasonCode): void {
    $this->auditLogger->logAlways(
      'denied_access',
      self::denialAuditMetadata(
        $toolId,
        $reasonCode,
        $this->holder->get() ?? $this->factory->fromCurrentRequest(),
      ),
    );
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
   * Writes a denied_access row and throws.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   */
  private function deny(
    string $toolId,
    string $reasonCode,
    string $message,
  ): never {
    $this->writeDenialAudit($toolId, $reasonCode);
    throw new McpPrincipalContextDeniedException($reasonCode, $message);
  }

}
