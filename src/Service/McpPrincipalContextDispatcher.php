<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Dispatches a tool handler as handler(args, ctx).
 *
 * Identity and tenant come only from the frozen token context. The
 * reserved-key and principal checks run on the exact argument array
 * passed to the handler / doExecute() — never a raw HTTP body. A
 * network or sealed-token HTTP call without a tenant claim fails
 * closed. Every denial writes a denied_access audit row.
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
   *   Write-once sealed context for this request.
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
   *
   * @return mixed
   *   Whatever the handler returns.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   Reserved identity keys, missing principal, or missing tenant.
   */
  public function dispatch(callable $handler, array $arguments): mixed {
    $ctx = $this->admit($arguments);
    return $handler($arguments, $ctx);
  }

  /**
   * Preflight + seal for the exact values about to reach doExecute().
   *
   * @param array<string, mixed> $arguments
   *   The array ToolBase::execute() will pass to doExecute().
   *
   * @return \Drupal\mcp_sentinel\Value\McpPrincipalContext
   *   The sealed context.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and the call is not allowed.
   */
  public function admit(array $arguments): McpPrincipalContext {
    $this->assertDispatchAllowed($arguments);
    $ctx = $this->factory->fromCurrentRequest();
    $token = $this->requestStack->getCurrentRequest() ?? 'cli';
    $this->holder->seal($ctx, $token);
    return $ctx;
  }

  /**
   * Refuses reserved identity keys, a missing principal, or tenant.
   *
   * Checks $arguments as-is — the exact map the handler receives.
   * HTTP body parsing is not a choke point (empty top-level
   * `arguments: {}` must not hide `params.arguments`).
   *
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and the call is not allowed.
   */
  public function assertDispatchAllowed(array $arguments): void {
    if (!$this->guard->required()) {
      return;
    }
    $reserved = McpPrincipalContext::reservedKeysIn($arguments);
    if ($reserved !== []) {
      $this->deny(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        'Tool arguments must not carry identity or tenant keys ('
        . implode(', ', $reserved)
        . '). Identity comes from the validated token context.',
      );
    }
    $ctx = $this->factory->fromCurrentRequest();
    if ($ctx->isNetwork() && $ctx->tenant() === '') {
      $this->deny(
        McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
        'Network calls require a tenant claim on the validated token (DEV-839).',
      );
    }
    try {
      McpPrincipalKey::fromClaims($ctx->keyClaims());
    }
    catch (McpPrincipalKeyException $e) {
      $this->deny(
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
   * Writes a denied_access row and throws.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   */
  private function deny(string $reasonCode, string $message): never {
    $this->auditLogger->log('denied_access', [
      'tool' => 'principal_context',
      'entity_type' => 'principal',
      'id' => '-',
      'operation' => 'dispatch',
      'reason' => $reasonCode,
    ]);
    throw new McpPrincipalContextDeniedException($reasonCode, $message);
  }

}
