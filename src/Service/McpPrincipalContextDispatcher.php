<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Dispatches a tool handler as handler(args, ctx).
 *
 * Identity and tenant come only from the frozen token context. Reserved
 * keys in arguments are rejected before the handler runs. A network
 * call without a tenant claim fails closed.
 */
final class McpPrincipalContextDispatcher {

  /**
   * Constructs the dispatcher.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextFactory $factory
   *   Builds the frozen context from the validated token.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   Request stack used to stamp the frozen context.
   */
  public function __construct(
    private readonly McpPrincipalContextFactory $factory,
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * Runs handler($args, $ctx) after the identity/tenant preflight.
   *
   * @param callable(array<string, mixed>, \Drupal\mcp_sentinel\Value\McpPrincipalContext): mixed $handler
   *   The tool handler. Receives arguments and the frozen context.
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   *
   * @return mixed
   *   Whatever the handler returns.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   Reserved identity keys, or a network call with no tenant claim.
   */
  public function dispatch(callable $handler, array $arguments): mixed {
    $this->assertDispatchAllowed($arguments);
    $ctx = $this->factory->fromCurrentRequest();
    $this->attachToRequest($ctx);
    return $handler($arguments, $ctx);
  }

  /**
   * Refuses reserved identity keys and a missing network tenant.
   *
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When the guard is on and the call is not allowed.
   */
  public function assertDispatchAllowed(array $arguments): void {
    if (!McpPrincipalContextGuard::required()) {
      return;
    }
    $reserved = McpPrincipalContext::reservedKeysIn($arguments);
    if ($reserved !== []) {
      throw new McpPrincipalContextDeniedException(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        'Tool arguments must not carry identity or tenant keys ('
        . implode(', ', $reserved)
        . '). Identity comes from the validated token context.',
      );
    }
    $ctx = $this->factory->fromCurrentRequest();
    if ($ctx->isNetwork() && $ctx->tenant() === '') {
      throw new McpPrincipalContextDeniedException(
        McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
        'Network calls require a tenant claim on the validated token (DEV-839).',
      );
    }
  }

  /**
   * Frozen context for the current request.
   */
  public function context(): McpPrincipalContext {
    return $this->factory->fromCurrentRequest();
  }

  /**
   * Raw tool arguments from an HTTP body or form, if present.
   *
   * Used at the Tool API seam so a spoofed identity key is seen even
   * when the plugin schema strips unknown inputs.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return array<string, mixed>
   *   Top-level argument map, or empty when none is present.
   */
  public static function rawArgumentsFromRequest(Request $request): array {
    $content = $request->getContent();
    if ($content !== '') {
      $decoded = json_decode($content, TRUE);
      if (is_array($decoded)) {
        $fromJson = self::argumentsFromDocument($decoded);
        if ($fromJson !== []) {
          return $fromJson;
        }
      }
    }
    $requestBag = $request->request->all();
    return self::argumentsFromDocument($requestBag);
  }

  /**
   * Pulls a tool-argument map out of a JSON-RPC / form document.
   *
   * @param array<string, mixed> $document
   *   Decoded body or form values.
   *
   * @return array<string, mixed>
   *   Arguments, or empty.
   */
  private static function argumentsFromDocument(array $document): array {
    foreach (['arguments', 'input'] as $key) {
      if (isset($document[$key]) && is_array($document[$key])) {
        return $document[$key];
      }
    }
    $params = $document['params'] ?? NULL;
    if (is_array($params)) {
      foreach (['arguments', 'input'] as $key) {
        if (isset($params[$key]) && is_array($params[$key])) {
          return $params[$key];
        }
      }
    }
    return [];
  }

  /**
   * Stamps the frozen context on the current request when one exists.
   */
  private function attachToRequest(McpPrincipalContext $ctx): void {
    $this->requestStack->getCurrentRequest()?->attributes->set(
      McpPrincipalContext::REQUEST_ATTRIBUTE,
      $ctx,
    );
  }

}
