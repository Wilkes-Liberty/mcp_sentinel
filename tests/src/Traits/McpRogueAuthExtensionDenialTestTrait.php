<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionOwnership;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;

/**
 * Shared assertions for a non-owned principal-auth hook.
 */
trait McpRogueAuthExtensionDenialTestTrait {

  /**
   * A stamped fallback request does not receive a rogue principal.
   *
   * @param string $provider
   *   Expected defining module on the audit row.
   */
  protected function assertRogueHookDenied(string $provider): void {
    $request = Request::create('/jsonapi/node/page', 'PATCH');
    $request->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $this->pushRequestKeepingSession($request);

    $ctx = $this->container->get('mcp_sentinel.principal_context_factory')
      ->fromRequest($request);
    $this->assertSame('', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    $this->assertSame(McpPrincipalContext::SOURCE_ROLE_FALLBACK, $ctx->source());

    $this->assertRejectedAuditNamesProvider($provider);

    $this->expectException(McpPrincipalContextDeniedException::class);
    $this->container->get('mcp_sentinel.principal_context_dispatcher')
      ->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
  }

  /**
   * audit_chain recorded the offending service and provider.
   *
   * @param string $provider
   *   Expected defining module.
   */
  protected function assertRejectedAuditNamesProvider(string $provider): void {
    $rows = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['operation', 'metadata'])
      ->condition(
        'l.operation',
        McpPrincipalAuthExtensionOwnership::AUDIT_OPERATION,
      )
      ->execute()
      ->fetchAll();
    $this->assertNotEmpty($rows, 'A rejected hook must write a governance row.');
    $providers = [];
    $services = [];
    foreach ($rows as $row) {
      $metadata = json_decode((string) $row->metadata, TRUE);
      $this->assertIsArray($metadata);
      $this->assertArrayHasKey('service', $metadata);
      $this->assertArrayHasKey('provider', $metadata);
      $this->assertArrayHasKey('reason', $metadata);
      $this->assertIsString($metadata['service']);
      $this->assertNotSame('', $metadata['service']);
      $this->assertIsString($metadata['provider']);
      $this->assertContains($metadata['reason'], [
        'refused',
        'claims_stripped',
      ]);
      $providers[] = $metadata['provider'];
      $services[] = $metadata['service'];
    }
    $this->assertContains($provider, $providers, sprintf(
      'Expected provider %s in %s (services %s).',
      $provider,
      implode(',', $providers),
      implode(',', $services),
    ));
  }

}
