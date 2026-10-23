<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

use Symfony\Component\HttpFoundation\Request;

/**
 * Shared kernel fixtures for sealed-token denial audit tests.
 */
trait McpSealedTokenDenialAuditTestTrait {

  use McpAuditSchemaTestTrait;

  /**
   * Installs schema and a default request for denial-audit tests.
   */
  protected function installSealedTokenDenialAudit(): void {
    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installEntitySchema('consumer');
    $this->installEntitySchema('oauth2_token');
    $this->installConfig(['mcp_sentinel', 'system']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_sealed_token']);
    $this->pushRequestKeepingSession(
      Request::create('https://sentinel.example/jsonapi/node/page'),
    );
  }

  /**
   * Sealed-token denied_access metadata rows, oldest first.
   *
   * @return list<array<string, mixed>>
   *   Decoded metadata.
   */
  protected function sealedTokenDenialRows(): array {
    $stored = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id')
      ->execute()
      ->fetchCol();
    $out = [];
    foreach ($stored as $json) {
      $meta = json_decode((string) $json, TRUE);
      if (is_array($meta) && ($meta['tool'] ?? '') === 'sealed_token') {
        $out[] = $meta;
      }
    }
    return $out;
  }

}
