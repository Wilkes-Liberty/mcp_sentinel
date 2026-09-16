<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

/**
 * Installs the audit log and the append mutex used by Audit Chain 1.7.2.
 */
trait McpAuditSchemaTestTrait {

  /**
   * Creates an audit store, preserving the mutex during outage recovery tests.
   */
  protected function installAuditChainSchema(): void {
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $database = $this->container->get('database');
    if (!$database->schema()->tableExists('audit_chain_mutex')) {
      $this->installSchema('audit_chain', ['audit_chain_mutex']);
      // Kernel schema installation does not invoke hook_install().
      $database->insert('audit_chain_mutex')->fields([
        'id' => 1,
        'locked' => 1,
      ])->execute();
    }
  }

}
