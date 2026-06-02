<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\Tests\BrowserTestBase;

/**
 * Tests that uninstall cleans up everything the module created.
 *
 * Covers gap G14: verifies that uninstalling mcp_sentinel removes:
 *  - the mcp_api role,
 *  - all mcp_sentinel_* database tables (audit_log, content_locks,
 *    webhook_delivery),
 *  - all mcp_sentinel.* config (settings + every policy profile),
 * leaving nothing orphaned.
 *
 * @group mcp_sentinel
 */
final class McpUninstallTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Uninstalling the module removes the mcp_api role it created on install.
   */
  public function testUninstallRemovesMcpApiRole(): void {
    $storage = $this->container->get('entity_type.manager')->getStorage('user_role');
    $this->assertNotNull($storage->load('mcp_api'), 'mcp_api role exists after install.');

    $this->container->get('module_installer')->uninstall(['mcp_sentinel']);

    $storage = $this->container->get('entity_type.manager')->getStorage('user_role');
    $this->assertNull($storage->load('mcp_api'), 'mcp_api role removed after uninstall.');
  }

  /**
   * Uninstalling removes all three mcp_sentinel_* database tables.
   *
   * The module creates these tables via hook_schema() and Drupal's module
   * installer drops them on uninstall. Verifying this prevents an upgrade path
   * where the tables outlive the module (orphaned data + schema drift).
   */
  public function testUninstallDropsDatabaseTables(): void {
    $schema = $this->container->get('database')->schema();

    // All three tables must exist after install.
    foreach ([
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
      'mcp_sentinel_webhook_delivery',
    ] as $table) {
      $this->assertTrue(
        $schema->tableExists($table),
        "Table '$table' must exist before uninstall."
      );
    }

    $this->container->get('module_installer')->uninstall(['mcp_sentinel']);

    // Refresh the schema object after uninstall (cached state).
    $schema = $this->container->get('database')->schema();

    foreach ([
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
      'mcp_sentinel_webhook_delivery',
    ] as $table) {
      $this->assertFalse(
        $schema->tableExists($table),
        "Table '$table' must be removed after uninstall — no orphaned tables allowed."
      );
    }
  }

  /**
   * Uninstalling removes the module's config objects.
   *
   * Mcp_sentinel.settings and every mcp_sentinel.mcp_policy_profile.* config
   * object must be gone after uninstall. A leftover config object would prevent
   * a clean re-install and could silently persist stale policy profiles.
   */
  public function testUninstallRemovesModuleConfig(): void {
    // Confirm settings exist before uninstall.
    $this->assertNotNull(
      $this->config('mcp_sentinel.settings')->get('enabled'),
      'mcp_sentinel.settings must exist before uninstall.'
    );

    // Confirm the default profile exists.
    $etm = $this->container->get('entity_type.manager');
    /** @var \Drupal\Core\Config\Entity\ConfigEntityStorageInterface $profileStorage */
    $profileStorage = $etm->getStorage('mcp_policy_profile');
    $this->assertNotNull(
      $profileStorage->load('default'),
      'Default policy profile must exist before uninstall.'
    );

    $this->container->get('module_installer')->uninstall(['mcp_sentinel']);

    // mcp_sentinel.settings must be gone.
    $settingsConfig = $this->container->get('config.factory')
      ->get('mcp_sentinel.settings');
    // A deleted config object returns NULL for all keys, not an empty config.
    $this->assertNull(
      $settingsConfig->get('enabled'),
      'mcp_sentinel.settings must be deleted on uninstall (all keys should be null).'
    );

    // No mcp_sentinel.mcp_policy_profile.* configs should remain.
    $configNames = $this->container->get('config.factory')
      ->listAll('mcp_sentinel.mcp_policy_profile.');
    $this->assertEmpty(
      $configNames,
      'All mcp_sentinel.mcp_policy_profile.* config objects must be removed on uninstall.'
    );
  }

  /**
   * Full uninstall cleanliness: role, tables, config all gone.
   *
   * Composite assertion that is the canonical G14 check: after a single
   * uninstall, the site has zero MCP Sentinel footprint — no role, no tables,
   * no config. New: also creates a second policy profile to verify the profile
   * cleanup is not limited to the default profile.
   */
  public function testUninstallLeavesNoOrphanedFootprint(): void {
    // Create a second policy profile so we can confirm multi-profile cleanup.
    McpPolicyProfile::create([
      'id' => 'test_agent',
      'label' => 'Test Agent',
      'allow_read' => TRUE,
      'allow_write' => FALSE,
    ])->save();

    // Confirm the second profile exists.
    $etm = $this->container->get('entity_type.manager');
    $profileStorage = $etm->getStorage('mcp_policy_profile');
    $this->assertNotNull(
      $profileStorage->load('test_agent'),
      'test_agent profile must exist before uninstall.'
    );

    $this->container->get('module_installer')->uninstall(['mcp_sentinel']);

    // Role gone.
    $roleStorage = $this->container->get('entity_type.manager')
      ->getStorage('user_role');
    $this->assertNull($roleStorage->load('mcp_api'),
      'mcp_api role must not exist after uninstall.');

    // Tables gone.
    $schema = $this->container->get('database')->schema();
    foreach ([
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
      'mcp_sentinel_webhook_delivery',
    ] as $table) {
      $this->assertFalse(
        $schema->tableExists($table),
        "Table '$table' must not exist after uninstall."
      );
    }

    // Config gone (both profiles).
    $configNames = $this->container->get('config.factory')
      ->listAll('mcp_sentinel.');
    $this->assertEmpty(
      $configNames,
      'All mcp_sentinel.* config must be removed on uninstall — no orphaned config allowed.'
    );
  }

}
