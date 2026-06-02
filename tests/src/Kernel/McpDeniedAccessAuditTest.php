<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\user\UserInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests that governed-tool policy denials produce denied_access audit rows.
 *
 * Fix 1 of the F10 security review: the denied_access audit operation must be
 * written by governed Tool plugins when an agent is denied by McpAccessChecker
 * or core entity access, so that the denied_access_storm anomaly rule (the F10
 * headline scenario) is reachable.
 *
 * Scope: governed Tool execution path only. JSON:API / GraphQL denial-logging
 * is a future enhancement (F10 v2) and is intentionally not covered here.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDeniedAccessAuditTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel', 'node', 'user']);

    // Ensure the mcp_api role exists.
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api');
    if (!$role) {
      $role = Role::create([
        'id' => 'mcp_api',
        'label' => 'MCP API',
        'weight' => 10,
      ]);
      $role->save();
    }
    // Grant administer nodes so entity->access() checks pass in tests that
    // need them to succeed; denial tests override this via policy.
    user_role_grant_permissions('mcp_api', ['administer nodes']);

    // Enable role fallback and mark mcp_api as governed.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('audit_enabled', TRUE)
      ->save();

    // Disable rate limiting so it does not interfere.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 0)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    // Create a node type used by denial tests.
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
  }

  /**
   * Creates and returns a governed account with the mcp_api role.
   */
  private function createGovernedAccount(): UserInterface {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * Creates published nodes and returns their IDs.
   *
   * @param int $count
   *   Number of nodes to create.
   *
   * @return string[]
   *   Numeric node IDs as strings.
   */
  private function createNodes(int $count): array {
    $ids = [];
    for ($i = 0; $i < $count; $i++) {
      $node = Node::create([
        'type' => 'page',
        'title' => 'Node ' . $i,
        'status' => 1,
        'uid' => 1,
      ]);
      $node->save();
      $ids[] = (string) $node->id();
    }
    return $ids;
  }

  /**
   * A bulk-delete denied by policy writes one denied_access row per entity.
   *
   * Allow_delete = FALSE on the profile triggers a policy denial for each
   * entity in the ids list, which must produce one denied_access audit row
   * per entity so that a denied_access_storm rule can fire.
   */
  public function testDeniedBulkDeleteWritesDeniedAccessRows(): void {
    // Deny deletes on the profile.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_delete', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $this->createGovernedAccount();
    $ids = $this->createNodes(3);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'delete');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', $ids);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();

    // All three entities should be in the failed list.
    $data = $tool->getResult()->getContextValues();
    $this->assertCount(3, $data['failed'] ?? [],
      'All 3 entities must fail when delete is denied by policy.');

    // Three denied_access rows must have been written.
    $count = (int) \Drupal::database()
      ->select('mcp_sentinel_audit_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(3, $count,
      'One denied_access audit row must be written per denied entity ID.');
  }

  /**
   * Denied_access rows from governed-tool denials trigger an anomaly rule.
   *
   * This is the headline F10 scenario: an agent hammering forbidden deletes
   * generates enough denied_access rows to exceed a threshold and alert.
   */
  public function testDeniedAccessAnomalyRuleFires(): void {
    // Deny deletes on the profile so policy denials fire.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_delete', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    // Enable the anomaly detector with a denied_access_storm rule.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id'                => 'denied_access_storm',
        'label'             => 'Denied access storm',
        'operation_pattern' => 'denied_access',
        'window_seconds'    => 300,
        'threshold'         => 3,
        'debounce_seconds'  => 0,
        'enabled'           => TRUE,
      ],
      ])->save();

    $this->createGovernedAccount();
    $ids = $this->createNodes(5);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'delete');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', $ids);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();

    // Evaluate anomaly rules: 5 denied_access rows >= threshold of 3.
    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(1, $fired,
      'denied_access_storm rule must fire when enough denied_access rows exist.');
    $this->assertSame('denied_access_storm', $fired[0]['rule']['id']);
    $this->assertGreaterThanOrEqual(3, $fired[0]['count'],
      'Count must be at least the threshold (3).');
  }

}
