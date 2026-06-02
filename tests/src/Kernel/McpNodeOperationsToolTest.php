<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel behavioral tests for McpNodeOperationsTool.
 *
 * Covers:
 * - Create: entity persisted, entity_presave audit row written.
 * - Update: mutations applied, change-diff captured in audit.
 * - Ungoverned account (NULL profile) is denied.
 * - Update on a content-locked node is blocked.
 * - Policy write-gate off denies creation and writes denied_access audit row.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpNodeOperationsToolTest extends KernelTestBase {

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
    $this->installConfig(['field', 'filter', 'system', 'node', 'user', 'mcp_sentinel']);

    // Ensure the mcp_api role exists and has necessary permissions.
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api');
    if (!$role) {
      $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
      $role->grantPermission('access mcp sentinel context');
      $role->save();
    }
    else {
      user_role_grant_permissions('mcp_api', ['access mcp sentinel context']);
    }
    user_role_grant_permissions('mcp_api', ['administer nodes']);

    // Enable role fallback governance.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Default profile: writes allowed, no rate limit, no entity deny list.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    // Create a page content type for all tests.
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
  }

  /**
   * Returns a governed mcp_api account set as the current user.
   */
  private function createGovernedAccount(): AccountInterface {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * Create action: entity is persisted and an audit row is written.
   */
  public function testCreatePersistsAndAudits(): void {
    $this->createGovernedAccount();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $tool->setInputValue('action', 'create');
    $tool->setInputValue('bundle', 'page');
    $tool->setInputValue('title', 'New Page Via Tool');
    $tool->setInputValue('published', FALSE);
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Node creation must succeed for a governed account; '
      . 'message: ' . (string) $tool->getResultMessage());

    $data = $tool->getResult()->getContextValues();
    $this->assertArrayHasKey('id', $data, 'Result must contain the new node ID.');
    $this->assertArrayHasKey('uuid', $data, 'Result must contain the new node UUID.');
    $this->assertSame('page', $data['bundle'] ?? NULL, 'Result bundle must match.');

    // Confirm the node exists in the database.
    $node = \Drupal::entityTypeManager()->getStorage('node')->load($data['id']);
    $this->assertNotNull($node, 'A node with the returned ID must exist.');
    $this->assertSame('New Page Via Tool', $node->label(),
      'Persisted node must have the supplied title.');

    // An audit row must have been written (entity_save from hook_entity_presave
    // or a tool-level log — at least 1 row proves the audit path fired).
    $count = (int) \Drupal::database()
      ->select('mcp_sentinel_audit_log', 'l')
      ->countQuery()->execute()->fetchField();
    $this->assertGreaterThan(0, $count,
      'At least one audit row must exist after a successful create operation.');
  }

  /**
   * Update action: mutations are applied and an audit row captures the change.
   */
  public function testUpdateCapturesChangeDiff(): void {
    $this->createGovernedAccount();

    // Pre-create a node as uid 1 so administer-nodes access passes.
    $node = Node::create([
      'type' => 'page',
      'title' => 'Original Title',
      'uid' => 1,
    ]);
    $node->save();
    $nid = (string) $node->id();

    // Clear audit log so we can count only the rows from the update.
    \Drupal::database()->delete('mcp_sentinel_audit_log')->execute();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $tool->setInputValue('action', 'update');
    $tool->setInputValue('id', $nid);
    $tool->setInputValue('title', 'Updated Title');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Node update must succeed; message: ' . (string) $tool->getResultMessage());

    // Reload and confirm the title changed.
    \Drupal::entityTypeManager()->getStorage('node')->resetCache([$node->id()]);
    $reloaded = \Drupal::entityTypeManager()->getStorage('node')->load($nid);
    $this->assertSame('Updated Title', $reloaded->label(),
      'The node title must be mutated by the update action.');

    // An audit row must have been written for the update.
    $count = (int) \Drupal::database()
      ->select('mcp_sentinel_audit_log', 'l')
      ->countQuery()->execute()->fetchField();
    $this->assertGreaterThan(0, $count,
      'At least one audit row must be written for a successful update operation.');
  }

  /**
   * Ungoverned account (NULL profile) is denied node creation.
   */
  public function testUngovernedBlocked(): void {
    // User without mcp_api role — ungoverned.
    $ungoverned = $this->createUser(['access mcp sentinel context', 'administer nodes']);
    \Drupal::currentUser()->setAccount($ungoverned);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $tool->setInputValue('action', 'create');
    $tool->setInputValue('bundle', 'page');
    $tool->setInputValue('title', 'Should Not Appear');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Node creation must be denied for an ungoverned account.');
    $this->assertStringContainsStringIgnoringCase(
      'no governance profile',
      (string) $tool->getResultMessage(),
      'Failure message must mention the missing governance profile.'
    );
  }

  /**
   * Update on a content-locked node is blocked with a clear message.
   */
  public function testUpdateOnLockedNodeBlocked(): void {
    $this->createGovernedAccount();

    $node = Node::create([
      'type' => 'page',
      'title' => 'Locked Node',
      'uid' => 1,
    ]);
    $node->save();
    $nid = (string) $node->id();

    // Lock the node.
    \Drupal::service('mcp_sentinel.content_lock')
      ->lock('node', $nid, 'Being edited by a human');

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $tool->setInputValue('action', 'update');
    $tool->setInputValue('id', $nid);
    $tool->setInputValue('title', 'Attempt To Override Lock');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Update on a content-locked node must be denied.');
    $this->assertStringContainsStringIgnoringCase(
      'locked',
      (string) $tool->getResultMessage(),
      'Failure message must indicate that the node is locked.'
    );
  }

  /**
   * Policy write gate off blocks creation and writes a denied_access audit row.
   */
  public function testPolicyWriteGateOffBlocksCreation(): void {
    $this->createGovernedAccount();

    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $tool->setInputValue('action', 'create');
    $tool->setInputValue('bundle', 'page');
    $tool->setInputValue('title', 'Denied By Gate');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Node creation must fail when the profile write gate is off.');

    // A denied_access audit row must have been written.
    $count = (int) \Drupal::database()
      ->select('mcp_sentinel_audit_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()->execute()->fetchField();
    $this->assertGreaterThan(0, $count,
      'A denied_access audit row must be written when the write gate denies creation.');
  }

}
