<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests result-count and response-size caps on McpBulkOperationsTool.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpBulkCapTest extends KernelTestBase {

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

    // Ensure the mcp_api role exists (hook_install creates it, but confirm
    // it is available before createUser() is called in each test) and that
    // it has node-update access so bulk operations actually succeed.
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api');
    if (!$role) {
      $role = Role::create([
        'id' => 'mcp_api',
        'label' => 'MCP API',
        'weight' => 10,
      ]);
      $role->save();
    }
    // Grant administer nodes so entity->access('update') passes in tests.
    user_role_grant_permissions('mcp_api', ['administer nodes']);

    // Enable role fallback so the test account triggers governance.
    // governed_roles already includes mcp_api from the default config install
    // but set explicitly to be robust against config cache differences.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Disable rate limiting so it does not interfere.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 0)
      ->set('allow_write', TRUE)
      ->set('allow_delete', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    // Create a 'page' node type.
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
  }

  /**
   * Creates nodes published and returns their IDs.
   *
   * @param int $count
   *   Number of nodes to create.
   *
   * @return string[]
   *   The numeric node IDs as strings.
   */
  private function createPublishedNodes(int $count): array {
    $ids = [];
    for ($i = 0; $i < $count; $i++) {
      $node = Node::create([
        'type' => 'page',
        'title' => 'Test node ' . $i,
        'status' => 1,
        'uid' => 1,
      ]);
      $node->save();
      $ids[] = (string) $node->id();
    }
    return $ids;
  }

  /**
   * Returns a mock user entity with id=1 and mcp_api role for bulk op tests.
   *
   * The tool checks $entity->access('update', $this->currentUser). In kernel
   * tests, node access defaults to allowing uid=1 (super-user). We create the
   * account with uid forced to 1 so all entity access checks pass, then add the
   * mcp_api role so the governance check resolves the default profile. The role
   * fallback in McpPolicyResolver covers the rest.
   */
  private function createGovernedAdminAccount(): UserInterface {
    // Create the user with the mcp_api role only (no extra permissions param)
    // so UserCreationTrait does NOT overwrite the roles array with a generated
    // role. The mcp_api role already has administer nodes granted in setUp().
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * When result_count_cap = 2, a bulk unpublish of 5 nodes returns 2 succeeded.
   */
  public function testBulkResultCountCapTruncatesSucceeded(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 2)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $this->createGovernedAdminAccount();
    $ids = $this->createPublishedNodes(5);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'unpublish');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', $ids);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();

    $data = $tool->getResult()->getContextValues();
    $failedInfo = json_encode($data['failed'] ?? []);
    $this->assertTrue($tool->getResultStatus(),
      'Tool must succeed; message: ' . (string) $tool->getResultMessage()
      . '; failed: ' . $failedInfo);
    $this->assertIsArray($data);
    $this->assertArrayHasKey('succeeded', $data);
    $this->assertCount(2, $data['succeeded'],
      'Succeeded list must be truncated to the cap of 2. Failed: ' . $failedInfo);
    $this->assertTrue($data['_result_truncated'] ?? FALSE,
      '_result_truncated flag must be TRUE when truncation occurred.');
    $this->assertSame(2, $data['_result_cap'] ?? NULL,
      '_result_cap must equal the profile cap.');
  }

  /**
   * When result_count_cap = 0 (unlimited), all 5 succeeded are returned.
   */
  public function testBulkResultCountCapUnlimitedReturnsAll(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 0)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $this->createGovernedAdminAccount();
    $ids = $this->createPublishedNodes(5);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'unpublish');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', $ids);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Tool must succeed; message was: ' . (string) $tool->getResultMessage());
    $data = $tool->getResult()->getContextValues();
    $this->assertIsArray($data);
    $this->assertCount(5, $data['succeeded'] ?? [],
      'All 5 succeeded must be returned when cap is 0 (unlimited).');
    $this->assertArrayNotHasKey('_result_truncated', $data,
      '_result_truncated must not be set when cap is 0.');
  }

  /**
   * When response_size_cap is tiny the bulk write SUCCEEDS with truncation.
   *
   * The operations are already performed before the size check runs.
   * Returning failure here would misreport a completed write batch and could
   * cause an agent to retry, toggling entity state. Instead, the reported
   * result lists are truncated to fit under the cap and '_size_truncated:
   * true' is set.
   */
  public function testResponseSizeCapTruncatesSucceededRatherThanFailing(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 0)
      ->set('response_size_cap', 10)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $this->createGovernedAdminAccount();
    $ids = $this->createPublishedNodes(3);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'unpublish');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', $ids);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();

    // The tool must SUCCEED — the unpublish operations were performed.
    $this->assertTrue($tool->getResultStatus(),
      'Bulk write must report success even when the response-size cap is exceeded; '
      . 'message: ' . (string) $tool->getResultMessage());
    $data = $tool->getResult()->getContextValues();
    $this->assertIsArray($data);
    // The truncation signal must be present so the agent knows it was cut.
    $this->assertTrue($data['_size_truncated'] ?? FALSE,
      '_size_truncated must be TRUE when payload was truncated to honour the size cap.');
    $this->assertArrayHasKey('_size_cap', $data,
      '_size_cap must be set to the profile cap value when size truncation occurs.');
    $this->assertSame(10, $data['_size_cap'],
      '_size_cap must match the configured response_size_cap.');
    // The result message must note the size truncation.
    $message = (string) $tool->getResultMessage();
    $this->assertStringContainsStringIgnoringCase('truncated', $message,
      'Success message must mention truncation when size cap was applied.');
  }

}
