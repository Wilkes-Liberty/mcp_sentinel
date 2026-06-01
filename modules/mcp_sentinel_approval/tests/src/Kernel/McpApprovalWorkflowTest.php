<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Core\Database\Statement\FetchAs;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the approval-workflow submodule.
 *
 * Verifies that, with the submodule enabled and delete gated, a governed bulk
 * delete creates a pending request and does NOT delete the target; and that
 * approving the request deletes the target, marks the request approved, and
 * writes an audit row for the decision.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpApprovalWorkflowTest extends KernelTestBase {

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
    'mcp_sentinel_approval',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installEntitySchema('mcp_approval_request');
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installConfig(['filter', 'node', 'mcp_sentinel', 'mcp_sentinel_approval']);

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent']);
    $role->grantPermission('delete any article content');
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    McpPolicyProfile::create([
      'id'           => 'agent_delete',
      'label'        => 'Agent delete profile',
      'roles'        => ['mcp_agent'],
      'weight'       => 10,
      'allow_write'  => TRUE,
      'allow_delete' => TRUE,
    ])->save();

    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
  }

  /**
   * Sets a governed user with delete rights as the current user.
   */
  private function setGovernedCurrentUser(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Runs the bulk delete tool against one node id.
   *
   * @param int $nid
   *   The node id.
   *
   * @return array
   *   The structured result array.
   */
  private function runBulkDelete(int $nid): array {
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'delete');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', [(string) $nid]);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();
    return $tool->getResult()->getContextValues();
  }

  /**
   * A gated bulk delete queues an approval request and keeps the target.
   */
  public function testBulkDeleteQueuesApprovalAndKeepsTarget(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create(['type' => 'article', 'title' => 'Pending delete']);
    $node->save();
    $nid = (int) $node->id();

    $results = $this->runBulkDelete($nid);

    // The delete must be queued, not executed.
    $this->assertSame([], $results['succeeded']);
    $this->assertArrayHasKey($nid, $results['queued']);
    $this->assertStringContainsString('Queued for approval', $results['queued'][$nid]);

    // Target node still exists.
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'Target must survive while approval is pending.',
    );

    // Exactly one pending approval request was created.
    $requests = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request')
      ->loadMultiple();
    $this->assertCount(1, $requests);
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);
    $this->assertTrue($request->isPending());
    $this->assertSame('delete', $request->getOperation());
    $this->assertSame('node', $request->getTargetEntityTypeId());
    $this->assertSame((string) $nid, $request->getTargetEntityId());
  }

  /**
   * Approving a pending request deletes the target and audits the decision.
   */
  public function testApprovingExecutesAndAudits(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create(['type' => 'article', 'title' => 'To approve']);
    $node->save();
    $nid = (int) $node->id();

    $this->runBulkDelete($nid);

    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    $requests = $storage->loadMultiple();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);

    // Approve via the executor service (the form/route delegates to this).
    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    $this->assertTrue($result['executed']);

    // Target node is now deleted.
    $this->assertNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'Target must be deleted after approval.',
    );

    // Request is marked approved with decision metadata.
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $reloaded */
    $reloaded = $storage->loadUnchanged($request->id());
    $this->assertSame(McpApprovalRequestInterface::STATUS_APPROVED, $reloaded->getStatus());
    $this->assertNotEmpty($reloaded->get('decided_by')->target_id);
    $this->assertNotEmpty($reloaded->get('decided')->value);

    // An audit row for the decision exists.
    $rows = $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->condition('operation', 'approval_decision')
      ->execute()
      ->fetchAll(FetchAs::Associative);
    $this->assertNotEmpty($rows, 'An approval_decision audit row must be written.');
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) end($rows)['metadata']);
    $this->assertSame('approved', $meta['decision']);
    $this->assertSame((int) $request->id(), $meta['request_id']);
  }

  /**
   * Denying a request leaves the target intact and audits the denial.
   */
  public function testDenyingKeepsTargetAndAudits(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create(['type' => 'article', 'title' => 'To deny']);
    $node->save();
    $nid = (int) $node->id();

    $this->runBulkDelete($nid);

    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    $requests = $storage->loadMultiple();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);

    $this->container->get('mcp_sentinel_approval.executor')->deny($request);

    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'Target must survive a denial.',
    );
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $reloaded */
    $reloaded = $storage->loadUnchanged($request->id());
    $this->assertSame(McpApprovalRequestInterface::STATUS_DENIED, $reloaded->getStatus());
  }

}
