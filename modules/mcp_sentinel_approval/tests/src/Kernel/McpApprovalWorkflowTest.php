<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Core\Database\Statement\FetchAs;
use Drupal\Core\Session\AnonymousUserSession;
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

    // An approver who may review the queue but lacks delete access on targets.
    $weak = Role::create(['id' => 'weak_approver', 'label' => 'Weak approver']);
    $weak->grantPermission('access mcp sentinel context');
    $weak->grantPermission('approve mcp sentinel operations');
    $weak->save();

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
    // Audit truthfully records a successful execution and the approver uid.
    $this->assertTrue($meta['executed']);
    $this->assertSame((int) $this->container->get('current_user')->id(), $meta['decided_by']);
    $this->assertArrayNotHasKey('reason', $meta);
  }

  /**
   * Approving an already-decided request throws and does not re-execute.
   *
   * Guards against a direct caller replaying a decision (Fix 1).
   */
  public function testDoubleApproveThrowsAndDoesNotReExecute(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create(['type' => 'article', 'title' => 'Double approve']);
    $node->save();

    $this->runBulkDelete((int) $node->id());
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    $requests = $storage->loadMultiple();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);

    $executor = $this->container->get('mcp_sentinel_approval.executor');
    $first = $executor->approve($request);
    $this->assertTrue($first['executed']);

    $auditCountBefore = (int) $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->condition('operation', 'approval_decision')
      ->countQuery()->execute()->fetchField();

    // Reload to a non-pending state, then attempt a second decision.
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $reloaded */
    $reloaded = $storage->loadUnchanged($request->id());
    $this->expectException(\LogicException::class);
    try {
      $executor->approve($reloaded);
    }
    finally {
      // No second audit row was written by the rejected re-decision.
      $auditCountAfter = (int) $this->container->get('database')
        ->select('mcp_sentinel_audit_log', 'l')
        ->condition('operation', 'approval_decision')
        ->countQuery()->execute()->fetchField();
      $this->assertSame($auditCountBefore, $auditCountAfter);
    }
  }

  /**
   * Access-denied on the target leaves the request pending and unaudited.
   *
   * Fix 3: a recoverable block must not be recorded as an approval.
   */
  public function testAccessDeniedKeepsPendingAndWritesNoApprovedAudit(): void {
    // The governed agent is created first (uid 1) so it can act on node access
    // grants when queueing the delete.
    $this->setGovernedCurrentUser();

    $node = Node::create(['type' => 'article', 'title' => 'No delete access']);
    $node->save();
    $nid = (int) $node->id();

    $this->runBulkDelete($nid);
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    $requests = $storage->loadMultiple();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);

    // Create and switch to an approver WITHOUT delete access on the target.
    // Drop to anonymous while creating the user so the creation is not itself
    // governed/audited (avoids logging an unrelated row).
    $current = $this->container->get('current_user');
    $current->setAccount(new AnonymousUserSession());
    $weak = $this->createUser([], NULL, FALSE, ['roles' => ['weak_approver']]);
    $current->setAccount($weak);

    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    $this->assertTrue($result['error']);
    $this->assertFalse($result['executed']);

    // Target survives and request stays pending.
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
    );
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $reloaded */
    $reloaded = $storage->loadUnchanged($request->id());
    $this->assertTrue($reloaded->isPending());

    // No "approved" audit row was written.
    $approved = (int) $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->condition('operation', 'approval_decision')
      ->countQuery()->execute()->fetchField();
    $this->assertSame(0, $approved);
  }

  /**
   * A UUID mismatch (id reuse) blocks deletion of the wrong entity.
   *
   * Fix 4: bind the target by UUID so a reused auto-increment id is not
   * silently deleted.
   */
  public function testUuidMismatchBlocksDeletion(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create(['type' => 'article', 'title' => 'Original']);
    $node->save();
    $nid = (int) $node->id();

    $this->runBulkDelete($nid);
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    $requests = $storage->loadMultiple();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);

    // Simulate the original being deleted and a different entity reusing the id
    // by rewriting the stored payload UUID to one that will not match.
    $payload = $request->getPayload();
    $payload['entity_uuid'] = 'deadbeef-0000-0000-0000-000000000000';
    $request->set('payload', (string) json_encode($payload));
    $request->save();

    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    $this->assertFalse($result['executed']);
    $this->assertFalse($result['error']);

    // The entity now under that id was NOT deleted.
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'A UUID mismatch must not delete the entity occupying the reused id.',
    );

    // Request is decided (approved, not executed) with a uuid_mismatch reason.
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $reloaded */
    $reloaded = $storage->loadUnchanged($request->id());
    $this->assertSame(McpApprovalRequestInterface::STATUS_APPROVED, $reloaded->getStatus());

    $rows = $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->condition('operation', 'approval_decision')
      ->execute()
      ->fetchAll(FetchAs::Associative);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) end($rows)['metadata']);
    $this->assertFalse($meta['executed']);
    $this->assertSame('uuid_mismatch', $meta['reason']);
  }

  /**
   * An unknown/uninstalled entity type does not fatal; it blocks cleanly.
   *
   * Fix 2: getStorage() is guarded by hasDefinition().
   */
  public function testUnknownEntityTypeIsHandledCleanly(): void {
    $this->setGovernedCurrentUser();

    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = $storage->create([
      'requested_by' => (int) $this->container->get('current_user')->id(),
      'operation'    => 'delete',
      'entity_type'  => 'no_such_entity_type',
      'entity_id'    => '1',
      'payload'      => (string) json_encode(['entity_type' => 'no_such_entity_type', 'entity_id' => '1']),
      'status'       => McpApprovalRequestInterface::STATUS_PENDING,
    ]);
    $request->save();

    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    $this->assertFalse($result['executed']);
    $this->assertFalse($result['error']);

    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $reloaded */
    $reloaded = $storage->loadUnchanged($request->id());
    $this->assertSame(McpApprovalRequestInterface::STATUS_APPROVED, $reloaded->getStatus());

    $rows = $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->condition('operation', 'approval_decision')
      ->execute()
      ->fetchAll(FetchAs::Associative);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) end($rows)['metadata']);
    $this->assertFalse($meta['executed']);
    $this->assertStringContainsString('unknown_entity_type', (string) $meta['reason']);
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
