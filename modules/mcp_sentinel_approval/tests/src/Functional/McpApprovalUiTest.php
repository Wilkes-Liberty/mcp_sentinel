<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Functional;

use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequest;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\BrowserTestBase;

/**
 * Functional test for the approval admin UI.
 *
 * An admin with the approve permission visits the approvals list, approves a
 * pending request, and the target node is deleted, the request is marked
 * approved, and an audit row is written for the decision.
 *
 * @group mcp_sentinel
 */
final class McpApprovalUiTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'node',
    'tool',
    'key',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
    'mcp_sentinel_approval',
  ];

  /**
   * Tests approving a pending request through the admin UI.
   */
  public function testAdminApprovesPendingRequest(): void {
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $node = Node::create(['type' => 'article', 'title' => 'Awaiting approval']);
    $node->save();
    $nid = (int) $node->id();

    $request = McpApprovalRequest::create([
      'requested_by' => 1,
      'operation'    => 'delete',
      'entity_type'  => 'node',
      'entity_id'    => (string) $nid,
      'payload'      => (string) json_encode(['entity_type' => 'node', 'entity_id' => (string) $nid]),
      'status'       => McpApprovalRequestInterface::STATUS_PENDING,
    ]);
    $request->save();

    $admin = $this->drupalCreateUser([
      'approve mcp sentinel operations',
      'delete any article content',
      'view mcp sentinel audit log',
    ]);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/approvals');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('node:' . $nid);

    // Visit the approve confirm form and submit it.
    $this->drupalGet('/admin/reports/mcp-sentinel/approvals/' . $request->id() . '/approve');
    $this->assertSession()->statusCodeEquals(200);
    $this->submitForm([], 'Approve');

    // Target node deleted.
    $this->assertNull(
      \Drupal::entityTypeManager()->getStorage('node')->loadUnchanged($nid),
      'Node must be deleted after approval through the UI.',
    );

    // Request approved.
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $reloaded */
    $reloaded = \Drupal::entityTypeManager()
      ->getStorage('mcp_approval_request')
      ->loadUnchanged($request->id());
    $this->assertSame(McpApprovalRequestInterface::STATUS_APPROVED, $reloaded->getStatus());

    // Audit row for the decision.
    $count = (int) \Drupal::database()->select('mcp_sentinel_audit_log', 'l')
      ->condition('operation', 'approval_decision')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertGreaterThan(0, $count, 'An approval_decision audit row must be written.');
  }

}
