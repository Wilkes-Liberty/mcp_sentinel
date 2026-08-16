<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Functional;

use Drupal\key\Entity\Key;
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
    'block',
    'node',
    'tool',
    'key',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
    'mcp_sentinel_approval',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    // Surface local-task tabs so they can be asserted in tests.
    $this->drupalPlaceBlock('local_tasks_block');
  }

  /**
   * D3: The Approvals tab is present on the dashboard for an eligible user.
   */
  public function testApprovalsTabPresentOnDashboard(): void {
    $this->drupalLogin($this->drupalCreateUser([
      'view mcp sentinel audit log',
      'approve mcp sentinel operations',
    ]));
    $this->drupalGet('/admin/reports/mcp-sentinel');
    $this->assertSession()->linkExists('Approvals');
  }

  /**
   * D3: The approval list shows Age and Reason columns.
   */
  public function testListShowsAgeAndReasonColumns(): void {
    $this->drupalLogin(
      $this->drupalCreateUser(['approve mcp sentinel operations'])
    );
    $this->drupalGet('/admin/reports/mcp-sentinel/approvals');
    $this->assertSession()->pageTextContains('Age');
    $this->assertSession()->pageTextContains('Reason');
  }

  /**
   * Tests approving a pending request through the admin UI.
   */
  public function testAdminApprovesPendingRequest(): void {
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $node = Node::create(['type' => 'article', 'title' => 'Awaiting approval']);
    $node->save();
    $nid = (int) $node->id();

    Key::create([
      'id' => 'ui_manifest_key',
      'label' => 'UI manifest key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'ui-manifest-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'ui_manifest_key')
      ->save();

    $requester = $this->drupalCreateUser([]);
    $payload = [
      'entity_type' => 'node',
      'entity_id' => (string) $nid,
      'entity_uuid' => (string) $node->uuid(),
      'label' => 'Awaiting approval',
    ];
    $manifest = \Drupal::service('mcp_sentinel.action_manifest_sealer')->tryMint(
      $requester,
      'delete',
      [
        'type' => 'node',
        'id' => (string) $nid,
        'uuid' => (string) $node->uuid(),
      ],
      $payload,
    );
    $this->assertNotNull($manifest);
    $request = McpApprovalRequest::create([
      'requested_by' => (int) $requester->id(),
      'operation'    => 'delete',
      'entity_type'  => 'node',
      'entity_id'    => (string) $nid,
      'payload'      => (string) json_encode($payload),
      'status'       => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest'     => $manifest->toJson(),
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
    $this->assertSession()->pageTextContains('Sealed action');
    $this->assertSession()->pageTextContains('Awaiting approval');
    $this->assertSession()->pageTextContains('delete');
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
    $count = (int) \Drupal::database()->select('audit_chain_log', 'l')
      ->condition('operation', 'approval_decision')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertGreaterThan(0, $count, 'An approval_decision audit row must be written.');
  }

  /**
   * An unsealed request cannot be approved from the UI.
   */
  public function testUnsealedRequestHidesApprove(): void {
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $node = Node::create(['type' => 'article', 'title' => 'No seal']);
    $node->save();
    $request = McpApprovalRequest::create([
      'requested_by' => 1,
      'operation'    => 'delete',
      'entity_type'  => 'node',
      'entity_id'    => (string) $node->id(),
      'payload'      => '{}',
      'status'       => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest'     => '',
    ]);
    $request->save();
    $this->drupalLogin($this->drupalCreateUser([
      'approve mcp sentinel operations',
    ]));
    $this->drupalGet('/admin/reports/mcp-sentinel/approvals/' . $request->id() . '/approve');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('no sealed action manifest');
    $this->assertSession()->buttonNotExists('Approve');
  }

}
