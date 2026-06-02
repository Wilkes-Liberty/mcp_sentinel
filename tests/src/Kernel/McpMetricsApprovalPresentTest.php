<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequest;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests McpMetrics::approvalSummary() with the approval submodule enabled.
 *
 * Proves the metric reports real pending-request data when the
 * mcp_approval_request entity type is defined.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpMetrics
 */
#[Group('mcp_sentinel')]
class McpMetricsApprovalPresentTest extends KernelTestBase {

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
    $this->installConfig(['mcp_sentinel']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_webhook_delivery',
    ]);
    $this->installEntitySchema('mcp_approval_request');
    $this->installEntitySchema('user');
  }

  /**
   * @covers ::approvalSummary
   */
  public function testApprovalSummaryReportsPendingAndOldestAge(): void {
    $now = \Drupal::time()->getRequestTime();
    foreach ([$now - 600, $now - 200] as $created) {
      McpApprovalRequest::create([
        'requested_by' => 1,
        'operation' => 'delete',
        'entity_type' => 'node',
        'entity_id' => '1',
        'status' => McpApprovalRequestInterface::STATUS_PENDING,
        'created' => $created,
      ])->save();
    }
    // A decided request must NOT count toward pending.
    McpApprovalRequest::create([
      'requested_by' => 1,
      'operation' => 'delete',
      'entity_type' => 'node',
      'entity_id' => '2',
      'status' => McpApprovalRequestInterface::STATUS_APPROVED,
      'created' => $now - 900,
    ])->save();

    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $summary = $m->approvalSummary();
    $this->assertTrue($summary['available']);
    $this->assertSame(2, $summary['pending']);
    // Oldest pending was created 600s ago.
    $this->assertGreaterThanOrEqual(600, $summary['oldest_age']);
  }

}
