<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Drupal\Tests\BrowserTestBase;

/**
 * Tests the filterable audit log UI and CSV/JSON export.
 *
 * @group mcp_sentinel
 * @covers \Drupal\mcp_sentinel\Controller\McpAuditController
 */
#[RunTestsInSeparateProcesses]
final class McpAuditFilterExportTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Seeds audit rows directly into the database.
   *
   * @param string $operation
   *   The operation value.
   * @param string $entity_type
   *   The entity_type value.
   * @param int $uid
   *   The uid value.
   * @param int|null $timestamp
   *   Unix timestamp, or NULL to use REQUEST_TIME.
   */
  private function seedRow(string $operation, string $entity_type = 'node', int $uid = 1, ?int $timestamp = NULL): void {
    \Drupal::database()->insert('mcp_sentinel_audit_log')
      ->fields([
        'timestamp'    => $timestamp ?? \Drupal::time()->getRequestTime(),
        'uid'          => $uid,
        'operation'    => $operation,
        'entity_type'  => $entity_type,
        'bundle'       => 'article',
        'entity_id'    => '42',
        'entity_label' => 'Test node',
        'ip_address'   => '127.0.0.1',
        'user_agent'   => 'TestUA/1.0',
        'metadata'     => json_encode(['source' => 'seed']),
        'prev_hash'    => NULL,
        'row_hash'     => NULL,
      ])
      ->execute();
  }

  /**
   * T3.1: Filtering the listing by operation only shows matching rows.
   *
   * Uses operation names that are unlikely to appear in page navigation.
   */
  public function testListingFilterByOperation(): void {
    // Enable audit so rows can be present.
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    // Use deliberately unique operation names to avoid collisions with
    // navigation or form hint text.
    $this->seedRow('mcp_op_alpha');
    $this->seedRow('mcp_op_beta');

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    // Without filter, both rows appear.
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('mcp_op_alpha');
    $this->assertSession()->pageTextContains('mcp_op_beta');

    // Filter by operation=mcp_op_alpha only.
    $this->drupalGet('/admin/reports/mcp-sentinel/audit', [
      'query' => ['operation' => 'mcp_op_alpha'],
    ]);
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('mcp_op_alpha');
    $this->assertSession()->pageTextNotContains('mcp_op_beta');
  }

  /**
   * T3.1: Filtering by entity_type.
   */
  public function testListingFilterByEntityType(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    // Use unique entity type names that won't appear in page chrome.
    $this->seedRow('mcp_op_save', 'mcp_etype_alpha');
    $this->seedRow('mcp_op_save', 'mcp_etype_beta');

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/audit', [
      'query' => ['entity_type' => 'mcp_etype_beta'],
    ]);
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('mcp_etype_beta');
    $this->assertSession()->pageTextNotContains('mcp_etype_alpha');
  }

  /**
   * T3.1: Filtering by uid.
   */
  public function testListingFilterByUid(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    // UID 3001 and 3002 are unlikely to be used for any system user.
    $this->seedRow('mcp_op_save', 'node', 3001);
    $this->seedRow('mcp_op_save', 'node', 3002);

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/audit', [
      'query' => ['uid' => '3002'],
    ]);
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('UID 3002');
    $this->assertSession()->pageTextNotContains('UID 3001');
  }

  /**
   * T3.1: Filtering by date range (from/to).
   */
  public function testListingFilterByDateRange(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    $now = \Drupal::time()->getRequestTime();
    // Old row: 2 hours ago, unique operation name.
    $this->seedRow('mcp_op_old', 'node', 1, $now - 7200);
    // Recent row: now, different unique operation.
    $this->seedRow('mcp_op_new', 'node', 1, $now);

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    // Filter to only last hour: mcp_op_old (2 h ago) should be excluded.
    $from = date('Y-m-d\TH:i', $now - 3600);
    $to   = date('Y-m-d\TH:i', $now + 60);
    $this->drupalGet('/admin/reports/mcp-sentinel/audit', [
      'query' => ['from' => $from, 'to' => $to],
    ]);
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('mcp_op_new');
    $this->assertSession()->pageTextNotContains('mcp_op_old');
  }

  /**
   * T3.1: The filter form is rendered on the listing page.
   */
  public function testFilterFormIsRendered(): void {
    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->fieldExists('operation');
    $this->assertSession()->fieldExists('entity_type');
    $this->assertSession()->fieldExists('uid');
    $this->assertSession()->fieldExists('from');
    $this->assertSession()->fieldExists('to');
  }

  /**
   * T3.2: CSV export contains headers and a seeded row.
   */
  public function testCsvExport(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    $this->seedRow('mcp_export_op');

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/export');
    $this->assertSession()->statusCodeEquals(200);

    $body = $this->getSession()->getPage()->getContent();
    // Check CSV header row.
    $this->assertStringContainsString('id,timestamp,uid,operation', $body);
    // Check a seeded row's operation.
    $this->assertStringContainsString('mcp_export_op', $body);
  }

  /**
   * T3.2: CSV export respects operation filter.
   */
  public function testCsvExportWithFilter(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    $this->seedRow('mcp_csv_alpha');
    $this->seedRow('mcp_csv_beta');

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/export', [
      'query' => ['operation' => 'mcp_csv_alpha'],
    ]);
    $this->assertSession()->statusCodeEquals(200);

    $body = $this->getSession()->getPage()->getContent();
    $this->assertStringContainsString('mcp_csv_alpha', $body);
    $this->assertStringNotContainsString('mcp_csv_beta', $body);
  }

  /**
   * T3.2: JSON export contains valid JSON with the seeded row.
   */
  public function testJsonExport(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    $this->seedRow('mcp_json_op');

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/export', [
      'query' => ['format' => 'json'],
    ]);
    $this->assertSession()->statusCodeEquals(200);

    $body = $this->getSession()->getPage()->getContent();
    $decoded = json_decode($body, TRUE);
    $this->assertIsArray($decoded);
    $this->assertNotEmpty($decoded);

    $operations = array_column($decoded, 'operation');
    $this->assertContains('mcp_json_op', $operations);
  }

  /**
   * T3.2: Export route requires 'view mcp sentinel audit log' permission.
   */
  public function testExportRequiresPermission(): void {
    $user = $this->drupalCreateUser([]);
    $this->drupalLogin($user);
    $this->drupalGet('/admin/reports/mcp-sentinel/export');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * D1: Audit rows show status badges and an expandable metadata detail block.
   */
  public function testRowsShowBadgesAndExpandableMetadata(): void {
    $this->seedRow('denied_access');
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->elementExists('css', '.mcp-badge');
    $this->assertSession()->elementExists('css', 'details.mcp-audit-detail');
    $this->assertSession()->pageTextContains('seed');
  }

  /**
   * D1: Prominent CSV and JSON export button links are present on the listing.
   */
  public function testProminentExportButtonsPresent(): void {
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->linkByHrefExists('/admin/reports/mcp-sentinel/export');
    $this->assertSession()->linkByHrefExists('format=json');
  }

  /**
   * D1: Empty state message shown when the log has no rows.
   */
  public function testEmptyStateShownWhenNoRows(): void {
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->pageTextContains('No audit log entries');
  }

  /**
   * T3.3: Metadata in the listing passes through decodeMetadata (no crash).
   *
   * Verifies the listing page loads even when metadata contains valid JSON.
   * The seam test: if json_decode were called directly, swapping in
   * encrypted data in Feature 5 would break this page — the accessor call
   * is the contract.
   */
  public function testListingMetadataViaDecodeMetadata(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();

    // Seed a row with metadata that is valid JSON.
    $this->seedRow('mcp_meta_read', 'node', 1);

    $admin = $this->drupalCreateUser(['view mcp sentinel audit log']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->statusCodeEquals(200);
    // The row should still appear (metadata decode did not crash the page).
    $this->assertSession()->pageTextContains('mcp_meta_read');
  }

}
