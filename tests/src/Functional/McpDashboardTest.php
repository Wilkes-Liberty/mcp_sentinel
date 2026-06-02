<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Functional coverage for the governance dashboard, routing move, and tabs.
 */
#[Group('mcp_sentinel')]
final class McpDashboardTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel', 'block'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    // Stark places no blocks; surface the local-task tabs so they can be
    // asserted (Claro/Gin place this block automatically in production).
    $this->drupalPlaceBlock('local_tasks_block');
  }

  /**
   * The dashboard renders its core widgets for a permitted user.
   */
  public function testDashboardRendersForPermittedUser(): void {
    // The "Webhook deliveries" tab route requires 'administer mcp sentinel';
    // grant both so all three base tabs resolve for this user.
    $this->drupalLogin($this->drupalCreateUser([
      'view mcp sentinel audit log',
      'administer mcp sentinel',
    ]));
    $this->drupalGet('/admin/reports/mcp-sentinel');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->elementExists('css', '.mcp-dashboard');
    // Posture hero + status tiles present.
    $this->assertSession()->pageTextContains('Governance');
    // Active-controls strip present.
    $this->assertSession()->elementExists('css', '.mcp-active-controls');
    // Local tasks resolve.
    $this->assertSession()->linkExists('Dashboard');
    $this->assertSession()->linkExists('Audit log');
    $this->assertSession()->linkExists('Webhook deliveries');
  }

  /**
   * An unprivileged user is denied the dashboard.
   */
  public function testDashboardForbiddenForUnprivilegedUser(): void {
    $this->drupalLogin($this->drupalCreateUser([]));
    $this->drupalGet('/admin/reports/mcp-sentinel');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * The audit listing now resolves at the moved /audit path.
   */
  public function testAuditListingMovedToAuditPath(): void {
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Filter audit log');
  }

  /**
   * The six charts render (SVG fallback) and at least one drills to the audit.
   */
  public function testSixChartsRenderWithData(): void {
    $now = \Drupal::time()->getRequestTime();
    foreach (['entity_save', 'entity_save', 'denied_access'] as $op) {
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
        'timestamp' => $now - 60,
        'uid' => 1,
        'operation' => $op,
        'entity_type' => 'node',
        'entity_id' => '1',
        'metadata' => '{}',
      ])->execute();
    }
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel');
    // Six chart cells (SVG fallback — the charts module is absent in CI).
    $this->assertSession()->elementsCount('css', '.mcp-chart-cell', 6);
    // At least one chart links into the filtered audit log.
    $this->assertSession()->elementExists('css', '.mcp-chart-cell a[href*="/admin/reports/mcp-sentinel/audit"]');
  }

  /**
   * The window toggle changes the ?window= query and re-renders.
   */
  public function testWindowToggleChangesQuery(): void {
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel', ['query' => ['window' => '7d']]);
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->linkByHrefExists('window=30d');
  }

  /**
   * Verify-now runs, writes last_verify state, redirects, and shows a message.
   */
  public function testVerifyNowWritesStateAndRedirects(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel', 'view mcp sentinel audit log']);
    $this->drupalLogin($admin);
    // Follow the CSRF-protected Verify-now link from the dashboard.
    $this->drupalGet('/admin/reports/mcp-sentinel');
    $this->clickLink('Verify chain now');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->addressEquals('/admin/reports/mcp-sentinel');
    // The action wrote the last-verify state in the drush-compatible shape.
    $last = \Drupal::state()->get('mcp_sentinel.last_verify');
    $this->assertIsArray($last);
    $this->assertArrayHasKey('ok', $last);
    $this->assertArrayHasKey('rows', $last);
    $this->assertArrayHasKey('time', $last);
    $this->assertTrue($last['ok']);
  }

  /**
   * The Verify-now action is CSRF-protected (no token → access denied).
   */
  public function testVerifyNowRequiresCsrfToken(): void {
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel/verify');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * A broken stored chain surfaces the critical banner on the dashboard.
   */
  public function testCriticalBannerShownWhenChainBroken(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => FALSE,
      'broken_at' => 3,
      'rows' => 5,
      'time' => \Drupal::time()->getRequestTime(),
    ]);
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel');
    $this->assertSession()->elementExists('css', '.mcp-banner--critical');
  }

}
