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
