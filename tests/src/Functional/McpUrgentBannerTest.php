<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Functional coverage for the site-wide critical urgent banner.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpUrgentBannerTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * A critical condition shows the banner site-wide for a permitted admin.
   */
  public function testCriticalBannerAppearsSiteWideForPermittedAdmin(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => FALSE,
      'broken_at' => 1,
      'rows' => 2,
      'time' => \Drupal::time()->getRequestTime(),
    ]);
    $this->drupalLogin($this->drupalCreateUser([
      'view mcp sentinel audit log',
      'access administration pages',
    ]));
    // An admin page that is NOT the dashboard.
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->elementExists('css', '.mcp-banner--critical');
  }

  /**
   * Warning/info conditions are not shown site-wide (dashboard-only).
   */
  public function testWarningBannerNotShownSiteWide(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('dashboard_broadcast', ['message' => 'note', 'severity' => 'warning'])
      ->save();
    $this->drupalLogin($this->drupalCreateUser([
      'view mcp sentinel audit log',
      'access administration pages',
    ]));
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->elementNotExists('css', '.mcp-banner--warning');
  }

  /**
   * The site-wide banner is not shown to an unprivileged user.
   */
  public function testBannerNotShownToUnprivilegedUser(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => FALSE,
      'broken_at' => 1,
      'rows' => 2,
      'time' => \Drupal::time()->getRequestTime(),
    ]);
    $this->drupalLogin($this->drupalCreateUser([]));
    $this->drupalGet('/user');
    $this->assertSession()->elementNotExists('css', '.mcp-banner--critical');
  }

  /**
   * The banner is not duplicated on the dashboard route itself.
   */
  public function testBannerNotDuplicatedOnDashboard(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => FALSE,
      'broken_at' => 1,
      'rows' => 2,
      'time' => \Drupal::time()->getRequestTime(),
    ]);
    $this->drupalLogin($this->drupalCreateUser(['view mcp sentinel audit log']));
    $this->drupalGet('/admin/reports/mcp-sentinel');
    // Exactly one critical banner (the dashboard's own), not a second from
    // hook_page_top().
    $this->assertSession()->elementsCount('css', '.mcp-banner--critical', 1);
  }

  /**
   * A dismissed critical condition does not reappear for that user.
   */
  public function testDismissedConditionStaysHidden(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => FALSE,
      'broken_at' => 1,
      'rows' => 2,
      'time' => \Drupal::time()->getRequestTime(),
    ]);
    $user = $this->drupalCreateUser([
      'view mcp sentinel audit log',
      'access administration pages',
    ]);
    $this->drupalLogin($user);
    // The banner is present before dismissal.
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->elementExists('css', '.mcp-banner--critical');
    // The dismissal endpoint URL (with a session-valid CSRF token) is exposed
    // to the dashboard JS via drupalSettings; reuse it to record the dismissal.
    $settings = $this->getDrupalSettings();
    $dismissUrl = $settings['mcpSentinel']['dismissUrl'];
    $this->assertNotEmpty($dismissUrl);
    $separator = str_contains($dismissUrl, '?') ? '&' : '?';
    $this->drupalGet($this->getAbsoluteUrl($dismissUrl . $separator . 'key=chain_broken'));
    $this->assertSession()->statusCodeEquals(200);
    // It no longer appears on a fresh admin page.
    $this->drupalGet('/admin/reports/mcp-sentinel/audit');
    $this->assertSession()->elementNotExists('css', '.mcp-banner--critical');
  }

}
