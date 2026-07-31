<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Functional;

use Drupal\mcp_sentinel_approval\Entity\McpAdminGrant;
use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Functional tests for the approval settings form and break-glass grants list.
 *
 * Covers the two admin surfaces added for operability: the settings form that
 * edits which operations require approval (and the break-glass TTL), and the
 * read-only break-glass grants list.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpApprovalAdminUiTest extends BrowserTestBase {

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
   * The settings form saves the gated operations and break-glass TTL.
   */
  public function testApprovalSettingsFormSavesConfig(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));

    $this->drupalGet('/admin/config/services/mcp-sentinel/approval');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->fieldExists('break_glass_ttl_seconds');

    $this->submitForm([
      'gated_operations[delete]'         => FALSE,
      'gated_operations[config_import]'  => TRUE,
      'gated_operations[module_disable]' => FALSE,
      'break_glass_ttl_seconds'          => 7200,
    ], 'Save configuration');

    $config = $this->config('mcp_sentinel_approval.settings');
    $this->assertSame(['config_import'], array_values($config->get('gated_operations')));
    $this->assertSame(7200, (int) $config->get('break_glass_ttl_seconds'));
  }

  /**
   * A user without the admin permission cannot reach the settings form.
   */
  public function testApprovalSettingsFormRequiresPermission(): void {
    $this->drupalLogin($this->drupalCreateUser(['approve mcp sentinel operations']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/approval');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * The break-glass grants list shows an active grant and its holder.
   */
  public function testBreakGlassGrantsListShowsActiveGrant(): void {
    $grantee = $this->drupalCreateUser([], 'breakglass-holder');
    $now = \Drupal::time()->getRequestTime();
    McpAdminGrant::create([
      'uid'     => $grantee->id(),
      'granted' => $now,
      'expires' => $now + 3600,
      'revoked' => FALSE,
    ])->save();

    $this->drupalLogin($this->drupalCreateUser(['approve mcp sentinel operations']));
    $this->drupalGet('/admin/reports/mcp-sentinel/grants');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('breakglass-holder');
    $this->assertSession()->pageTextContains('Active');
  }

  /**
   * Editing the mcp_admin role in People shows the break-glass warning.
   */
  public function testMcpAdminRoleFormShowsBreakGlassWarning(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer permissions']));
    $this->drupalGet('/admin/people/roles/manage/mcp_admin');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('MCP Sentinel break-glass role');
    $this->assertSession()->pageTextContains('time-boxed');
    $this->assertSession()->pageTextContains('administer mcp sentinel');
    $this->assertSession()->linkExists('Status report');
  }

  /**
   * Editing a different role does not show the break-glass warning.
   */
  public function testOtherRoleFormHasNoBreakGlassWarning(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer permissions']));
    $this->drupalGet('/admin/people/roles/manage/authenticated');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextNotContains('MCP Sentinel break-glass role');
  }

}
