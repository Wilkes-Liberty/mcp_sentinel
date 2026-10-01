<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\consumers\Entity\Consumer;
use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Functional coverage for the sealed-token mint UI (DEV-762).
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpSealedTokenUiTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'mcp_sentinel',
    'block',
    'consumers',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->drupalPlaceBlock('local_tasks_block');
  }

  /**
   * Admins see the mint page and a deep link when no client is designated.
   */
  public function testEmptyStateLinksToAddClient(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('No designated agent client');
    $this->assertSession()->linkExists('Add agent client');
    $this->assertSession()->pageTextContains('MCP');
    $this->assertSession()->pageTextContains('Readiness');
  }

  /**
   * A designated client can mint; the secret is copy-once and then gone.
   */
  public function testMintCopyOnceThenGoneAndRevoke(): void {
    $owner = $this->drupalCreateUser([]);
    $consumer = Consumer::create([
      'client_id' => 'mcp-agent-prod',
      'label' => 'MCP agent prod',
      'owner_id' => $owner->id(),
      'user_id' => $owner->id(),
      'secret' => 'not-shown-in-ui',
      'confidential' => TRUE,
      'status' => 1,
    ]);
    $consumer->save();
    $this->config('mcp_sentinel.settings')
      ->set('agent_oauth_clients', ['mcp-agent-prod'])
      ->save();

    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens');
    $this->assertSession()->fieldExists('client_id');
    $this->assertSession()->pageTextContains('mcp-agent-prod');
    $this->submitForm([
      'client_id' => 'mcp-agent-prod',
      'ttl' => '900',
    ], 'Mint sealed token');
    $this->assertSession()->addressEquals('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->pageTextContains('Copy this token now');
    $this->assertSession()->pageTextContains('TTL: 900 seconds');
    $this->assertSession()->pageTextContains('mcs1.');
    $this->assertSession()->pageTextNotContains('not-shown-in-ui');

    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->pageTextContains('no longer shown');
    $this->assertSession()->pageTextNotContains('mcs1.');

    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens');
    $this->assertSession()->pageTextContains('mcp-agent-prod');
    $this->assertSession()->pageTextContains('Active');
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->clickLink('Revoke');
    $this->assertSession()->pageTextContains('was revoked');
    $this->assertSession()->pageTextContains('Revoked');
  }

  /**
   * Unprivileged users cannot mint.
   */
  public function testForbiddenForUnprivilegedUser(): void {
    $this->drupalLogin($this->drupalCreateUser([]));
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens');
    $this->assertSession()->statusCodeEquals(403);
  }

}
