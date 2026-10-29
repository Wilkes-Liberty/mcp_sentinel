<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Behat\Mink\Driver\BrowserKitDriver;
use Drupal\consumers\Entity\Consumer;
use Drupal\Tests\BrowserTestBase;
use Drupal\user\UserInterface;
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
    $this->assertSession()->fieldExists('tenant');
    $this->assertSession()->pageTextContains('Paladin is the sole issuer');
    $this->assertSession()->pageTextNotContains('DEV-843');
    $this->submitForm([
      'client_id' => 'mcp-agent-prod',
      'tenant' => 'tenant-a',
      'ttl' => '900',
    ], 'Mint sealed token');
    $this->assertSession()->addressEquals('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->responseHeaderContains('Cache-Control', 'no-store');
    // GET after mint is the prompt. The secret stays in tempstore.
    $this->assertSession()->pageTextContains('does not reveal the secret');
    $this->assertSession()->pageTextNotContains('Copy this token now');
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertSession()->pageTextNotContains('not-shown-in-ui');
    $this->submitForm([], 'Show sealed token');
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
   * GET never reveals the copy-once secret, even right after mint.
   */
  public function testGetDoesNotRevealSecret(): void {
    $this->mintDesignatedToken();
    $this->assertSession()->addressEquals('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->buttonExists('Show sealed token');
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertSession()->pageTextNotContains('Copy this token now');
    // A second GET still must not consume or echo the handoff.
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->buttonExists('Show sealed token');
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertRevealAuditCount(0);
    $this->assertRevealDeniedAuditCount(0);
  }

  /**
   * POST without a CSRF token is 403 and leaves the secret unrevealed.
   */
  public function testPostWithoutCsrfTokenIsForbiddenAndRevealsNothing(): void {
    $this->mintDesignatedToken();
    $this->assertRevealAuditCount(0);
    $this->assertRevealDeniedAuditCount(0);
    $this->postRevealPath();
    $this->assertSession()->statusCodeEquals(403);
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertSession()->pageTextNotContains('Copy this token now');
    $this->assertRevealAuditCount(0);
    $this->assertRevealDeniedAuditCount(1);
    $this->assertRevealDeniedAuditHasNoBearer();
    // A present but invalid token is the same deny: 403, secret untouched.
    $this->postRevealPath('not-a-csrf-token');
    $this->assertSession()->statusCodeEquals(403);
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertRevealAuditCount(0);
    $this->assertRevealDeniedAuditCount(2);
    $this->assertRevealDeniedAuditHasNoBearer();
    // Fail-closed: the handoff is still waiting for a valid POST.
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->buttonExists('Show sealed token');
    $this->assertSession()->pageTextNotContains('mcs1.');
  }

  /**
   * POST with a valid CSRF token reveals once, then the secret is gone.
   */
  public function testPostWithCsrfTokenRevealsOnce(): void {
    $this->mintDesignatedToken();
    $this->assertRevealAuditCount(0);
    // The Show button action already has the browser-session CSRF
    // token. Url::fromRoute() here signs a different session seed.
    $action = $this->assertSession()
      ->elementExists('css', 'form[method="post"]')
      ->getAttribute('action');
    $this->assertNotEmpty($action);
    $this->submitForm([], 'Show sealed token');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Copy this token now');
    $this->assertSession()->pageTextContains('mcs1.');
    $this->assertRevealAuditCount(1);
    $this->assertRevealAuditHasNoBearer();
    $this->assertRevealDeniedAuditCount(0);
    // Same CSRF query string after consume: gone page, no bearer.
    $this->postRevealUrl($action);
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('no longer shown');
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertRevealAuditCount(1);
    $this->assertRevealDeniedAuditCount(0);
  }

  /**
   * A successful reveal always writes, even when audit_enabled is off.
   */
  public function testRevealAuditWritesWhenAuditDisabled(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $this->mintDesignatedToken();
    $this->assertRevealAuditCount(0);
    $this->submitForm([], 'Show sealed token');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Copy this token now');
    $this->assertSession()->pageTextContains('mcs1.');
    $this->assertRevealAuditCount(1);
    $this->assertRevealAuditHasNoBearer();
  }

  /**
   * Unprivileged users cannot mint.
   */
  public function testForbiddenForUnprivilegedUser(): void {
    $this->drupalLogin($this->drupalCreateUser([]));
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * GET/POST without permission is 403, hides the secret, and does not consume.
   */
  public function testRevealPathForbiddenWithoutPermission(): void {
    $this->mintDesignatedToken();
    $admin = $this->loggedInUser;
    $this->assertInstanceOf(UserInterface::class, $admin);
    $this->assertRevealAuditCount(0);
    $this->assertRevealDeniedAuditCount(0);

    // Anonymous HTML 403s are redirected to login. The secret must still
    // stay hidden and the admin handoff must stay in tempstore.
    $this->drupalLogout();
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertRevealSecretNotShown();
    $this->postRevealPath();
    $this->assertRevealSecretNotShown();

    $this->drupalLogin($this->drupalCreateUser([]));
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->statusCodeEquals(403);
    $this->assertRevealSecretNotShown();
    $this->postRevealPath();
    $this->assertSession()->statusCodeEquals(403);
    $this->assertRevealSecretNotShown();

    $this->assertRevealAuditCount(0);
    $this->assertRevealDeniedAuditCount(0);

    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/services/mcp-sentinel/tokens/reveal');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->buttonExists('Show sealed token');
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertRevealAuditCount(0);
    $this->assertRevealDeniedAuditCount(0);
  }

  /**
   * Mints one designated-client token and lands on the GET reveal prompt.
   */
  private function mintDesignatedToken(): void {
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
    $this->submitForm([
      'client_id' => 'mcp-agent-prod',
      'tenant' => 'tenant-a',
      'ttl' => '900',
    ], 'Mint sealed token');
  }

  /**
   * Asserts the current page never showed the copy-once secret.
   */
  private function assertRevealSecretNotShown(): void {
    $this->assertSession()->pageTextNotContains('mcs1.');
    $this->assertSession()->pageTextNotContains('Copy this token now');
    $this->assertSession()->buttonNotExists('Show sealed token');
  }

  /**
   * POSTs the reveal path, optionally with a CSRF query token.
   *
   * Uses the Mink BrowserKit client so the logged-in session is kept and
   * assertSession() reads this POST. A missing or bad token must 403.
   *
   * @param string|null $tokenOverride
   *   Explicit token query value when testing a bad token.
   */
  private function postRevealPath(?string $tokenOverride = NULL): void {
    $options = ['absolute' => TRUE];
    if ($tokenOverride !== NULL) {
      $options['query']['token'] = $tokenOverride;
    }
    $this->postRevealUrl($this->buildUrl(
      '/admin/config/services/mcp-sentinel/tokens/reveal',
      $options,
    ));
  }

  /**
   * POSTs an already-built reveal URL through the BrowserKit client.
   *
   * @param string $url
   *   Absolute or root-relative URL, including any CSRF query string.
   */
  private function postRevealUrl(string $url): void {
    $driver = $this->getSession()->getDriver();
    $this->assertInstanceOf(BrowserKitDriver::class, $driver);
    // getAbsoluteUrl() keeps a relative ?token= query on the host.
    $driver->getClient()->request('POST', $this->getAbsoluteUrl($url));
  }

  /**
   * Asserts how many sealed_token_reveal audit rows exist.
   */
  private function assertRevealAuditCount(int $expected): void {
    $db = $this->container->get('database');
    $this->assertTrue($db->schema()->tableExists('audit_chain_log'));
    $count = (int) $db->select('audit_chain_log', 'l')
      ->condition('l.operation', 'sealed_token_reveal')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame($expected, $count);
  }

  /**
   * Asserts the latest reveal audit row never stored the bearer.
   */
  private function assertRevealAuditHasNoBearer(): void {
    $row = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'sealed_token_reveal')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row);
    $metadata = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $encoded = json_encode($metadata);
    $this->assertIsString($encoded);
    $this->assertStringNotContainsString('mcs1.', $encoded);
    $this->assertArrayHasKey('jti', $metadata);
    $this->assertNotSame('', $metadata['jti']);
  }

  /**
   * Asserts how many sealed_token_reveal_denied audit rows exist.
   */
  private function assertRevealDeniedAuditCount(int $expected): void {
    $db = $this->container->get('database');
    $this->assertTrue($db->schema()->tableExists('audit_chain_log'));
    $count = (int) $db->select('audit_chain_log', 'l')
      ->condition('l.operation', 'sealed_token_reveal_denied')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame($expected, $count);
  }

  /**
   * Asserts the latest reveal-denied row is csrf_invalid and has no bearer.
   */
  private function assertRevealDeniedAuditHasNoBearer(): void {
    $row = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'sealed_token_reveal_denied')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row);
    $metadata = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $encoded = json_encode($metadata);
    $this->assertIsString($encoded);
    $this->assertStringNotContainsString('mcs1.', $encoded);
    $this->assertSame('csrf_invalid', $metadata['reason'] ?? NULL);
    $this->assertSame(
      'mcp_sentinel.sealed_token_reveal_post',
      $metadata['route'] ?? NULL,
    );
    $this->assertArrayHasKey('uid', $metadata);
    $this->assertNotFalse($this->loggedInUser);
    $this->assertSame(
      (int) $this->loggedInUser->id(),
      (int) $metadata['uid'],
    );
    $this->assertArrayNotHasKey('token', $metadata);
  }

}
