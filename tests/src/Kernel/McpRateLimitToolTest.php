<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests that governed tool plugins enforce the profile rate limit.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRateLimitToolTest extends KernelTestBase {

  use UserCreationTrait;

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
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel', 'node', 'user']);
    // Enable role fallback so the test account triggers governance.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)->save();
    // Set profile to 1 request per 60 s.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 1)->set('rate_limit_window', 60)->save();
  }

  /**
   * The second tool call within the window is rejected with a rate-limit msg.
   */
  public function testSecondCallBlockedByRateLimit(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);

    // Clear flood for this uid.
    $this->container->get('flood')
      ->clear('mcp_sentinel.profile.default.' . $account->id());

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    // First call: passes rate limit, fails for other reason (no bundle) — fine.
    $tool->setInputValue('action', 'create');
    $tool->setInputValue('bundle', '');
    $tool->setInputValue('title', 'T');
    $tool->execute();
    // Second call: must hit the rate limit.
    $tool->setInputValue('action', 'create');
    $tool->setInputValue('bundle', '');
    $tool->setInputValue('title', 'T');
    $tool->execute();
    $this->assertStringContainsStringIgnoringCase(
      'rate limit', (string) $tool->getResultMessage()
    );
  }

}
