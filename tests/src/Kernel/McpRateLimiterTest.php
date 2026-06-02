<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests McpRateLimiter service and the rate-limit fields on McpPolicyProfile.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRateLimiterTest extends KernelTestBase {

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
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * The profile entity stores and returns its rate-limit and cap fields.
   */
  public function testProfileHasRateLimitFields(): void {
    McpPolicyProfile::create([
      'id' => 'rl_test',
      'label' => 'RL Test',
      'rate_limit_requests' => 100,
      'rate_limit_window' => 60,
      'result_count_cap' => 200,
      'response_size_cap' => 512000,
    ])->save();
    $loaded = McpPolicyProfile::load('rl_test');
    $this->assertSame(100, $loaded->getRateLimitRequests());
    $this->assertSame(60, $loaded->getRateLimitWindow());
    $this->assertSame(200, $loaded->getResultCountCap());
    $this->assertSame(512000, $loaded->getResponseSizeCap());
  }

  /**
   * Within-limit requests are allowed and the 4th is blocked after 3.
   */
  public function testAllowedUnderThreshold(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 3)->set('rate_limit_window', 60)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    // Clear any stale flood entries for uid 1.
    $this->container->get('flood')->clear('mcp_sentinel.profile.default.1');
    /** @var \Drupal\mcp_sentinel\Service\McpRateLimiter $limiter */
    $limiter = $this->container->get('mcp_sentinel.rate_limiter');
    for ($i = 0; $i < 3; $i++) {
      $this->assertTrue($limiter->check($profile, 1, NULL));
      $limiter->register($profile, 1, NULL);
    }
    $this->assertFalse($limiter->check($profile, 1, NULL),
      'Must be blocked after threshold exhausted.');
  }

  /**
   * When rate_limit_requests is 0 (unlimited), flood is never called.
   */
  public function testUnlimitedWhenZero(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 0)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    $limiter = $this->container->get('mcp_sentinel.rate_limiter');
    for ($i = 0; $i < 500; $i++) {
      $this->assertTrue($limiter->check($profile, 1, NULL));
      $limiter->register($profile, 1, NULL);
    }
  }

}
