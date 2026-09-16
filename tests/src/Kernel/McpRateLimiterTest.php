<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Flood\DatabaseBackend;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpFloodKey;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests McpRateLimiter service and the rate-limit fields on McpPolicyProfile.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
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
    'audit_chain',
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
   * Zero requests stays unlimited only under the explicit override (#3616540).
   */
  public function testUnlimitedWhenZero(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', FALSE)->save();
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

  /**
   * Long identifiers retain isolated request and page budgets in real storage.
   */
  public function testLongFloodKeysRemainBoundedAndIsolated(): void {
    // KernelTestBase substitutes an in-memory flood backend by default.
    $this->container->set('flood', new DatabaseBackend(
      $this->container->get('database'),
      $this->container->get('request_stack'),
      $this->container->get('datetime.time'),
    ));
    $profile = McpPolicyProfile::create([
      'id' => str_repeat('p', 64),
      'label' => 'Long profile',
      'rate_limit_requests' => 1,
      'rate_limit_window' => 60,
    ]);
    $tool = str_repeat('tool_', 30);
    $uid = PHP_INT_MAX;
    $limiter = $this->container->get('mcp_sentinel.rate_limiter');
    self::assertTrue($limiter->check($profile, $uid, $tool));
    $limiter->register($profile, $uid, $tool);
    self::assertFalse($limiter->check($profile, $uid, $tool));
    self::assertTrue($limiter->check($profile, $uid - 1, $tool));
    self::assertTrue($limiter->check($profile, $uid, $tool . 'different'));
    $other = McpPolicyProfile::create([
      'id' => str_repeat('q', 64),
      'label' => 'Other profile',
      'rate_limit_requests' => 1,
      'rate_limit_window' => 60,
    ]);
    self::assertTrue($limiter->check($other, $uid, $tool));
    $this->config('mcp_sentinel.settings')->set('read_budget_defaults.pages', 1)->save();
    self::assertTrue($limiter->checkPageBudget($profile, $uid));
    $limiter->registerPageBudget($profile, $uid);
    self::assertFalse($limiter->checkPageBudget($profile, $uid));
    self::assertTrue($limiter->checkPageBudget($other, $uid));
    $events = $this->container->get('database')->select('flood', 'f')->fields('f', ['event'])->execute()->fetchCol();
    self::assertCount(2, $events);
    foreach ($events as $event) {
      self::assertSame(64, strlen($event));
    }
    self::assertNotSame($events[0], $events[1]);
    self::assertSame('mcp_sentinel.profile.default.1', McpFloodKey::normalize('mcp_sentinel.profile.default.1'));
  }

  /**
   * Upgrade preserves active counters, even across multiple update batches.
   */
  public function testUpgradePreservesLongLegacyCounters(): void {
    $database = $this->container->get('database');
    $backend = new DatabaseBackend($database, $this->container->get('request_stack'), $this->container->get('datetime.time'));
    $backend->register('mcp_sentinel.profile.default.1', 60, '1');
    // Simulate a permissive legacy backend such as SQLite: PostgreSQL could
    // never have stored these names under the original varchar(64) column.
    $database->schema()->changeField('flood', 'event', 'event', [
      'type' => 'varchar_ascii',
      'length' => 255,
      'not null' => TRUE,
    ]);
    $legacy = 'mcp_sentinel.profile.' . str_repeat('p', 64) . '.4242.long_tool';
    for ($index = 0; $index < 501; $index++) {
      $backend->register($legacy, 600, '4242');
    }
    $backend->register('unrelated.event', 60, 'other');
    $before = $database->select('flood', 'f')->fields('f')->orderBy('fid')->execute()->fetchAll(\PDO::FETCH_ASSOC);
    $this->container->get('module_handler')->loadInclude('mcp_sentinel', 'install');
    $sandbox = [];
    mcp_sentinel_update_10023($sandbox);
    self::assertSame(0, $sandbox['#finished']);
    mcp_sentinel_update_10023($sandbox);
    self::assertSame(1, $sandbox['#finished']);
    $after = $database->select('flood', 'f')->fields('f')->orderBy('fid')->execute()->fetchAll(\PDO::FETCH_ASSOC);
    foreach ($before as &$row) {
      if ($row['event'] === $legacy) {
        $row['event'] = McpFloodKey::normalize($legacy);
      }
    }
    unset($row);
    self::assertSame($before, $after, 'Only the overlong event name changes; every counter remains intact.');
    self::assertFalse($backend->isAllowed(McpFloodKey::normalize($legacy), 501, 600, '4242'));
    $sandbox = [];
    mcp_sentinel_update_10023($sandbox);
    self::assertSame(1, $sandbox['#finished'], 'A repeated update does not revisit normalized keys.');
  }

}
