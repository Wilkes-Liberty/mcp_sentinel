<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the time-boxed mcp_admin break-glass model.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpBreakGlassTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'tool', 'key', 'serialization',
    'file', 'image', 'options',
    'consumers', 'simple_oauth', 'encrypt',
    'audit_chain', 'mcp_sentinel', 'mcp_sentinel_approval',
  ];

  /**
   * A frozen-time test clock.
   */
  private int $now = 1000000;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('consumer');
    $this->installEntitySchema('oauth2_token');
    $this->installEntitySchema('mcp_approval_request');
    $this->installEntitySchema('mcp_admin_grant');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel', 'mcp_sentinel_approval']);

    // The break-glass role must exist on the site.
    Role::create(['id' => McpBreakGlassManager::ROLE_ID, 'label' => 'MCP admin'])->save();

    // Freeze time so expiry math is deterministic.
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturnCallback(fn (): int => $this->now);
    $this->container->set('datetime.time', $time);
  }

  /**
   * Returns the break-glass manager (rebuilt to pick up the mocked clock).
   */
  private function manager(): McpBreakGlassManager {
    return $this->container->get('mcp_sentinel_approval.break_glass');
  }

  /**
   * Granting adds the role and records a grant; cron later reaps it.
   *
   * @covers ::grant
   * @covers ::reapExpired
   */
  public function testGrantThenExpireRevokes(): void {
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 100)->save();
    $user = User::create(['name' => 'breakglass', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertTrue($result['granted']);

    $user = User::load($user->id());
    $this->assertTrue($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role granted.');

    // Before expiry: reaper is a no-op.
    $this->now += 50;
    $this->assertSame(0, $this->manager()->reapExpired());
    $user = User::load($user->id());
    $this->assertTrue($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role still held before expiry.');

    // After expiry: reaper removes the role and marks the grant revoked.
    $this->now += 100;
    $this->assertSame(1, $this->manager()->reapExpired());
    $user = User::load($user->id());
    $this->assertFalse($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role revoked after expiry.');
  }

  /**
   * An overlapping grant keeps the role when the earlier one expires.
   *
   * The reaper asks hasOtherActiveGrant() before removing the role, and that
   * question is answered by a second entity query with its own 'revoked'
   * condition. Nothing exercised it, so the same bind defect that made
   * reapExpired() a silent no-op would have made this one answer "no other
   * grant" every time -- and the reaper would have pulled the role out from
   * under a grant that had not expired yet. Renewing a break-glass grant
   * before the first lapses is the ordinary case, not an exotic one.
   *
   * @covers ::reapExpired
   */
  public function testStillActiveOverlappingGrantKeepsTheRole(): void {
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 100)->save();
    $user = User::create(['name' => 'overlap', 'status' => 1]);
    $user->save();
    $uid = (int) $user->id();

    // First grant: expires at now + 100.
    $this->assertTrue($this->manager()->grant($uid)['granted']);

    // Renewed 50s later, so the second grant runs to now + 150.
    $this->now += 50;
    $this->assertTrue($this->manager()->grant($uid)['granted']);

    // Past the first expiry but not the second: the lapsed grant is reaped,
    // and the role stays because the renewal still covers this user.
    $this->now += 60;
    $this->assertSame(1, $this->manager()->reapExpired(), 'The lapsed grant is revoked.');
    $user = User::load($uid);
    $this->assertTrue(
      $user->hasRole(McpBreakGlassManager::ROLE_ID),
      'The role survives while a later grant is still active.',
    );

    // Past the second expiry: nothing covers the user, so the role goes.
    $this->now += 100;
    $this->assertSame(1, $this->manager()->reapExpired(), 'The renewal is revoked in turn.');
    $user = User::load($uid);
    $this->assertFalse($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role revoked once no grant covers the user.');
  }

  /**
   * Granting to a non-existent user fails closed.
   *
   * @covers ::grant
   */
  public function testGrantUnknownUserFails(): void {
    $result = $this->manager()->grant(99999);
    $this->assertFalse($result['granted']);
  }

}
