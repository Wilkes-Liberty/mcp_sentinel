<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigException;
use Drupal\key\Entity\Key;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for break-glass config-conduct auditing.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_approval\EventSubscriber\McpBreakGlassConductSubscriber
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpBreakGlassConductTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'tool',
    'key',
    'serialization',
    'file',
    'image',
    'options',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
    'mcp_sentinel_approval',
  ];

  /**
   * Frozen request time for deterministic grant expiry.
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
    $this->installSchema('mcp_sentinel_approval', ['mcp_sentinel_manifest_used']);
    $this->installConfig(['mcp_sentinel', 'mcp_sentinel_approval']);
    $this->configureSigningKey();
    if (User::load(1) === NULL) {
      User::create(['name' => 'root', 'status' => 1])->save();
    }

    if (Role::load(McpBreakGlassManager::ROLE_ID) === NULL) {
      Role::create([
        'id' => McpBreakGlassManager::ROLE_ID,
        'label' => 'MCP break-glass admin',
        'is_admin' => FALSE,
        'permissions' => McpBreakGlassManager::ALLOWED_PERMISSIONS,
      ])->save();
    }

    // Freeze time and rebind the manager (installConfig may have already
    // constructed a manager with the real clock).
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturnCallback(fn (): int => $this->now);
    $this->container->set('datetime.time', $time);
    $this->container->set('mcp_sentinel_approval.break_glass', new McpBreakGlassManager(
      $this->container->get('entity_type.manager'),
      $time,
      $this->container->get('config.factory'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('mcp_sentinel.action_manifest_sealer'),
      $this->container->get('mcp_sentinel_approval.manifest_binder'),
      $this->container->get('current_user'),
    ));

    // Ensure audit is on for ordinary paths; tests that flip it use logAlways.
    $this->config('mcp_sentinel.settings')->set('audit_enabled', TRUE)->save();
  }

  /**
   * Configures the audit-chain signing key the sealer shares with evidence.
   */
  private function configureSigningKey(): void {
    Key::create([
      'id' => 'break_glass_conduct_key',
      'label' => 'Break-glass conduct key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'break-glass-conduct-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'break_glass_conduct_key')
      ->save();
  }

  /**
   * Counts audit rows for an operation.
   */
  private function auditCount(string $operation): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Returns the latest audit row for an operation.
   *
   * @return array<string, mixed>
   *   The row, or empty array.
   */
  private function latestRow(string $operation): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('l.operation', $operation)
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    return is_array($row) ? $row : [];
  }

  /**
   * Returns the latest audit metadata payload for an operation.
   *
   * @return array
   *   Decoded metadata, or empty array.
   */
  private function latestMetadata(string $operation): array {
    $row = $this->latestRow($operation);
    if ($row === []) {
      return [];
    }
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) ($row['metadata'] ?? ''));
  }

  /**
   * Elevates a user with a live grant and sets them as current.
   *
   * @return \Drupal\user\Entity\User
   *   The elevated user.
   */
  private function elevateCurrentUser(): User {
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 3600)->save();
    $user = User::create(['name' => 'elevated_operator', 'status' => 1]);
    $user->save();
    $result = $this->container->get('mcp_sentinel_approval.break_glass')->grant((int) $user->id());
    $this->assertTrue($result['granted'], 'Grant for conduct tests must succeed.');
    $user = User::load($user->id());
    $this->assertNotNull($user);
    $this->container->get('current_user')->setAccount($user);
    return $user;
  }

  /**
   * Elevated config save produces config_save_break_glass with keys only.
   *
   * @covers ::onConfigSave
   */
  public function testElevatedConfigSaveIsAuditedWithKeysOnly(): void {
    $user = $this->elevateCurrentUser();
    $before = $this->auditCount('config_save_break_glass');

    $this->config('system.site')->set('name', 'Break-glass site')->save();

    $this->assertSame($before + 1, $this->auditCount('config_save_break_glass'));
    $row = $this->latestRow('config_save_break_glass');
    // entity_type / id are columns on the row; remaining keys stay in metadata.
    $this->assertSame('config', $row['entity_type'] ?? NULL);
    $this->assertSame('system.site', $row['entity_id'] ?? NULL);
    $meta = $this->latestMetadata('config_save_break_glass');
    $this->assertContains('name', $meta['changed_keys'] ?? []);
    $this->assertArrayNotHasKey('name', $meta, 'Values must not appear at the metadata root.');
    $this->assertSame((int) $user->id(), $meta['uid'] ?? 0);
    $this->assertArrayHasKey('grant_id', $meta);
    // No value payload under changed_keys — it is a list of names.
    foreach ($meta['changed_keys'] ?? [] as $key) {
      $this->assertIsString($key);
    }
  }

  /**
   * Setting audit_enabled false while elevated is itself audited.
   *
   * @covers ::onConfigSave
   */
  public function testDisablingAuditWhileElevatedIsAudited(): void {
    $this->elevateCurrentUser();
    $before = $this->auditCount('config_save_break_glass');

    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();

    $this->assertSame(
      $before + 1,
      $this->auditCount('config_save_break_glass'),
      'Turning audit off while elevated must leave a row (logAlways).',
    );
    $row = $this->latestRow('config_save_break_glass');
    $this->assertSame('mcp_sentinel.settings', $row['entity_id'] ?? NULL);
    $meta = $this->latestMetadata('config_save_break_glass');
    $this->assertContains('audit_enabled', $meta['changed_keys'] ?? []);
  }

  /**
   * An identical save with no active grant produces no break-glass audit row.
   *
   * @covers ::onConfigSave
   */
  public function testUngovernedAdminWithoutGrantIsNotAudited(): void {
    // Admin-shaped account with the role but no grant row.
    $role = Role::create([
      'id' => 'site_admin_like',
      'label' => 'Site admin like',
      'permissions' => ['administer mcp sentinel'],
    ]);
    $role->save();
    $user = User::create(['name' => 'standing_admin', 'status' => 1]);
    $user->addRole('site_admin_like');
    $user->save();
    $this->container->get('current_user')->setAccount($user);

    $before = $this->auditCount('config_save_break_glass');
    $this->config('system.site')->set('name', 'Standing admin site')->save();
    $this->assertSame(
      $before,
      $this->auditCount('config_save_break_glass'),
      'Ordinary ungoverned admin traffic must not produce break-glass rows.',
    );
  }

  /**
   * Holding mcp_admin without a live grant is not elevated for auditing.
   *
   * @covers ::onConfigSave
   */
  public function testRoleWithoutActiveGrantIsNotAudited(): void {
    $user = User::create(['name' => 'stale_role', 'status' => 1]);
    $user->addRole(McpBreakGlassManager::ROLE_ID);
    $user->save();
    $this->container->get('current_user')->setAccount($user);

    $before = $this->auditCount('config_save_break_glass');
    $this->config('system.site')->set('name', 'Stale role site')->save();
    $this->assertSame($before, $this->auditCount('config_save_break_glass'));
  }

  /**
   * Changing break-glass settings is audited as configuration, not use.
   *
   * @covers ::onConfigSave
   */
  public function testSettingsSaveIsConfiguredEvent(): void {
    $beforeConfigured = $this->auditCount('break_glass_configured');
    $beforeUse = $this->auditCount('config_save_break_glass');
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 1800)->save();
    $this->assertSame($beforeConfigured + 1, $this->auditCount('break_glass_configured'));
    $this->assertSame($beforeUse, $this->auditCount('config_save_break_glass'));
    $meta = $this->latestMetadata('break_glass_configured');
    $this->assertContains('break_glass_ttl_seconds', $meta['changed_keys'] ?? []);
  }

  /**
   * An elevated operator cannot save a policy profile.
   *
   * @covers ::onConfigSave
   */
  public function testElevatedPolicySaveIsRefused(): void {
    $this->elevateCurrentUser();
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $original = $profile->label();
    $profile->set('label', 'Promoted by break-glass');
    $before = $this->auditCount('break_glass_refused');
    $caught = NULL;
    try {
      $profile->save();
    }
    catch (\Throwable $e) {
      $caught = $e;
    }
    $this->assertInstanceOf(ConfigException::class, $caught);
    $this->assertStringContainsString('cannot promote policy', $caught->getMessage());
    $reloaded = McpPolicyProfile::load('default');
    $this->assertNotNull($reloaded);
    $this->assertSame($original, $reloaded->label());
    $this->assertSame($before + 1, $this->auditCount('break_glass_refused'));
    $meta = $this->latestMetadata('break_glass_refused');
    $this->assertSame('break_glass_policy_promotion', $meta['reason'] ?? NULL);
  }

  /**
   * An elevated operator cannot turn deny_publish off.
   *
   * @covers ::onConfigSave
   */
  public function testElevatedPublishFloorLiftIsRefused(): void {
    $this->elevateCurrentUser();
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $this->assertTrue($profile->deniesPublish());
    $profile->set('deny_publish', FALSE);
    $caught = NULL;
    try {
      $profile->save();
    }
    catch (\Throwable $e) {
      $caught = $e;
    }
    $this->assertInstanceOf(ConfigException::class, $caught);
    $this->assertStringContainsString('no-agent-publish floor', $caught->getMessage());
    $reloaded = McpPolicyProfile::load('default');
    $this->assertNotNull($reloaded);
    $this->assertTrue($reloaded->deniesPublish());
    $meta = $this->latestMetadata('break_glass_refused');
    $this->assertSame('break_glass_publish_floor', $meta['reason'] ?? NULL);
  }

}
