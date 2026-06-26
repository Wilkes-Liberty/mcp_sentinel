<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Config\ConfigException;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Covers McpConfigSaveSubscriber: governed config audit + denylist hard-deny.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\EventSubscriber\McpConfigSaveSubscriber
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpConfigSaveSubscriberTest extends KernelTestBase {

  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'tool', 'key', 'serialization',
    'consumers', 'simple_oauth', 'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_audit_log', 'mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel']);

    // Make the current user a governed agent via the role fallback.
    $this->enableRoleFallbackGovernance();
    Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    $account = User::create(['name' => 'agent', 'status' => 1]);
    $account->addRole('mcp_api');
    $account->save();
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Configures the default profile's config-governance fields.
   *
   * @param array $values
   *   Field values to set on the default profile.
   */
  private function configureProfile(array $values): void {
    $profile = McpPolicyProfile::load('default');
    foreach ($values as $key => $value) {
      $profile->set($key, $value);
    }
    $profile->save();
  }

  /**
   * Counts audit rows for an operation.
   */
  private function auditCount(string $operation): int {
    return (int) $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->condition('l.operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * A governed, non-denied config save is audited as config_save.
   *
   * @covers ::onConfigSave
   */
  public function testGovernedSaveIsAudited(): void {
    $this->configureProfile(['allow_config_write' => TRUE]);
    $this->config('user.settings')->set('anonymous', 'Visitor')->save();
    $this->assertGreaterThanOrEqual(1, $this->auditCount('config_save'),
      'A governed config save must produce a config_save audit row.');
  }

  /**
   * A governed save to a denied config name is hard-denied and reverted.
   *
   * @covers ::onConfigSave
   */
  public function testDeniedSaveThrowsAndReverts(): void {
    $this->configureProfile([
      'allow_config_write' => TRUE,
      'denied_config_types' => ['user.'],
    ]);
    $original = $this->config('user.settings')->get('anonymous');

    $thrown = FALSE;
    try {
      $this->config('user.settings')->set('anonymous', 'Hacked')->save();
    }
    catch (ConfigException $e) {
      $thrown = TRUE;
    }
    $this->assertTrue($thrown, 'A write to a denied config name must throw.');

    // The persisted value is reverted to the original.
    $reverted = $this->container->get('config.factory')
      ->get('user.settings')
      ->get('anonymous');
    $this->assertSame($original, $reverted, 'The denied write must be reverted.');
    $this->assertGreaterThanOrEqual(1, $this->auditCount('config_write_denied'),
      'A denied write must be audited as config_write_denied.');
  }

}
