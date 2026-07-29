<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAccessChecker
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpConfigAccessTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'tool', 'key', 'serialization',
    'consumers', 'simple_oauth', 'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Returns the access checker service.
   */
  private function checker(): McpAccessChecker {
    return $this->container->get('mcp_sentinel.access_checker');
  }

  /**
   * Creates an unsaved policy profile with the given values.
   *
   * @param array $values
   *   Profile field values beyond the required id/label.
   *
   * @return \Drupal\mcp_sentinel\Entity\McpPolicyProfile
   *   The unsaved profile entity.
   */
  private function profile(array $values): McpPolicyProfile {
    return McpPolicyProfile::create(['id' => 'p', 'label' => 'P'] + $values);
  }

  /**
   * Sets the master enabled flag in config.
   */
  private function setMaster(bool $enabled): void {
    $this->config('mcp_sentinel.settings')->set('enabled', $enabled)->save();
  }

  /**
   * Read is forbidden when the master switch is off, even if allowed.
   *
   * @covers ::checkConfigAccess
   */
  public function testDisabledForbidsConfig(): void {
    $this->setMaster(FALSE);
    $p = $this->profile(['allow_config_read' => TRUE, 'allow_config_write' => TRUE]);
    $this->assertTrue($this->checker()->checkConfigAccess('system.site', 'read', $p)->isForbidden());
    $this->assertTrue($this->checker()->checkConfigAccess('system.site', 'write', $p)->isForbidden());
  }

  /**
   * The read-only tier may read but not write configuration.
   *
   * @covers ::checkConfigAccess
   */
  public function testReadOnlyTier(): void {
    $this->setMaster(TRUE);
    $p = $this->profile(['allow_config_read' => TRUE, 'allow_config_write' => FALSE]);
    $this->assertFalse($this->checker()->checkConfigAccess('system.site', 'read', $p)->isForbidden());
    $this->assertTrue($this->checker()->checkConfigAccess('system.site', 'write', $p)->isForbidden());
  }

  /**
   * The write tier may both read and write configuration.
   *
   * @covers ::checkConfigAccess
   */
  public function testWriteTier(): void {
    $this->setMaster(TRUE);
    $p = $this->profile(['allow_config_read' => TRUE, 'allow_config_write' => TRUE]);
    $this->assertFalse($this->checker()->checkConfigAccess('system.site', 'read', $p)->isForbidden());
    $this->assertFalse($this->checker()->checkConfigAccess('system.site', 'write', $p)->isForbidden());
  }

  /**
   * Read is forbidden when config-read is off (safe default).
   *
   * @covers ::checkConfigAccess
   */
  public function testReadGateOffByDefault(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([]);
    $this->assertTrue(
      $this->checker()->checkConfigAccess('system.site', 'read', $p)->isForbidden(),
      'Config read must be denied by default.'
    );
    $this->assertTrue(
      $this->checker()->checkConfigAccess('system.site', 'write', $p)->isForbidden(),
      'Config write must be denied by default.'
    );
  }

  /**
   * A denied_config_types prefix blocks even a full-write profile.
   *
   * @covers ::checkConfigAccess
   * @covers ::checkConfigTypePolicy
   */
  public function testDeniedConfigTypeBeatsAllow(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([
      'allow_config_read' => TRUE,
      'allow_config_write' => TRUE,
      'denied_config_types' => ['system.'],
    ]);
    $this->assertTrue(
      $this->checker()->checkConfigAccess('system.site', 'write', $p)->isForbidden(),
      'A denied prefix must block writes regardless of allow_config_write.'
    );
    $this->assertTrue(
      $this->checker()->checkConfigAccess('system.site', 'read', $p)->isForbidden(),
      'A denied prefix must block reads regardless of allow_config_read.'
    );
    // A non-matching name is still permitted.
    $this->assertFalse(
      $this->checker()->checkConfigAccess('user.settings', 'write', $p)->isForbidden(),
      'A name not matching the denylist remains permitted.'
    );
  }

  /**
   * With allowed_ips set, the config result is uncacheable (max-age 0).
   *
   * @covers ::checkConfigAccess
   */
  public function testIpRestrictedConfigResultUncacheable(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([
      'allow_config_read' => TRUE,
      'allowed_ips' => ['203.0.113.0/24'],
    ]);
    $result = $this->checker()->checkConfigAccess('system.site', 'read', $p);
    $this->assertSame(0, $result->getCacheMaxAge(),
      'An IP-restricted profile must make the config result uncacheable.');
  }

}
