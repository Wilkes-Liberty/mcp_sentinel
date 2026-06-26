<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Covers the config-governance + publish-gate profile fields (safe defaults).
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Entity\McpPolicyProfile
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpPolicyProfileConfigFieldsTest extends KernelTestBase {

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
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * A bare profile returns the safe defaults for the new fields.
   *
   * @covers ::allowsConfigRead
   * @covers ::allowsConfigWrite
   * @covers ::getDeniedConfigTypes
   * @covers ::deniesPublish
   * @covers ::getMaxModerationState
   */
  public function testSafeDefaults(): void {
    $profile = McpPolicyProfile::create(['id' => 'bare', 'label' => 'Bare']);
    $this->assertFalse($profile->allowsConfigRead(), 'Config read defaults off.');
    $this->assertFalse($profile->allowsConfigWrite(), 'Config write defaults off.');
    $this->assertSame([], $profile->getDeniedConfigTypes());
    $this->assertTrue($profile->deniesPublish(), 'Publishing is denied by default.');
    $this->assertSame('', $profile->getMaxModerationState());
  }

  /**
   * The installed default profile carries the safe defaults too.
   */
  public function testInstalledDefaultProfile(): void {
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $this->assertFalse($profile->allowsConfigRead());
    $this->assertFalse($profile->allowsConfigWrite());
    $this->assertTrue($profile->deniesPublish());
  }

  /**
   * Values round-trip through save/load.
   */
  public function testRoundTrip(): void {
    McpPolicyProfile::create([
      'id' => 'dev',
      'label' => 'Dev',
      'allow_config_read' => TRUE,
      'allow_config_write' => TRUE,
      'denied_config_types' => ['system.', 'field.field.'],
      'deny_publish' => FALSE,
      'max_moderation_state' => 'needs_review',
    ])->save();

    $profile = McpPolicyProfile::load('dev');
    $this->assertTrue($profile->allowsConfigRead());
    $this->assertTrue($profile->allowsConfigWrite());
    $this->assertSame(['system.', 'field.field.'], $profile->getDeniedConfigTypes());
    $this->assertFalse($profile->deniesPublish());
    $this->assertSame('needs_review', $profile->getMaxModerationState());
  }

}
