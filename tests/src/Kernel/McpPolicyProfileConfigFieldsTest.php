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
    $this->assertSame([], $profile->getEntityRules(), 'Entity rules default empty.');
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
      'allow_delete' => FALSE,
      'entity_rules' => ['taxonomy_term' => ['allow_delete' => TRUE]],
    ])->save();

    $profile = McpPolicyProfile::load('dev');
    $this->assertTrue($profile->allowsConfigRead());
    $this->assertTrue($profile->allowsConfigWrite());
    $this->assertSame(['system.', 'field.field.'], $profile->getDeniedConfigTypes());
    $this->assertFalse($profile->deniesPublish());
    $this->assertSame('needs_review', $profile->getMaxModerationState());
    $this->assertSame(
      ['taxonomy_term' => ['allow_delete' => TRUE]],
      $profile->getEntityRules()
    );
    $this->assertTrue(
      $profile->allowsDeleteForEntityType('taxonomy_term'),
      'The per-type override grants delete after reload.'
    );
    $this->assertFalse(
      $profile->allowsDeleteForEntityType('node'),
      'A type without an override falls back to the global allow_delete (false).'
    );
  }

}
