<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Component\Serialization\Yaml;
use Drupal\mcp_sentinel\Service\McpInstallVerifier;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * The shipped install YAML is itself a claim: a clean supported install.
 *
 * These assertions read the files in config/install, the same way the
 * connector verifier reads config.example.json in CI.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpInstallVerifier
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpInstallVerifier::class)]
#[Group('mcp_sentinel')]
final class McpInstallVerifierShippedConfigTest extends UnitTestCase {

  /**
   * Shipped install files name no W&L host and carry no inline secret.
   */
  public function testShippedInstallIsTenantNeutral(): void {
    $findings = McpInstallVerifier::inspectShippedInstall($this->moduleRoot());
    $this->assertSame([], $findings);
  }

  /**
   * A W&L hostname in a fixture file is reported.
   */
  public function testShippedFileRejectsTenantHost(): void {
    $dir = $this->scratchDir();
    file_put_contents(
      $dir . '/mcp_sentinel.settings.yml',
      "webhook_url: 'https://hooks.wilkesliberty.com/sentinel'\n",
    );
    $findings = McpInstallVerifier::inspectShippedInstall($dir);
    $this->assertNotEmpty($findings);
    $this->assertStringContainsString('wilkesliberty.com', implode(' ', $findings));
  }

  /**
   * A reserved documentation host is not a finding.
   */
  public function testReservedHostIsNeutral(): void {
    $this->assertTrue(McpInstallVerifier::isNeutralHost('example.com'));
    $this->assertTrue(McpInstallVerifier::isNeutralHost('cms.example.org'));
    $this->assertTrue(McpInstallVerifier::isNeutralHost('localhost'));
    $this->assertTrue(McpInstallVerifier::isNeutralHost('www.drupal.org'));
    $this->assertFalse(McpInstallVerifier::isNeutralHost('hooks.wilkesliberty.com'));
    $this->assertFalse(McpInstallVerifier::isNeutralHost('cms.agency.gov'));
  }

  /**
   * The shipped default profile denies publish and does not grant config write.
   */
  public function testShippedDefaultProfileIsTheSecureFloor(): void {
    $profile = Yaml::decode((string) file_get_contents(
      $this->moduleRoot() . '/config/install/mcp_sentinel.mcp_policy_profile.default.yml',
    ));
    $this->assertTrue((bool) $profile['deny_publish']);
    $this->assertFalse((bool) $profile['allow_config_write']);
    $this->assertFalse((bool) $profile['allow_delete']);
    $this->assertFalse((bool) $profile['allow_raw_sql']);
  }

  /**
   * The shipped settings require finite budgets and leave the fallback off.
   */
  public function testShippedSettingsAreTheSecureFloor(): void {
    $settings = Yaml::decode((string) file_get_contents(
      $this->moduleRoot() . '/config/install/mcp_sentinel.settings.yml',
    ));
    $this->assertTrue((bool) $settings['require_finite_read_budgets']);
    $this->assertFalse((bool) $settings['governed_role_fallback']);
    $this->assertSame('', (string) $settings['webhook_secret']);
    $this->assertSame('', (string) $settings['webhook_url']);
    $this->assertNotEmpty($settings['classification_labels']);
  }

  /**
   * Module root (three levels up from tests/src/Unit).
   */
  private function moduleRoot(): string {
    return dirname(__DIR__, 3);
  }

  /**
   * A throwaway directory torn down by the test runner's temp cleanup.
   */
  private function scratchDir(): string {
    $dir = sys_get_temp_dir() . '/mcp-sentinel-verify-' . uniqid('', TRUE);
    mkdir($dir);
    return $dir;
  }

}
