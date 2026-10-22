<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Component\Serialization\Yaml;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\Group;

/**
 * The Drupal 12 declaration is itself a claim: keep it honest.
 *
 * Upgrade Status refuses next-major compatibility until every shipped
 * info.yml and composer.json include ^12. These assertions fail if that
 * constraint, or the 10.6 / 11.3 floors, regress. They do not install
 * Drupal 12 — hard dependencies still have to publish their own ^12
 * constraints before a next-major CI lane can resolve.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpCoreCompatibilityTest extends UnitTestCase {

  /**
   * Every info.yml keeps the 10.6 and 11.3 floors and declares Drupal 12.
   */
  public function testInfoYmlDeclaresDrupal12WithoutDroppingFloors(): void {
    $files = $this->infoYmlFiles();
    $this->assertNotEmpty($files, 'Expected at least one info.yml in the project.');

    foreach ($files as $path) {
      $info = Yaml::decode((string) file_get_contents($path));
      $this->assertIsArray($info, $path . ' must decode as YAML.');
      $this->assertArrayHasKey('core_version_requirement', $info, $path);
      $requirement = (string) $info['core_version_requirement'];
      $relative = $this->relativePath($path);
      $this->assertStringContainsString('^10.6', $requirement, $relative);
      $this->assertStringContainsString('^11.3', $requirement, $relative);
      $this->assertStringContainsString('^12', $requirement, $relative);
    }
  }

  /**
   * Composer.json must resolve on Drupal 12 the same way info.yml does.
   */
  public function testComposerJsonDeclaresDrupal12WithoutDroppingFloors(): void {
    $composer = json_decode((string) file_get_contents($this->moduleRoot() . '/composer.json'), TRUE);
    $this->assertIsArray($composer);
    $this->assertArrayHasKey('drupal/core', $composer['require']);
    $constraint = (string) $composer['require']['drupal/core'];
    $this->assertStringContainsString('^10.6', $constraint);
    $this->assertStringContainsString('^11.3', $constraint);
    $this->assertStringContainsString('^12', $constraint);
  }

  /**
   * Production and tests must not call the Drupal 11.5-deprecated grant helper.
   */
  public function testDeprecatedRoleGrantHelperIsNotCalled(): void {
    $hits = [];
    $root = $this->moduleRoot();
    $iterator = new \RecursiveIteratorIterator(
      new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
    );
    foreach ($iterator as $file) {
      if (!$file->isFile()) {
        continue;
      }
      $path = $file->getPathname();
      if (str_contains($path, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)) {
        continue;
      }
      if ($file->getFilename() === 'McpCoreCompatibilityTest.php') {
        continue;
      }
      $extension = $file->getExtension();
      if (!in_array($extension, ['php', 'module', 'install', 'inc'], TRUE)) {
        continue;
      }
      $contents = (string) file_get_contents($path);
      // Comments may name the deprecated helper; only a real call is a miss.
      $code = preg_replace('!/\*.*?\*/!s', '', $contents) ?? $contents;
      $code = preg_replace('!//.*$!m', '', $code) ?? $code;
      if (preg_match('/\buser_role_grant_permissions\s*\(/', $code)) {
        $hits[] = $this->relativePath($path);
      }
    }
    $this->assertSame([], $hits, 'The deprecated role grant helper must not be called; use McpRolePermissions::grant().');
  }

  /**
   * Every shipped and test info.yml under the module root.
   *
   * @return string[]
   *   Absolute paths.
   */
  private function infoYmlFiles(): array {
    $files = [];
    $root = $this->moduleRoot();
    $iterator = new \RecursiveIteratorIterator(
      new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
    );
    foreach ($iterator as $file) {
      if (!$file->isFile() || !str_ends_with($file->getFilename(), '.info.yml')) {
        continue;
      }
      if (str_contains($file->getPathname(), DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)) {
        continue;
      }
      $files[] = $file->getPathname();
    }
    sort($files);
    return $files;
  }

  /**
   * Module root (three levels up from tests/src/Unit).
   */
  private function moduleRoot(): string {
    return dirname(__DIR__, 3);
  }

  /**
   * Path relative to the module root, for assertion messages.
   */
  private function relativePath(string $path): string {
    return ltrim(substr($path, strlen($this->moduleRoot())), DIRECTORY_SEPARATOR);
  }

}
