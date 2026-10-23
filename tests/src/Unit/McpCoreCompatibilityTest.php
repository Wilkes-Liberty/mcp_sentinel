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
 * File walking is limited to this project's own tree. On drupal.org,
 * gitlab_templates checks the module out as the project root and then
 * builds Drupal under web/ (plus vendor/). dirname(__DIR__, 3) is still
 * the module root on both layouts, but on d.o that directory also
 * contains the site. Walking it without a skip list reads core info.yml
 * files, the expanded site composer.json, and contrib calls to
 * user_role_grant_permissions().
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpCoreCompatibilityTest extends UnitTestCase {

  /**
   * Top-level names that are the built site, not this project.
   *
   * web/ is the gitlab_templates docroot. vendor/ is Composer.
   * The others are CI or editor leftovers that can sit in the
   * checkout on d.o.
   */
  private const BUILD_DIRECTORY_NAMES = [
    '.git',
    '.idea',
    'node_modules',
    'vendor',
    'web',
  ];

  /**
   * Current shipped info.yml count. A dropped file fails the scan.
   */
  private const SHIPPED_INFO_YML_FLOOR = 13;

  /**
   * Loose floor so an empty PHP scan cannot pass.
   *
   * The tree currently has a few hundred .php / .module / .install
   * files. The number is below that so adding files is fine and
   * losing a whole directory is not.
   */
  private const SHIPPED_PHP_FLOOR = 400;

  /**
   * Every info.yml keeps the 10.6 and 11.3 floors and declares Drupal 12.
   */
  public function testInfoYmlDeclaresDrupal12WithoutDroppingFloors(): void {
    $files = $this->infoYmlFiles();
    $this->assertGreaterThanOrEqual(
      self::SHIPPED_INFO_YML_FLOOR,
      count($files),
      'Expected the shipped info.yml files; '
      . 'the scan must not skip the project tree.',
    );
    $this->assertContains(
      'mcp_sentinel.info.yml',
      array_map($this->relativePath(...), $files),
    );

    foreach ($files as $path) {
      $this->assertNotBuildTreePath($path);
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
    $composer = $this->shippedComposerJson();
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
    $scanned = 0;
    foreach ($this->projectFiles() as $file) {
      if ($file->getFilename() === 'McpCoreCompatibilityTest.php') {
        continue;
      }
      $extension = $file->getExtension();
      if (!in_array($extension, ['php', 'module', 'install', 'inc'], TRUE)) {
        continue;
      }
      $path = $file->getPathname();
      $this->assertNotBuildTreePath($path);
      $scanned++;
      $contents = (string) file_get_contents($path);
      // Comments may name the deprecated helper; only a real call is a miss.
      $code = preg_replace('!/\*.*?\*/!s', '', $contents) ?? $contents;
      $code = preg_replace('!//.*$!m', '', $code) ?? $code;
      if (preg_match('/\buser_role_grant_permissions\s*\(/', $code)) {
        $hits[] = $this->relativePath($path);
      }
    }
    $this->assertGreaterThanOrEqual(
      self::SHIPPED_PHP_FLOOR,
      $scanned,
      'Expected to scan shipped PHP files; '
      . 'the walker must not skip the project tree.',
    );
    $this->assertSame(
      [],
      $hits,
      'The deprecated role grant helper must not be called; '
      . 'use McpRolePermissions::grant().',
    );
  }

  /**
   * Every shipped and test info.yml under the module root.
   *
   * @return string[]
   *   Absolute paths.
   */
  private function infoYmlFiles(): array {
    $files = [];
    foreach ($this->projectFiles() as $file) {
      if (!$file->isFile()
        || !str_ends_with($file->getFilename(), '.info.yml')) {
        continue;
      }
      $files[] = $file->getPathname();
    }
    sort($files);
    return $files;
  }

  /**
   * Files under the module root, skipping the built Drupal tree.
   *
   * @return \Traversable<\SplFileInfo>
   *   Project files only.
   */
  private function projectFiles(): \Traversable {
    $root = $this->moduleRoot();
    $iterator = new \RecursiveIteratorIterator(
      new \RecursiveCallbackFilterIterator(
        new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
        $this->isProjectEntry(...),
      ),
    );
    foreach ($iterator as $file) {
      if ($file->isFile()) {
        yield $file;
      }
    }
  }

  /**
   * TRUE when this directory entry is part of the project, not the site.
   *
   * @param \SplFileInfo $current
   *   The file or directory being considered.
   *
   * @return bool
   *   FALSE for a build directory so the walker does not descend.
   */
  private function isProjectEntry(\SplFileInfo $current): bool {
    if (!$current->isDir()) {
      return TRUE;
    }
    return !in_array(
      $current->getFilename(),
      self::BUILD_DIRECTORY_NAMES,
      TRUE,
    );
  }

  /**
   * Fail if a scanned path leaked into the built Drupal tree.
   */
  private function assertNotBuildTreePath(string $path): void {
    $relative = $this->relativePath($path);
    foreach (self::BUILD_DIRECTORY_NAMES as $name) {
      $prefix = $name . DIRECTORY_SEPARATOR;
      $this->assertFalse(
        str_starts_with($relative, $prefix),
        $relative . ' is under ' . $name . '/; the scan walked the built site.',
      );
    }
  }

  /**
   * The module composer.json, not gitlab_templates' expanded site file.
   *
   * expand_composer_json.php merges this package with core-recommended
   * and, when IGNORE_PROJECT_DRUPAL_CORE_VERSION is set, unsets
   * require.drupal/core. The working-tree composer.json at the checkout
   * root is then the site file. The committed document is the shipped
   * one.
   *
   * @return array<string, mixed>
   *   Decoded composer.json.
   */
  private function shippedComposerJson(): array {
    $path = $this->moduleRoot() . '/composer.json';
    $this->assertFileExists($path);
    $data = json_decode((string) file_get_contents($path), TRUE);
    $this->assertIsArray($data);
    if (!$this->isGitlabTemplatesSiteComposer($data)) {
      return $data;
    }
    $recovered = $this->recoverShippedComposerJson();
    $this->assertFalse(
      $this->isGitlabTemplatesSiteComposer($recovered),
      'Recovered composer.json is still the gitlab_templates site file.',
    );
    return $recovered;
  }

  /**
   * TRUE when composer.json is the expanded site file, not this module.
   *
   * The shipped file has neither extra.installer-paths nor
   * extra.drupal-scaffold. gitlab_templates always writes both.
   *
   * @param array<string, mixed> $data
   *   Decoded composer.json.
   *
   * @return bool
   *   TRUE for the expanded site file.
   */
  private function isGitlabTemplatesSiteComposer(array $data): bool {
    return isset(
      $data['extra']['installer-paths'],
      $data['extra']['drupal-scaffold'],
    );
  }

  /**
   * The committed composer.json, used when the working tree was expanded.
   *
   * composer.json.backup is the pre-expand copy. gitlab_templates
   * moves that file onto the custom mount before phpunit runs, so
   * the backup is usually gone by the time this test starts. The
   * git index is the shipped file either way.
   *
   * @return array<string, mixed>
   *   Decoded composer.json.
   */
  private function recoverShippedComposerJson(): array {
    $backup = $this->moduleRoot() . '/composer.json.backup';
    if (is_file($backup)) {
      $data = json_decode((string) file_get_contents($backup), TRUE);
      if (is_array($data) && !$this->isGitlabTemplatesSiteComposer($data)) {
        return $data;
      }
    }
    return $this->committedComposerJson();
  }

  /**
   * composer.json as committed in this checkout.
   *
   * @return array<string, mixed>
   *   Decoded composer.json.
   */
  private function committedComposerJson(): array {
    $root = $this->moduleRoot();
    $pipes = [];
    $process = proc_open(
      ['git', '-C', $root, 'show', ':composer.json'],
      [
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
      ],
      $pipes,
    );
    $this->assertIsResource(
      $process,
      'Could not start git to recover shipped composer.json.',
    );
    $stdout = (string) stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($process);
    $this->assertSame(0, $code, 'git show :composer.json failed: ' . $stderr);
    $data = json_decode($stdout, TRUE);
    $this->assertIsArray($data, 'Committed composer.json must decode as JSON.');
    return $data;
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
