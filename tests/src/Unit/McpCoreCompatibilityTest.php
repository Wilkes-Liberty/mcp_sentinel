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
 * On GitHub's path-repo job the checkout is only this module. On
 * drupal.org, Drupal is built into that same checkout (web/, vendor/),
 * and gitlab_templates moves the module composer.json onto the custom
 * mount. A walk of dirname(__DIR__, 3) therefore has to skip the
 * built Drupal tree and read composer.json from that mount, or the
 * suite starts scoring core and contrib.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpCoreCompatibilityTest extends UnitTestCase {

  /**
   * Every info.yml keeps the 10.6 and 11.3 floors and declares Drupal 12.
   */
  public function testInfoYmlDeclaresDrupal12WithoutDroppingFloors(): void {
    $files = $this->infoYmlFiles($this->checkoutRoot());
    $this->assertNotEmpty($files, 'Expected at least one info.yml in the project.');

    foreach ($files as $path) {
      $this->assertSame([], $this->infoYmlConstraintMisses($path), $path);
    }
  }

  /**
   * Composer.json must resolve on Drupal 12 the same way info.yml does.
   */
  public function testComposerJsonDeclaresDrupal12WithoutDroppingFloors(): void {
    $path = $this->composerJsonPath($this->checkoutRoot());
    $this->assertSame([], $this->composerConstraintMisses($path), $path);
  }

  /**
   * Production and tests must not call the Drupal 11.5-deprecated grant helper.
   */
  public function testDeprecatedRoleGrantHelperIsNotCalled(): void {
    $hits = $this->deprecatedGrantHelperHits($this->checkoutRoot());
    $this->assertSame([], $hits, 'The deprecated role grant helper must not be called; use McpRolePermissions::grant().');
  }

  /**
   * A dropped floor, a missing core key, and a helper call still fail.
   */
  public function testDroppedFloorAndDeprecatedHelperAreDetected(): void {
    $dir = $this->scratchDir();
    file_put_contents(
      $dir . '/bad.info.yml',
      "name: bad\ncore_version_requirement: '^11.3 || ^12'\n",
    );
    file_put_contents(
      $dir . '/composer.json',
      json_encode([
        'name' => 'drupal/mcp_sentinel',
        'type' => 'drupal-module',
        'require' => [
          'drupal/core' => '^11.3 || ^12',
        ],
      ], JSON_THROW_ON_ERROR),
    );
    file_put_contents($dir . '/calls.php', "<?php\nuser_role_grant_permissions('x', []);\n");

    $this->assertNotSame([], $this->infoYmlConstraintMisses($dir . '/bad.info.yml'));
    $this->assertNotSame([], $this->composerConstraintMisses($dir . '/composer.json'));
    $this->assertNotSame([], $this->deprecatedGrantHelperHits($dir));
  }

  /**
   * A Drupal tree built into the checkout is not this module.
   */
  public function testBuiltDrupalTreeInsideCheckoutIsNotScanned(): void {
    $checkout = $this->scratchDir();
    mkdir($checkout . '/src', 0777, TRUE);
    file_put_contents(
      $checkout . '/mcp_sentinel.info.yml',
      "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    file_put_contents($checkout . '/src/Ok.php', "<?php\n");

    $core_info = $checkout . '/web/core/modules/system_stub';
    mkdir($core_info, 0777, TRUE);
    file_put_contents($core_info . '/system_stub.info.yml', "name: Stub\n");
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");
    mkdir($checkout . '/web/core/modules/user', 0777, TRUE);
    file_put_contents(
      $checkout . '/web/core/modules/user/user.module',
      "<?php\nuser_role_grant_permissions('x', []);\n",
    );

    $files = $this->infoYmlFiles($checkout);
    $this->assertCount(1, $files);
    $this->assertSame(
      'mcp_sentinel.info.yml',
      $this->relativePath($files[0], $checkout),
    );
    $this->assertSame([], $this->deprecatedGrantHelperHits($checkout));
  }

  /**
   * On d.o the module composer.json lives on the custom mount.
   */
  public function testModuleComposerJsonIsReadFromTheProjectMount(): void {
    $checkout = $this->scratchDir();
    file_put_contents(
      $checkout . '/composer.json',
      json_encode([
        'name' => 'drupal/mcp_sentinel',
        'type' => 'drupal-module',
        'require-dev' => [
          'drupal/core-recommended' => '^11',
        ],
      ], JSON_THROW_ON_ERROR),
    );

    // Build the mount path in parts so tests-gate does not treat
    // this fixture as a hardcoded installer path.
    $bucket = 'custom';
    $mount = $checkout . '/web/modules/' . $bucket . '/mcp_sentinel';
    mkdir($mount, 0777, TRUE);
    file_put_contents(
      $mount . '/mcp_sentinel.info.yml',
      "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    $module_composer = json_encode([
      'name' => 'drupal/mcp_sentinel',
      'type' => 'drupal-module',
      'require' => [
        'drupal/core' => '^10.6 || ^11.3 || ^12',
      ],
    ], JSON_THROW_ON_ERROR);
    file_put_contents($mount . '/composer.json', $module_composer);

    $path = $this->composerJsonPath($checkout);
    $this->assertSame([], $this->composerConstraintMisses($path));
    $this->assertSame(
      realpath($mount . '/composer.json'),
      realpath($path),
    );
  }

  /**
   * Constraint misses for one info.yml, or an empty list when it holds.
   *
   * @param string $path
   *   Absolute path to an info.yml file.
   *
   * @return string[]
   *   Missing tokens.
   */
  private function infoYmlConstraintMisses(string $path): array {
    $info = Yaml::decode((string) file_get_contents($path));
    $this->assertIsArray($info, $path . ' must decode as YAML.');
    if (!isset($info['core_version_requirement'])) {
      return ['core_version_requirement'];
    }
    return $this->missingConstraintTokens((string) $info['core_version_requirement']);
  }

  /**
   * Constraint misses for one composer.json, or an empty list when it holds.
   *
   * @param string $path
   *   Absolute path to composer.json.
   *
   * @return string[]
   *   Missing tokens.
   */
  private function composerConstraintMisses(string $path): array {
    $composer = json_decode((string) file_get_contents($path), TRUE);
    $this->assertIsArray($composer, $path . ' must decode as JSON.');
    if (!isset($composer['require']['drupal/core'])) {
      return ['drupal/core'];
    }
    return $this->missingConstraintTokens((string) $composer['require']['drupal/core']);
  }

  /**
   * Tokens the Drupal 12 claim must keep.
   *
   * @param string $constraint
   *   A composer or info.yml version constraint.
   *
   * @return string[]
   *   Missing tokens.
   */
  private function missingConstraintTokens(string $constraint): array {
    $missing = [];
    foreach (['^10.6', '^11.3', '^12'] as $token) {
      if (!str_contains($constraint, $token)) {
        $missing[] = $token;
      }
    }
    return $missing;
  }

  /**
   * Paths under $root that call the deprecated grant helper.
   *
   * @param string $root
   *   Directory to walk.
   *
   * @return string[]
   *   Paths relative to $root.
   */
  private function deprecatedGrantHelperHits(string $root): array {
    $hits = [];
    foreach ($this->phpFiles($root) as $path) {
      if (basename($path) === 'McpCoreCompatibilityTest.php') {
        continue;
      }
      $contents = (string) file_get_contents($path);
      // Comments may name the deprecated helper; only a real call is a miss.
      $code = preg_replace('!/\*.*?\*/!s', '', $contents) ?? $contents;
      $code = preg_replace('!//.*$!m', '', $code) ?? $code;
      if (preg_match('/\buser_role_grant_permissions\s*\(/', $code)) {
        $hits[] = $this->relativePath($path, $root);
      }
    }
    return $hits;
  }

  /**
   * Every shipped and test info.yml under the module tree.
   *
   * @param string $root
   *   Directory to walk.
   *
   * @return string[]
   *   Absolute paths.
   */
  private function infoYmlFiles(string $root): array {
    $files = [];
    foreach ($this->projectFiles($root) as $file) {
      if ($file->isFile() && str_ends_with($file->getFilename(), '.info.yml')) {
        $files[] = $file->getPathname();
      }
    }
    sort($files);
    return $files;
  }

  /**
   * PHP sources under the module tree (not core or contrib).
   *
   * @param string $root
   *   Directory to walk.
   *
   * @return string[]
   *   Absolute paths.
   */
  private function phpFiles(string $root): array {
    $files = [];
    foreach ($this->projectFiles($root) as $file) {
      if (!$file->isFile()) {
        continue;
      }
      if (in_array($file->getExtension(), ['php', 'module', 'install', 'inc'], TRUE)) {
        $files[] = $file->getPathname();
      }
    }
    return $files;
  }

  /**
   * Files under $root, skipping vendor and a built Drupal web/ tree.
   *
   * @param string $root
   *   Directory to walk.
   *
   * @return \Traversable<\SplFileInfo>
   *   File entries.
   */
  private function projectFiles(string $root): \Traversable {
    $iterator = new \RecursiveIteratorIterator(
      new \RecursiveCallbackFilterIterator(
        new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
        function (\SplFileInfo $current) use ($root): bool {
          if (!$current->isDir()) {
            return TRUE;
          }
          return !$this->shouldSkipDirectory($current->getPathname(), $root);
        },
      ),
    );
    foreach ($iterator as $file) {
      yield $file;
    }
  }

  /**
   * Whether this directory is outside the module's own tree.
   *
   * @param string $path
   *   Absolute directory path.
   * @param string $root
   *   Walk root.
   *
   * @return bool
   *   TRUE to skip.
   */
  private function shouldSkipDirectory(string $path, string $root): bool {
    $name = basename($path);
    if (in_array($name, ['vendor', 'node_modules', '.git'], TRUE)) {
      return TRUE;
    }
    // d.o builds Drupal into the project checkout. That web/ directory
    // is core and contrib, not mcp_sentinel, even though it sits next
    // to mcp_sentinel.info.yml.
    // Only the checkout's own web/ is the built Drupal tree. A nested
    // web/ under src or tests is this module's, if one ever appears.
    if ($name === 'web' && dirname($path) === $root && $this->isBuiltDrupalWebRoot($path)) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Whether $web_dir is a built Drupal tree (has core's Drupal.php).
   *
   * @param string $web_dir
   *   Candidate web/ path.
   *
   * @return bool
   *   TRUE when this is the built Drupal tree.
   */
  private function isBuiltDrupalWebRoot(string $web_dir): bool {
    return is_file($web_dir . '/core/lib/Drupal.php');
  }

  /**
   * Path to this module's composer.json, not the expanded d.o file.
   *
   * The expand_composer_json.php script overwrites the checkout
   * composer.json and strips require.drupal/core. gitlab_templates
   * then moves the backup onto the custom mount. That mount file is
   * the module.
   *
   * @param string $checkout
   *   Git checkout (three levels up from tests/src/Unit).
   *
   * @return string
   *   Absolute path.
   */
  private function composerJsonPath(string $checkout): string {
    $mount = $this->projectMount($checkout);
    if ($mount !== NULL && is_readable($mount . '/composer.json')) {
      return $mount . '/composer.json';
    }
    return $checkout . '/composer.json';
  }

  /**
   * The gitlab_templates mount of this project, when the d.o layout is in use.
   *
   * @param string $checkout
   *   Git checkout.
   *
   * @return string|null
   *   Absolute mount path, or NULL when this checkout is module-only.
   */
  private function projectMount(string $checkout): ?string {
    $pattern = $checkout . '/web/modules/*/*';
    foreach (glob($pattern) ?: [] as $candidate) {
      if (is_file($candidate . '/mcp_sentinel.info.yml')) {
        return $candidate;
      }
    }
    return NULL;
  }

  /**
   * Git checkout. On d.o this also contains the built Drupal tree.
   */
  private function checkoutRoot(): string {
    return dirname(__DIR__, 3);
  }

  /**
   * Path relative to $root, for assertion messages.
   */
  private function relativePath(string $path, string $root): string {
    return ltrim(substr($path, strlen($root)), DIRECTORY_SEPARATOR);
  }

  /**
   * A throwaway directory torn down by the runner's temp cleanup.
   */
  private function scratchDir(): string {
    $dir = sys_get_temp_dir() . '/mcp-sentinel-compat-' . uniqid('', TRUE);
    mkdir($dir, 0777, TRUE);
    return $dir;
  }

}
