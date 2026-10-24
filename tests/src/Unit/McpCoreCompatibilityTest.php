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
 * built Drupal tree — and only when git does not track web/ and
 * the mount resolves to this checkout — and read composer.json
 * from that mount, or the suite starts scoring core and contrib.
 *
 * The d.o phpunit job runs as www-data after a chown of the
 * checkout. Git is in that image; if it cannot answer, the skip
 * stays off (fail closed). Git is invoked with safe.directory
 * set to the walk root so an ownership mismatch cannot turn the
 * skip off and walk core again.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpCoreCompatibilityTest extends UnitTestCase {

  /**
   * Scratch directories this instance created.
   *
   * @var string[]
   */
  private array $scratchDirectories = [];

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    foreach ($this->scratchDirectories as $directory) {
      $this->removeScratchDirectory($directory);
    }
    $this->scratchDirectories = [];
    parent::tearDown();
  }

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
    $this->plantCustomMount($checkout);

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
    // web/ is the d.o build: present on disk, not tracked.
    $this->initGitCheckout($checkout, [
      'mcp_sentinel.info.yml',
      'src',
    ]);

    $files = $this->infoYmlFiles($checkout);
    $this->assertCount(1, $files);
    $this->assertSame(
      'mcp_sentinel.info.yml',
      $this->relativePath($files[0], $checkout),
    );
    $this->assertSame([], $this->deprecatedGrantHelperHits($checkout));
  }

  /**
   * A root web/ that only plants Drupal.php is still this module.
   */
  public function testRootWebWithDrupalPhpIsStillScanned(): void {
    $checkout = $this->scratchDir();
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");
    file_put_contents(
      $checkout . '/web/core/bad.info.yml',
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );
    mkdir($checkout . '/web/core/modules/user', 0777, TRUE);
    file_put_contents(
      $checkout . '/web/core/modules/user/user.module',
      "<?php\nuser_role_grant_permissions('x', []);\n",
    );

    $planted = $checkout . '/web/core/bad.info.yml';
    $this->assertContains($planted, $this->infoYmlFiles($checkout));
    $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
    $this->assertNotSame([], $this->deprecatedGrantHelperHits($checkout));
  }

  /**
   * A nested web/ is still this module, even with a custom-looking mount.
   *
   * The checkout is a real git repo and src/web is untracked with a
   * resolving mount. If the skip is applied at any depth, this
   * planted miss is invisible.
   */
  public function testNestedWebIsStillScanned(): void {
    $checkout = $this->scratchDir();
    file_put_contents(
      $checkout . '/mcp_sentinel.info.yml',
      "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    $this->initGitCheckout($checkout, ['mcp_sentinel.info.yml']);
    $nested = $checkout . '/src/web';
    mkdir($nested . '/core/lib', 0777, TRUE);
    file_put_contents($nested . '/core/lib/Drupal.php', "<?php\n");
    mkdir($nested . '/modules/custom/mcp_sentinel', 0777, TRUE);
    symlink(
      $checkout . '/mcp_sentinel.info.yml',
      $nested . '/modules/custom/mcp_sentinel/mcp_sentinel.info.yml',
    );
    $planted = $nested . '/planted.info.yml';
    file_put_contents(
      $planted,
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );
    file_put_contents(
      $nested . '/calls.php',
      "<?php\nuser_role_grant_permissions('x', []);\n",
    );

    $this->assertContains($planted, $this->infoYmlFiles($checkout));
    $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
    $this->assertNotSame([], $this->deprecatedGrantHelperHits($checkout));
  }

  /**
   * A mount that only copies info.yml is not the d.o symlink mount.
   *
   * The web/ tree is untracked, so the git guard would allow a
   * skip. The copy has a different realpath than the checkout
   * file; if that comparison is removed, this web/ is skipped
   * and the planted miss is invisible.
   */
  public function testCopiedMountInfoYmlDoesNotSkipWeb(): void {
    $checkout = $this->scratchDir();
    $info = "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n";
    file_put_contents($checkout . '/mcp_sentinel.info.yml', $info);
    $this->initGitCheckout($checkout, ['mcp_sentinel.info.yml']);

    $mount = $checkout . '/web/modules/custom/mcp_sentinel';
    mkdir($mount, 0777, TRUE);
    file_put_contents($mount . '/mcp_sentinel.info.yml', $info);
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");
    $planted = $checkout . '/web/core/bad.info.yml';
    file_put_contents(
      $planted,
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );

    $this->assertNotSame(
      realpath($checkout . '/mcp_sentinel.info.yml'),
      realpath($mount . '/mcp_sentinel.info.yml'),
    );
    $this->assertContains($planted, $this->infoYmlFiles($checkout));
    $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
  }

  /**
   * A committed symlink under web/ is this repo, not the d.o build.
   */
  public function testTrackedWebMountDoesNotSkipWeb(): void {
    $checkout = $this->scratchDir();
    file_put_contents(
      $checkout . '/mcp_sentinel.info.yml',
      "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    $this->plantCustomMount($checkout);
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");
    $planted = $checkout . '/web/core/bad.info.yml';
    file_put_contents(
      $planted,
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );
    $this->initGitCheckout($checkout, [
      'mcp_sentinel.info.yml',
      'web/modules/custom/mcp_sentinel/mcp_sentinel.info.yml',
      'web/core/bad.info.yml',
    ]);

    $this->assertSame(
      realpath($checkout . '/mcp_sentinel.info.yml'),
      realpath($checkout . '/web/modules/custom/mcp_sentinel/mcp_sentinel.info.yml'),
    );
    $this->assertContains($planted, $this->infoYmlFiles($checkout));
    $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
  }

  /**
   * A built web/ is still scanned when git is not on PATH.
   *
   * The php-8.3-ubuntu-apache image installs git. If that binary
   * is missing, ls-files cannot answer and the skip must stay
   * off — the core/contrib walk that failed pipelines 1012720,
   * 1012776, and 1012775.
   */
  public function testMissingGitBinaryDoesNotSkipBuiltWeb(): void {
    $checkout = $this->plantBuiltWebWithBadCoreInfo();
    $previous_path = getenv('PATH');
    putenv('PATH=/nonexistent-mcp-sentinel-compat-git');
    try {
      $this->assertNull($this->gitExecutable());
      $planted = $checkout . '/web/core/bad.info.yml';
      $this->assertContains($planted, $this->infoYmlFiles($checkout));
      $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
    }
    finally {
      if (is_string($previous_path)) {
        putenv('PATH=' . $previous_path);
      }
      else {
        putenv('PATH');
      }
    }
  }

  /**
   * A built web/ is still scanned when the checkout has no .git.
   *
   * The phpunit job's helper clone leaves .git; composer
   * artifacts exclude it. If that metadata is absent, do not
   * skip.
   */
  public function testCheckoutWithoutGitMetadataDoesNotSkipBuiltWeb(): void {
    $checkout = $this->plantBuiltWebWithBadCoreInfo();
    $this->assertDirectoryDoesNotExist($checkout . '/.git');
    $planted = $checkout . '/web/core/bad.info.yml';
    $this->assertContains($planted, $this->infoYmlFiles($checkout));
    $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
  }

  /**
   * A non-repo nested in a parent git checkout is not that parent.
   *
   * Git -C walks up. Without a toplevel pin, ls-files answers
   * from the parent (no tracked web/) and this planted miss is
   * skipped.
   */
  public function testNestedNonRepoInsideParentGitDoesNotSkipWeb(): void {
    $parent = $this->scratchDir();
    file_put_contents($parent . '/README', "parent\n");
    $this->initGitCheckout($parent, ['README']);
    $checkout = $parent . '/module';
    mkdir($checkout, 0777, TRUE);
    file_put_contents(
      $checkout . '/mcp_sentinel.info.yml',
      "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    $this->plantCustomMount($checkout);
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");
    $planted = $checkout . '/web/core/bad.info.yml';
    file_put_contents(
      $planted,
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );

    $this->assertDirectoryDoesNotExist($checkout . '/.git');
    $this->assertContains($planted, $this->infoYmlFiles($checkout));
    $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
  }

  /**
   * An inherited GIT_DIR cannot make a tracked web/ look untracked.
   *
   * GIT_WORK_TREE is set to this checkout so --show-toplevel still
   * names $root; only stripping GIT_* keeps ls-files on this repo.
   */
  public function testInheritedGitDirDoesNotSkipTrackedWeb(): void {
    $foreign = $this->scratchDir();
    file_put_contents($foreign . '/README', "foreign\n");
    $this->initGitCheckout($foreign, ['README']);

    $checkout = $this->scratchDir();
    file_put_contents(
      $checkout . '/mcp_sentinel.info.yml',
      "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    $this->plantCustomMount($checkout);
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");
    $planted = $checkout . '/web/core/bad.info.yml';
    file_put_contents(
      $planted,
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );
    $this->initGitCheckout($checkout, [
      'mcp_sentinel.info.yml',
      'web/modules/custom/mcp_sentinel/mcp_sentinel.info.yml',
      'web/core/bad.info.yml',
    ]);

    $previous_git_dir = getenv('GIT_DIR');
    $previous_work_tree = getenv('GIT_WORK_TREE');
    putenv('GIT_DIR=' . $foreign . '/.git');
    putenv('GIT_WORK_TREE=' . $checkout);
    try {
      $this->assertContains($planted, $this->infoYmlFiles($checkout));
      $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
    }
    finally {
      $this->restoreEnvironmentVariable('GIT_DIR', $previous_git_dir);
      $this->restoreEnvironmentVariable('GIT_WORK_TREE', $previous_work_tree);
    }
  }

  /**
   * A built web/ is still scanned when ls-files exits non-zero.
   *
   * A fake git that names this checkout as toplevel would pass
   * the pin. The exit-status check is then the only thing
   * keeping the skip off.
   */
  public function testLsFilesFailureDoesNotSkipBuiltWeb(): void {
    $checkout = $this->plantBuiltWebWithBadCoreInfo();
    $script = $this->fakeGitArgParser() . <<<'SH'
case "$cmd" in
  rev-parse) printf '%s\n' "$(pwd)"; exit 0 ;;
  ls-files) exit 1 ;;
  *) exit 1 ;;
esac
SH;
    $this->withFakeGit($script, function () use ($checkout): void {
      $planted = $checkout . '/web/core/bad.info.yml';
      $this->assertContains($planted, $this->infoYmlFiles($checkout));
      $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
    });
  }

  /**
   * A built web/ is still scanned when --show-toplevel is empty.
   *
   * Exit 0 with no path makes realpath('') resolve to CWD. The
   * test changes directory into the checkout so that fallback
   * would match $root and skip this planted miss.
   */
  public function testEmptyGitToplevelDoesNotSkipBuiltWeb(): void {
    $checkout = $this->plantBuiltWebWithBadCoreInfo();
    $cwd = getcwd();
    if (!is_string($cwd)) {
      $this->fail('getcwd() must return the current directory.');
    }
    $script = $this->fakeGitArgParser() . <<<'SH'
case "$cmd" in
  rev-parse) exit 0 ;;
  ls-files) exit 0 ;;
  *) exit 1 ;;
esac
SH;
    $this->withFakeGit($script, function () use ($checkout, $cwd): void {
      $this->assertTrue(chdir($checkout));
      try {
        $planted = $checkout . '/web/core/bad.info.yml';
        $this->assertContains($planted, $this->infoYmlFiles($checkout));
        $this->assertNotSame([], $this->infoYmlConstraintMisses($planted));
      }
      finally {
        chdir($cwd);
      }
    });
  }

  /**
   * Nested vendor/ and node_modules/ trees are still this module.
   */
  public function testNestedVendorAndNodeModulesAreStillScanned(): void {
    $checkout = $this->scratchDir();
    mkdir($checkout . '/src/vendor', 0777, TRUE);
    file_put_contents(
      $checkout . '/src/vendor/calls.php',
      "<?php\nuser_role_grant_permissions('x', []);\n",
    );
    mkdir($checkout . '/tests/node_modules', 0777, TRUE);
    $planted = $checkout . '/tests/node_modules/planted.info.yml';
    file_put_contents(
      $planted,
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );

    $this->assertNotSame([], $this->deprecatedGrantHelperHits($checkout));
    $this->assertContains($planted, $this->infoYmlFiles($checkout));
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

    $mount = $checkout . '/web/modules/custom/mcp_sentinel';
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
   * Custom and contrib copies of this module cannot both be present.
   */
  public function testBothCustomAndContribMountsAreRejected(): void {
    $checkout = $this->scratchDir();
    $module_composer = json_encode([
      'name' => 'drupal/mcp_sentinel',
      'type' => 'drupal-module',
      'require' => [
        'drupal/core' => '^10.6 || ^11.3 || ^12',
      ],
    ], JSON_THROW_ON_ERROR);
    foreach ([
      $checkout . '/web/modules/custom/mcp_sentinel',
      $checkout . '/web/modules/contrib/mcp_sentinel',
    ] as $dir) {
      mkdir($dir, 0777, TRUE);
      file_put_contents($dir . '/mcp_sentinel.info.yml', "name: 'MCP Sentinel'\n");
      file_put_contents($dir . '/composer.json', $module_composer);
    }

    $this->expectException(\RuntimeException::class);
    $this->expectExceptionMessage('custom mount and a contrib copy');
    $this->composerJsonPath($checkout);
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
   * Files under $root, skipping checkout-root vendor and a d.o-built web/.
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
    // Only the checkout-root copies are installer trees. A helper
    // under src/vendor or an info.yml under tests/node_modules is ours.
    if (in_array($name, ['vendor', 'node_modules', '.git'], TRUE) && dirname($path) === $root) {
      return TRUE;
    }
    // d.o builds Drupal into the project checkout. That web/ directory
    // is core and contrib, not mcp_sentinel, even though it sits next
    // to mcp_sentinel.info.yml.
    // Skip only the checkout's own web/, and only when git does
    // not track it (the d.o build is untracked) and the
    // gitlab_templates custom mount resolves here. A committed
    // symlink under web/, a root web/ that merely contains
    // core/lib/Drupal.php, a nested web/, or a tree git cannot
    // describe, is still this tree.
    if (
      $name === 'web'
      && dirname($path) === $root
      && $this->webDirectoryIsUntracked($root)
      && $this->isBuiltDrupalWebRoot($path, $root)
    ) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Whether $web_dir is the d.o-built Drupal tree for this checkout.
   *
   * The gitlab_templates scripts write web/ next to the module and
   * mount the project at web/modules/custom/mcp_sentinel. The
   * mount's mcp_sentinel.info.yml must resolve to this checkout's
   * file. A planted Drupal.php is not enough.
   *
   * @param string $web_dir
   *   Candidate web/ path.
   * @param string $root
   *   Walk root (the git checkout).
   *
   * @return bool
   *   TRUE when this is the built Drupal tree.
   */
  private function isBuiltDrupalWebRoot(string $web_dir, string $root): bool {
    $mount_info = $web_dir . '/modules/custom/mcp_sentinel/mcp_sentinel.info.yml';
    $checkout_info = $root . '/mcp_sentinel.info.yml';
    if (!is_file($mount_info) || !is_file($checkout_info)) {
      return FALSE;
    }
    $mount_real = realpath($mount_info);
    $checkout_real = realpath($checkout_info);
    return $mount_real !== FALSE && $mount_real === $checkout_real;
  }

  /**
   * Whether git tracks nothing under $root/web.
   *
   * The d.o build writes web/ beside the module; those files are
   * not in the project tree. A committed path under web/ is this
   * repo. If git cannot be asked — missing binary, no .git, a
   * toplevel that is not $root, or a non-zero ls-files — do not
   * skip (fail closed).
   *
   * @param string $root
   *   Walk root.
   *
   * @return bool
   *   TRUE only when git answers and lists no tracked web/ paths.
   */
  private function webDirectoryIsUntracked(string $root): bool {
    $tracked = $this->gitLsFiles($root, 'web');
    return $tracked !== NULL && $tracked === [];
  }

  /**
   * Paths git tracks under $path, or NULL when git cannot answer.
   *
   * @param string $root
   *   Repository root.
   * @param string $path
   *   Path relative to $root.
   *
   * @return string[]|null
   *   Tracked paths, or NULL when git is missing or $root is not a
   *   repository.
   */
  private function gitLsFiles(string $root, string $path): ?array {
    $git = $this->gitExecutable();
    if ($git === NULL) {
      return NULL;
    }
    if (!$this->gitToplevelIs($git, $root)) {
      return NULL;
    }
    $result = $this->runGitCommand($git, $root, ['ls-files', '-z', '--', $path]);
    if ($result === NULL) {
      return NULL;
    }
    if ($result['stdout'] === '') {
      return [];
    }
    return array_values(array_filter(explode("\0", $result['stdout'])));
  }

  /**
   * Whether git's toplevel for $root is $root itself.
   *
   * The git -C option walks up to a parent repo. An inherited
   * GIT_DIR can point at another tree. Either way, ls-files is
   * not about this checkout. A .git file that names a foreign
   * repo is local tampering and cannot be committed.
   *
   * @param string $git
   *   Absolute git executable.
   * @param string $root
   *   Walk root.
   *
   * @return bool
   *   TRUE when --show-toplevel realpath equals $root.
   */
  private function gitToplevelIs(string $git, string $root): bool {
    $result = $this->runGitCommand($git, $root, ['rev-parse', '--show-toplevel']);
    if ($result === NULL || $result['status'] !== 0) {
      return FALSE;
    }
    $toplevel = realpath(trim($result['stdout']));
    $root_real = realpath($root);
    return $toplevel !== FALSE && $root_real !== FALSE && $toplevel === $root_real;
  }

  /**
   * Absolute path to git, or NULL when it is not on PATH.
   *
   * @return string|null
   *   Executable path.
   */
  private function gitExecutable(): ?string {
    $paths = getenv('PATH');
    if (!is_string($paths) || $paths === '') {
      return NULL;
    }
    foreach (explode(PATH_SEPARATOR, $paths) as $dir) {
      $candidate = $dir . DIRECTORY_SEPARATOR . 'git';
      if (is_executable($candidate)) {
        return $candidate;
      }
    }
    return NULL;
  }

  /**
   * Turn $checkout into a git repo and commit the listed paths.
   *
   * @param string $checkout
   *   Scratch checkout.
   * @param string[] $paths
   *   Paths relative to $checkout.
   */
  private function initGitCheckout(string $checkout, array $paths): void {
    $git = $this->gitExecutable();
    $this->assertNotNull($git, 'git must be on PATH for checkout fixtures.');
    $this->runGit($checkout, ['init']);
    $this->runGit($checkout, ['config', 'user.name', 'compat-test']);
    $this->runGit($checkout, ['config', 'user.email', 'compat-test@example.com']);
    $this->runGit($checkout, ['config', 'commit.gpgsign', 'false']);
    $this->runGit($checkout, array_merge(['add', '--'], $paths));
    $this->runGit($checkout, ['commit', '-m', 'fixture']);
  }

  /**
   * Run git in $root and fail the test if it exits non-zero.
   *
   * @param string $root
   *   Working tree.
   * @param string[] $args
   *   Arguments after git -C $root.
   */
  private function runGit(string $root, array $args): void {
    $git = $this->gitExecutable();
    $this->assertNotNull($git, 'git must be on PATH for checkout fixtures.');
    $result = $this->runGitCommand($git, $root, $args);
    $this->assertNotNull($result, 'git could not be started.');
    $this->assertSame(0, $result['status'], $result['stderr']);
  }

  /**
   * Invoke git -C $root without a shell.
   *
   * Every GIT_* variable is stripped so an inherited GIT_DIR
   * cannot retarget the repo. The safe.directory setting is
   * $root so ls-files still answers when the process user is
   * not the directory owner. d.o phpunit is www-data;
   * gitlab_templates runs chown on the checkout first, so
   * owner matches there. This keeps the same answer if that
   * chown is skipped or a helper clone stays root-owned.
   * Stderr is a file so a full stdout pipe cannot deadlock
   * against an unread stderr pipe.
   *
   * @param string $git
   *   Absolute git executable.
   * @param string $root
   *   Working tree.
   * @param string[] $args
   *   Arguments after git -C $root.
   *
   * @return array{status: int, stdout: string, stderr: string}|null
   *   Captured streams, or NULL if the process could not start.
   */
  private function runGitCommand(string $git, string $root, array $args): ?array {
    $stderr_file = tempnam(sys_get_temp_dir(), 'mcp-git-err-');
    if ($stderr_file === FALSE) {
      return NULL;
    }
    $cmd = array_merge(
      [$git, '-C', $root, '-c', 'safe.directory=' . $root],
      $args,
    );
    $pipes = [];
    $proc = proc_open(
      $cmd,
      [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['file', $stderr_file, 'w'],
      ],
      $pipes,
      $root,
      $this->environmentWithoutGitVariables(),
    );
    if (!is_resource($proc)) {
      unlink($stderr_file);
      return NULL;
    }
    fclose($pipes[0]);
    $stdout = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $status = proc_close($proc);
    $stderr = (string) file_get_contents($stderr_file);
    unlink($stderr_file);
    return [
      'status' => $status,
      'stdout' => $stdout,
      'stderr' => $stderr,
    ];
  }

  /**
   * Process environment with every GIT_* variable removed.
   *
   * @return array<string, string>
   *   Environment for proc_open.
   */
  private function environmentWithoutGitVariables(): array {
    $env = getenv();
    foreach (array_keys($env) as $key) {
      if (str_starts_with((string) $key, 'GIT_')) {
        unset($env[$key]);
      }
    }
    return $env;
  }

  /**
   * POSIX shim prefix that strips git -C/-c and leaves $root and $cmd.
   *
   * The helper invokes git as `git -C $root -c safe.directory=$root
   * <args>`. The fake binary has to ignore those flags.
   *
   * @return string
   *   Shell fragment.
   */
  private function fakeGitArgParser(): string {
    return <<<'SH'
root=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -C) shift; root=$1; shift ;;
    -c) shift; shift ;;
    *) break ;;
  esac
done
cmd="${1:-}"
shift || true

SH;
  }

  /**
   * Run $callback with a fake git first on PATH.
   *
   * @param string $script
   *   Body of the git shim after the shebang.
   * @param callable $callback
   *   Test body.
   */
  private function withFakeGit(string $script, callable $callback): void {
    $bin = $this->scratchDir() . '/bin';
    mkdir($bin, 0777, TRUE);
    $git = $bin . '/git';
    file_put_contents($git, "#!/bin/sh\n" . $script);
    chmod($git, 0755);
    $previous_path = getenv('PATH');
    $prefix = $bin;
    if (is_string($previous_path) && $previous_path !== '') {
      $prefix .= PATH_SEPARATOR . $previous_path;
    }
    putenv('PATH=' . $prefix);
    try {
      $this->assertSame($git, $this->gitExecutable());
      $callback();
    }
    finally {
      $this->restoreEnvironmentVariable('PATH', $previous_path);
    }
  }

  /**
   * Restore one environment variable after a putenv test.
   *
   * @param string $name
   *   Variable name.
   * @param string|false $previous
   *   Prior value, or FALSE when it was unset.
   */
  private function restoreEnvironmentVariable(string $name, string|false $previous): void {
    if (is_string($previous)) {
      putenv($name . '=' . $previous);
      return;
    }
    putenv($name);
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
   * Prefer the custom mount. A contrib copy is the GitHub path-repo
   * layout. Both at once is a mixed layout, not either venue.
   *
   * @param string $checkout
   *   Git checkout.
   *
   * @return string|null
   *   Absolute mount path, or NULL when this checkout is module-only.
   */
  private function projectMount(string $checkout): ?string {
    $custom = $checkout . '/web/modules/custom/mcp_sentinel';
    $contrib = $checkout . '/web/modules/contrib/mcp_sentinel';
    $has_custom = is_file($custom . '/mcp_sentinel.info.yml');
    $has_contrib = is_file($contrib . '/mcp_sentinel.info.yml');
    if ($has_custom && $has_contrib) {
      throw new \RuntimeException(
        'Both the gitlab_templates custom mount and a contrib copy of this module exist. The custom mount must be the only copy.',
      );
    }
    if ($has_custom) {
      return $custom;
    }
    if ($has_contrib) {
      return $contrib;
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
   * A throwaway directory this test removes in tearDown.
   *
   * @return string
   *   Absolute path.
   */
  private function scratchDir(): string {
    $dir = sys_get_temp_dir() . '/mcp-sentinel-compat-' . uniqid('', TRUE);
    mkdir($dir, 0777, TRUE);
    $this->scratchDirectories[] = $dir;
    return $dir;
  }

  /**
   * Built Drupal web/ with a resolving mount and a planted core miss.
   *
   * @return string
   *   Scratch checkout. web/ is on disk; git is not initialized.
   */
  private function plantBuiltWebWithBadCoreInfo(): string {
    $checkout = $this->scratchDir();
    file_put_contents(
      $checkout . '/mcp_sentinel.info.yml',
      "name: 'MCP Sentinel'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    $this->plantCustomMount($checkout);
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");
    file_put_contents(
      $checkout . '/web/core/bad.info.yml',
      "name: planted\ncore_version_requirement: '^11.3 || ^12'\n",
    );
    return $checkout;
  }

  /**
   * Point web/modules/custom/mcp_sentinel at this checkout.
   *
   * @param string $checkout
   *   Git checkout.
   */
  private function plantCustomMount(string $checkout): void {
    $mount = $checkout . '/web/modules/custom/mcp_sentinel';
    mkdir($mount, 0777, TRUE);
    $info = $checkout . '/mcp_sentinel.info.yml';
    $link = $mount . '/mcp_sentinel.info.yml';
    if (is_file($info) && !file_exists($link)) {
      symlink($info, $link);
    }
  }

  /**
   * Delete one scratch directory created by scratchDir().
   *
   * File and directory symlinks are unlinked, not followed, so a
   * mount that pointed outside the scratch tree cannot delete the
   * checkout. Runs from tearDown, including when a test failed.
   *
   * @param string $path
   *   Absolute path.
   */
  private function removeScratchDirectory(string $path): void {
    if (is_link($path) || is_file($path)) {
      unlink($path);
      return;
    }
    if (!is_dir($path)) {
      return;
    }
    $items = new \FilesystemIterator($path);
    foreach ($items as $item) {
      $this->removeScratchDirectory($item->getPathname());
    }
    rmdir($path);
  }

}
