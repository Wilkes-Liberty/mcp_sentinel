<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Caller-facing src denies must go through refuse() (DEV-966).
 *
 * Lives in Kernel so a failing scan cannot skip the rest of the Kernel
 * suite (Unit runs first under set -euo pipefail).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpCallerDenySourceGuardTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system'];

  /**
   * AccessResult::forbidden and policy-deny tool failures use refuse().
   */
  public function testSrcCallerFacingDeniesGoThroughRefuse(): void {
    $moduleRoot = dirname(__DIR__, 3);
    $roots = [$moduleRoot . '/src'];
    foreach (glob($moduleRoot . '/modules/*/src') ?: [] as $dir) {
      $roots[] = $dir;
    }
    $leaks = [];
    foreach ($roots as $root) {
      $this->assertDirectoryExists($root);
      $files = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
      );
      foreach ($files as $file) {
        if (!$file->isFile() || $file->getExtension() !== 'php') {
          continue;
        }
        $code = (string) file_get_contents($file->getPathname());
        $rel = substr($file->getPathname(), strlen($moduleRoot) + 1);
        $leaks = array_merge($leaks, $this->forbiddenLeaks($rel, $code));
        $leaks = array_merge($leaks, $this->failureLeaks($rel, $code));
      }
    }
    $this->assertSame(
      [],
      $leaks,
      "Caller-facing deny literals must go through refuse() or CALLER_MESSAGE:\n" . implode("\n", $leaks),
    );
  }

  /**
   * AccessResult::forbidden() arguments that are not the generic helper.
   *
   * @param string $rel
   *   Path relative to src/.
   * @param string $code
   *   File contents.
   *
   * @return array
   *   Leak descriptions.
   */
  private function forbiddenLeaks(string $rel, string $code): array {
    $leaks = [];
    if (!preg_match_all('/AccessResult::forbidden\s*\((.*?)\)/s', $code, $matches, PREG_OFFSET_CAPTURE)) {
      return $leaks;
    }
    foreach ($matches[1] as $match) {
      $arg = $match[0];
      if (str_contains($arg, 'CALLER_MESSAGE') || str_contains($arg, 'refuse(')) {
        continue;
      }
      $leaks[] = $rel . ':' . $this->lineAt($code, $match[1]) . ' AccessResult::forbidden(' . $this->oneLine($arg) . ')';
    }
    return $leaks;
  }

  /**
   * Tool failure literals that still name a Sentinel rule.
   *
   * @param string $rel
   *   Path relative to src/.
   * @param string $code
   *   File contents.
   *
   * @return array
   *   Leak descriptions.
   */
  private function failureLeaks(string $rel, string $code): array {
    $leaks = [];
    if (!preg_match_all('/ExecutableResult::failure\(\s*\$this->t\(\s*\'([^\']*)\'/', $code, $matches, PREG_OFFSET_CAPTURE)) {
      return $leaks;
    }
    foreach ($matches[1] as $match) {
      $literal = $match[0];
      $start = max(0, $match[1] - 600);
      $window = substr($code, $start, 1200);
      if ($literal === '@msg') {
        if (!str_contains($window, 'refuse(')
          && !str_contains($window, 'CALLER_MESSAGE')) {
          $leaks[] = $rel . ':' . $this->lineAt($code, $match[1])
            . ' failure t(\'@msg\') is not bound to refuse() or CALLER_MESSAGE';
        }
        continue;
      }
      if ($literal === 'MCP access is denied.') {
        continue;
      }
      if (!preg_match('/MCP Sentinel refused|holds secrets|response size cap/', $literal)) {
        continue;
      }
      $leaks[] = $rel . ':' . $this->lineAt($code, $match[1]) . ' failure t(\'' . $literal . '\')';
    }
    return $leaks;
  }

  /**
   * Returns the 1-based line number for a byte offset.
   *
   * @param string $code
   *   File contents.
   * @param int $offset
   *   Byte offset of the match.
   *
   * @return int
   *   Line number starting at 1.
   */
  private function lineAt(string $code, int $offset): int {
    return substr_count(substr($code, 0, $offset), "\n") + 1;
  }

  /**
   * Collapses an argument snippet to one line.
   *
   * @param string $arg
   *   Raw argument text from the source.
   *
   * @return string
   *   Whitespace-collapsed argument.
   */
  private function oneLine(string $arg): string {
    return trim(preg_replace('/\s+/', ' ', $arg) ?? $arg);
  }

}
