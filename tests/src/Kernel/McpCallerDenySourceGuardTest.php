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
   * Nested parentheses inside forbidden() are part of the scanned argument.
   */
  public function testForbiddenMatchHandlesNestedParentheses(): void {
    $leaky = <<<'PHP'
<?php
AccessResult::forbidden($this->t('Nope (@id)', ['@id' => $id]));
PHP;
    $leaks = $this->forbiddenLeaks('nested.php', $leaky);
    $this->assertNotSame([], $leaks, 'A nested-paren leak must be reported.');
    $this->assertStringContainsString(
      "['@id' => \$id]",
      $leaks[0],
      'The matcher must not stop at the first closing parenthesis.',
    );

    $ok = <<<'PHP'
<?php
AccessResult::forbidden($this->denyExplainer?->refuse('tenant_mismatch'));
PHP;
    $this->assertSame(
      [],
      $this->forbiddenLeaks('ok.php', $ok),
      'A nested refuse() argument is not a leak.',
    );
  }

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
    if (!preg_match_all('/AccessResult::forbidden\s*\(/', $code, $matches, PREG_OFFSET_CAPTURE)) {
      return $leaks;
    }
    foreach ($matches[0] as $match) {
      $open = $match[1] + strlen($match[0]) - 1;
      $arg = $this->argumentInsideParens($code, $open);
      if ($arg === NULL) {
        continue;
      }
      if (str_contains($arg, 'CALLER_MESSAGE') || str_contains($arg, 'refuse(')) {
        continue;
      }
      $leaks[] = $rel . ':' . $this->lineAt($code, $open + 1)
        . ' AccessResult::forbidden(' . $this->oneLine($arg) . ')';
    }
    return $leaks;
  }

  /**
   * Returns the argument text inside a '(' at $open, matching nested pairs.
   *
   * @param string $code
   *   File contents.
   * @param int $open
   *   Byte offset of the opening parenthesis.
   *
   * @return string|null
   *   Inner argument text, or NULL when the pair is unclosed.
   */
  private function argumentInsideParens(string $code, int $open): ?string {
    $depth = 0;
    $length = strlen($code);
    $inString = FALSE;
    $quote = '';
    $escape = FALSE;
    for ($i = $open; $i < $length; $i++) {
      $ch = $code[$i];
      if ($inString) {
        if ($escape) {
          $escape = FALSE;
          continue;
        }
        if ($ch === '\\') {
          $escape = TRUE;
          continue;
        }
        if ($ch === $quote) {
          $inString = FALSE;
        }
        continue;
      }
      if ($ch === "'" || $ch === '"') {
        $inString = TRUE;
        $quote = $ch;
        continue;
      }
      if ($ch === '(') {
        $depth++;
        continue;
      }
      if ($ch === ')') {
        $depth--;
        if ($depth === 0) {
          return substr($code, $open + 1, $i - $open - 1);
        }
      }
    }
    return NULL;
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
