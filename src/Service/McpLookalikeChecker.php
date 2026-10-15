<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;

/**
 * Process-wide reserved-key folds and Spoofchecker (UTS #39).
 *
 * Built once per process. Governed calls fail closed when
 * Spoofchecker is missing (deny + audit lookalike_check_unavailable).
 * Tests inject unavailability via disableForTest().
 */
final class McpLookalikeChecker {

  /**
   * Process-wide reserved folds (immutable after first build).
   *
   * @var array<string, true>|null
   */
  private static ?array $reservedFolds = NULL;

  /**
   * Process-wide Spoofchecker, or NULL until first non-ASCII key.
   */
  private static ?\Spoofchecker $checker = NULL;

  /**
   * Test-only: treat Spoofchecker as missing.
   */
  private static bool $forcedUnavailable = FALSE;

  /**
   * Refuses when look-alike detection cannot run.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When Spoofchecker is missing or disabled for a test.
   */
  public static function assertAvailable(): void {
    if (self::$forcedUnavailable || !class_exists(\Spoofchecker::class)) {
      throw new McpPrincipalContextDeniedException(
        McpPrincipalContextDeniedException::LOOKALIKE_CHECK_UNAVAILABLE,
        'Reserved-key look-alike detection requires ext-intl Spoofchecker.',
      );
    }
  }

  /**
   * Normalized reserved-key folds, built once.
   *
   * @return array<string, true>
   *   Folded reserved names.
   */
  public static function reservedFolds(): array {
    if (self::$reservedFolds === NULL) {
      $folds = [];
      foreach (McpPrincipalContext::RESERVED_IDENTITY_KEYS as $reserved) {
        $folds[McpPrincipalContext::foldKey($reserved)] = TRUE;
      }
      self::$reservedFolds = $folds;
    }
    return self::$reservedFolds;
  }

  /**
   * The process-wide Spoofchecker.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When Spoofchecker is unavailable.
   */
  public static function checker(): \Spoofchecker {
    self::assertAvailable();
    if (self::$checker === NULL) {
      self::$checker = new \Spoofchecker();
    }
    return self::$checker;
  }

  /**
   * Test-only: fail closed as if Spoofchecker were missing.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function disableForTest(): void {
    self::assertPhpUnit();
    self::$forcedUnavailable = TRUE;
  }

  /**
   * Test-only: restore process-wide availability.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function resetForTest(): void {
    self::assertPhpUnit();
    self::$forcedUnavailable = FALSE;
    self::$checker = NULL;
  }

  /**
   * Restricts test hooks to PHPUnit.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  private static function assertPhpUnit(): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Lookalike checker can be injected only under PHPUnit.',
      );
    }
  }

}
