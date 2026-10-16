<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Process facts the role-fallback gate must not read from the request.
 *
 * PHPUnit injects a probe so permitted() can be tested as a production
 * SAPI or as cli-server without the live PHPUnit constants.
 */
final class McpRoleFallbackEnvironment {

  /**
   * Constructs the probe.
   *
   * @param string $sapi
   *   PHP_SAPI of the process under test.
   * @param bool $inPhpUnit
   *   TRUE when this process is PHPUnit.
   * @param bool $inDrupalTestChildSite
   *   TRUE when this process is a Drupal functional-test child.
   */
  public function __construct(
    private readonly string $sapi,
    private readonly bool $inPhpUnit,
    private readonly bool $inDrupalTestChildSite,
  ) {}

  /**
   * Reads the live process.
   */
  public static function detect(): self {
    return new self(
      PHP_SAPI,
      defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_PHAR__'),
      self::liveDrupalTestChildSite(),
    );
  }

  /**
   * TRUE when this process is a Drupal functional-test child.
   *
   * Read through get_defined_constants() so a PHPStan stub that
   * defines the constant as FALSE cannot collapse the runtime check.
   */
  public static function liveDrupalTestChildSite(): bool {
    $constants = get_defined_constants(FALSE);
    return isset($constants['DRUPAL_TEST_IN_CHILD_SITE'])
      && $constants['DRUPAL_TEST_IN_CHILD_SITE'] === TRUE;
  }

  /**
   * PHP_SAPI of this process.
   */
  public function sapi(): string {
    return $this->sapi;
  }

  /**
   * TRUE when this process is PHPUnit.
   */
  public function inPhpUnit(): bool {
    return $this->inPhpUnit;
  }

  /**
   * TRUE when this process is a Drupal functional-test child.
   */
  public function inDrupalTestChildSite(): bool {
    return $this->inDrupalTestChildSite;
  }

}
