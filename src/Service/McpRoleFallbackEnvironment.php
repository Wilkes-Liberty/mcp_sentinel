<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Process facts the role-fallback gate must not read from the request.
 *
 * PHPUnit injects a probe so permitted() can be tested as a
 * production process without the live PHPUnit constants.
 */
final class McpRoleFallbackEnvironment {

  /**
   * Constructs the probe.
   *
   * @param bool $inPhpUnit
   *   TRUE when this process is PHPUnit.
   */
  public function __construct(
    private readonly bool $inPhpUnit,
  ) {}

  /**
   * Reads the live process.
   */
  public static function detect(): self {
    return new self(
      defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_PHAR__'),
    );
  }

  /**
   * TRUE when this process is PHPUnit.
   */
  public function inPhpUnit(): bool {
    return $this->inPhpUnit;
  }

}
