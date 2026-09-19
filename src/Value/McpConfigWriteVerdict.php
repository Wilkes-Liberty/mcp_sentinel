<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * The outcome of validating a proposed governed config write.
 *
 * Carries property paths and a fixed reason code. It never carries a submitted
 * value or a validator's message, because either can repeat what the caller
 * sent.
 */
final class McpConfigWriteVerdict {

  /**
   * The config name has no schema and the profile does not allow that.
   */
  public const SCHEMA_MISSING = 'schema_missing';

  /**
   * Typed-config validation reported at least one violation.
   */
  public const SCHEMA_VIOLATION = 'schema_violation';

  /**
   * A config import validator refused the resulting object.
   */
  public const IMPORT_VALIDATION = 'import_validation';

  /**
   * The keys could not be merged into a config object.
   */
  public const INVALID_STRUCTURE = 'invalid_structure';

  /**
   * Validation itself failed to run. Refused, because it proved nothing.
   */
  public const VALIDATION_ERROR = 'validation_error';

  /**
   * Constructs a verdict.
   *
   * @param bool $valid
   *   TRUE when the write may proceed.
   * @param string|null $reason
   *   One of the class constants, or NULL when valid.
   * @param string[] $paths
   *   The property paths that failed typed-config validation.
   * @param int $importErrors
   *   How many errors config import validators reported.
   * @param bool $schemaless
   *   TRUE when the name has no schema and the write was admitted anyway.
   */
  private function __construct(
    public readonly bool $valid,
    public readonly ?string $reason,
    public readonly array $paths,
    public readonly int $importErrors,
    public readonly bool $schemaless,
  ) {}

  /**
   * The write may proceed.
   */
  public static function valid(bool $schemaless = FALSE): self {
    return new self(TRUE, NULL, [], 0, $schemaless);
  }

  /**
   * The write is refused.
   *
   * @param string $reason
   *   One of the class constants.
   * @param string[] $paths
   *   The failing property paths.
   * @param int $importErrors
   *   How many errors config import validators reported.
   */
  public static function refused(string $reason, array $paths = [], int $importErrors = 0): self {
    return new self(FALSE, $reason, array_values($paths), $importErrors, FALSE);
  }

  /**
   * A value-free sentence for a result message, a log line or an audit row.
   */
  public function summary(): string {
    return match ($this->reason) {
      NULL => 'valid',
      self::SCHEMA_MISSING => 'the configuration name has no schema, so the write cannot be validated',
      self::SCHEMA_VIOLATION => 'schema validation failed at: ' . implode(', ', $this->paths),
      self::IMPORT_VALIDATION => sprintf('%d config import validator error(s)', $this->importErrors),
      self::INVALID_STRUCTURE => 'the keys could not be applied to a configuration object',
      default => 'validation could not be completed',
    };
  }

}
