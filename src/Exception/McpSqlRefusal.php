<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Exception;

/**
 * Carries curated policy reasons for the local command adapter.
 */
final class McpSqlRefusal extends \RuntimeException {

  /**
   * Constructs a refusal without exposing SQL or driver errors to adapters.
   *
   * @param string[] $reasons
   *   Curated validation or policy reasons.
   */
  public function __construct(public readonly array $reasons) {
    parent::__construct('Governed SQL was refused.');
  }

}
