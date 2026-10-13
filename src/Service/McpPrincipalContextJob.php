<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Resets the sealed principal at CLI, queue, and Drush job boundaries.
 *
 * @internal Not a public API. Queue workers call begin()/end() per
 *   item. Drush commands call them per invocation. Site code must
 *   not reset a sealed HTTP principal through the holder.
 */
final class McpPrincipalContextJob {

  /**
   * Constructs the job boundary helper.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   The write-once sealed context.
   */
  public function __construct(
    private readonly McpPrincipalContextHolder $holder,
  ) {}

  /**
   * Clears any previous job seal so this item can seal its own principal.
   */
  public function begin(): void {
    $this->holder->resetForJob();
  }

  /**
   * Clears this item's seal so the next item cannot reuse it.
   */
  public function end(): void {
    $this->holder->resetForJob();
  }

  /**
   * Runs one queue/Drush item inside a begin/end pair.
   *
   * @param callable(): mixed $item
   *   The item body.
   *
   * @return mixed
   *   Whatever the item returns.
   */
  public function run(callable $item): mixed {
    $this->begin();
    try {
      return $item();
    }
    finally {
      $this->end();
    }
  }

}
