<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Resets the sealed principal at CLI, queue, and Drush job boundaries.
 *
 * @internal Not a public API. Queue workers call begin()/end() per
 *   item. Drush commands call them per invocation. begin() pushes a
 *   nested job overlay over a request-sealed state (web cron) and
 *   never mutates that seal. Site code must not reset a sealed HTTP
 *   principal through the holder.
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
   * Opens a job overlay so this item can seal its own principal.
   *
   * A request-sealed HTTP principal (web cron) is not mutated.
   * Sequential begin() without end() clears only the overlay.
   * Refused from arbitrary HTTP code; queue workers and Drush
   * commands are the allowed callers.
   */
  public function begin(): void {
    $this->holder->enterJobScope();
  }

  /**
   * Drops the job overlay and restores any request seal.
   */
  public function end(): void {
    $this->holder->leaveJobScope();
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
