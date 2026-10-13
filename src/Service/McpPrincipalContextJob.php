<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Resets the sealed principal at CLI, queue, and Drush job boundaries.
 *
 * @internal Not a public API. Queue workers call begin()/end() per
 *   item. Drush commands call them per invocation. begin() pushes a
 *   deny-only overlay over a request-sealed state (web cron) and
 *   never mutates that seal. Governed tools refuse while the overlay
 *   is open. Site code must not reset a sealed HTTP principal
 *   through the holder.
 */
final class McpPrincipalContextJob {

  /**
   * Handles for begin() calls that have not yet been ended.
   *
   * @var list<\Drupal\mcp_sentinel\Service\McpJobScopeHandle>
   */
  private array $handles = [];

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
   * Opens a deny-only overlay that hides the request seal.
   *
   * A request-sealed HTTP principal (web cron) is not mutated.
   * Governed tools refuse until a hop token is available.
   */
  public function begin(): void {
    $this->handles[] = $this->holder->enterJobScope();
  }

  /**
   * Drops the matching job overlay and restores any request seal.
   *
   * @throws \LogicException
   *   When end() has no matching begin().
   */
  public function end(): void {
    $handle = array_pop($this->handles);
    if ($handle === NULL) {
      throw new \LogicException(
        'end() requires a matching begin().',
      );
    }
    $this->holder->leaveJobScope($handle);
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
