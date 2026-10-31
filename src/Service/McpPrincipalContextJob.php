<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Value\McpCarriedPrincipal;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Opens a deny-only overlay at CLI, queue, and Drush job boundaries.
 *
 * @internal Not a public API. Queue workers call begin()/release() or
 *   run() per item. Drush and console callers call begin()/end() per
 *   invocation and must pass the handle begin() returned. run() cannot
 *   cover PRE/POST hooks: those bookend a command they do not wrap.
 *   begin() pushes a deny-only overlay over a request-sealed state
 *   (web cron) and never mutates that seal. Governed tools refuse
 *   while the overlay is open. Site code must not reset a sealed HTTP
 *   principal through the holder.
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
   * @param \Psr\Log\LoggerInterface $logger
   *   Logs leftover overlays when release() unwinds.
   */
  public function __construct(
    private readonly McpPrincipalContextHolder $holder,
    private readonly LoggerInterface $logger = new NullLogger(),
  ) {}

  /**
   * Opens a deny-only overlay that hides the request seal.
   *
   * A request-sealed HTTP principal (web cron) is not mutated.
   * Governed tools refuse until a hop token is available.
   *
   * @return \Drupal\mcp_sentinel\Service\McpJobScopeHandle
   *   Token that end() / leaveJobScope() / release() must present.
   */
  public function begin(): McpJobScopeHandle {
    $handle = $this->holder->enterJobScope();
    $this->handles[] = $handle;
    return $handle;
  }

  /**
   * Opens a deny-only overlay that carries keys for kill checks.
   *
   * Identity is still not inherited. A killed carried principal is
   * refused at admit() with the same generic deny as an invalid
   * principal.
   *
   * @param string $principalKey
   *   Principal key (iss|sub|actor) from the queued work.
   * @param string $humanKey
   *   Person key (iss|sub), or empty.
   * @param string $tenant
   *   Tenant claim, or empty.
   *
   * @return \Drupal\mcp_sentinel\Service\McpJobScopeHandle
   *   Token that end() / release() must present.
   */
  public function beginCarrying(string $principalKey, string $humanKey = '', string $tenant = ''): McpJobScopeHandle {
    $handle = $this->begin();
    $this->holder->carryPrincipal(
      $handle,
      new McpCarriedPrincipal($principalKey, $humanKey, $tenant),
    );
    return $handle;
  }

  /**
   * Drops the matching job overlay and restores any request seal.
   *
   * @param \Drupal\mcp_sentinel\Service\McpJobScopeHandle $handle
   *   The token returned by the matching begin().
   *
   * @throws \LogicException
   *   When $handle is not the innermost begin() still open.
   */
  public function end(McpJobScopeHandle $handle): void {
    $top = $this->handles === []
      ? NULL
      : $this->handles[array_key_last($this->handles)];
    if ($top !== $handle) {
      throw new \LogicException(
        'end() requires the handle returned by the matching begin().',
      );
    }
    array_pop($this->handles);
    $this->holder->leaveJobScope($handle);
  }

  /**
   * Unwinds open overlays down to $handle and never throws.
   *
   * A queue item that leaves an inner scope open is closed here.
   * A missing handle (already left) is logged and ignored.
   *
   * @param \Drupal\mcp_sentinel\Service\McpJobScopeHandle $handle
   *   The handle this worker's begin() returned.
   *
   * @return int
   *   Overlays closed, including $handle when it was still open.
   */
  public function release(McpJobScopeHandle $handle): int {
    $closed = $this->holder->unwindTo($handle);
    $this->handles = array_values(array_filter(
      $this->handles,
      static fn (McpJobScopeHandle $open): bool => $open !== $handle,
    ));
    if ($closed !== 1) {
      $this->logger->error(
        'Job scope release closed @count overlay(s) for its own handle; the item left a scope open or already left it.',
        ['@count' => $closed],
      );
    }
    return $closed;
  }

  /**
   * Runs one queue/Drush item inside a begin/release pair.
   *
   * @param callable(): mixed $item
   *   The item body.
   *
   * @return mixed
   *   Whatever the item returns.
   */
  public function run(callable $item): mixed {
    $handle = $this->begin();
    try {
      return $item();
    }
    finally {
      $this->release($handle);
    }
  }

}
