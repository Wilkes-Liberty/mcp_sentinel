<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Support;

use Drupal\Component\Datetime\TimeInterface;

/**
 * A time service whose request time and current time are set by the test.
 *
 * The two are independent, so a test can tell which one the code reads.
 */
final class McpSettableClock implements TimeInterface {

  /**
   * The value returned by getRequestTime().
   */
  public int $request;

  /**
   * The value returned by getCurrentTime().
   */
  public int $current;

  /**
   * Constructs a clock with both times set to the same instant.
   *
   * @param int $now
   *   Unix seconds.
   */
  public function __construct(int $now) {
    $this->request = $now;
    $this->current = $now;
  }

  /**
   * Moves both the request time and the current time to one instant.
   *
   * @param int $now
   *   Unix seconds.
   */
  public function setNow(int $now): void {
    $this->request = $now;
    $this->current = $now;
  }

  /**
   * {@inheritdoc}
   */
  public function getRequestTime() {
    return $this->request;
  }

  /**
   * {@inheritdoc}
   */
  public function getRequestMicroTime() {
    return (float) $this->request;
  }

  /**
   * {@inheritdoc}
   */
  public function getCurrentTime() {
    return $this->current;
  }

  /**
   * {@inheritdoc}
   */
  public function getCurrentMicroTime() {
    return (float) $this->current;
  }

}
