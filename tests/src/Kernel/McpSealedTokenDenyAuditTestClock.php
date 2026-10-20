<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Component\Datetime\TimeInterface;

/**
 * Mutable clock for sealed-token denial window tests.
 */
final class McpSealedTokenDenyAuditTestClock implements TimeInterface {

  /**
   * Unix timestamp returned by every TimeInterface method.
   *
   * @var int
   */
  public int $now;

  /**
   * Constructs the clock.
   *
   * @param int $now
   *   Unix timestamp.
   */
  public function __construct(int $now) {
    $this->now = $now;
  }

  /**
   * {@inheritdoc}
   */
  public function getRequestTime(): int {
    return $this->now;
  }

  /**
   * {@inheritdoc}
   */
  public function getCurrentTime(): int {
    return $this->now;
  }

  /**
   * {@inheritdoc}
   */
  public function getRequestMicroTime(): float {
    return (float) $this->now;
  }

  /**
   * {@inheritdoc}
   */
  public function getCurrentMicroTime(): float {
    return (float) $this->now;
  }

}
