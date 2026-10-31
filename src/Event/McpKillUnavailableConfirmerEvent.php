<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Event;

use Drupal\mcp_sentinel\Value\McpKillSelector;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Fired when a two-person confirm window elapses with no second operator.
 *
 * An unconfirmed mass freeze stays frozen and escalates
 * through this event and hook_mcp_sentinel_kill_unavailable_confirmer.
 * There is no fallback that lifts the freeze or grants a pending
 * un-kill. The hook receives every target; stopped agents are not
 * notified. A distinct verified operator can still keep, extend, or
 * lift the freeze.
 */
final class McpKillUnavailableConfirmerEvent extends Event {

  /**
   * Event name.
   */
  public const NAME = 'mcp_sentinel.kill_unavailable_confirmer';

  /**
   * Constructs the event.
   *
   * @param string $batchId
   *   Batch that expired.
   * @param string $transition
   *   Kill or unkill.
   * @param string $firstOperatorId
   *   Account id of the operator who opened the request. Never a
   *   username.
   * @param \Drupal\mcp_sentinel\Value\McpKillSelector $selector
   *   One selector from the expired batch.
   * @param list<string> $targets
   *   Every selector in the batch as type:key.
   */
  public function __construct(
    public readonly string $batchId,
    public readonly string $transition,
    public readonly string $firstOperatorId,
    public readonly McpKillSelector $selector,
    public readonly array $targets = [],
  ) {}

}
