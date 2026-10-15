<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Event;

use Drupal\mcp_sentinel\Value\McpKillSelector;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Fired when a two-person confirm window elapses with no second operator.
 *
 * @todo DEV-846 operator decision: the unavailable-confirmer rule is
 *   not decided. This event (and hook_mcp_sentinel_kill_unavailable_confirmer)
 *   is the operator-decision hook. There is no fallback that weakens the
 *   two-person rule: a pending mass kill is not applied, and a pending
 *   un-kill is not granted, when the named second person (secondary
 *   account holder) does not confirm in time.
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
   */
  public function __construct(
    public readonly string $batchId,
    public readonly string $transition,
    public readonly string $firstOperatorId,
    public readonly McpKillSelector $selector,
  ) {}

}
