<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

/**
 * Live webhook event names. Unknown names are never saved or dispatched.
 *
 * Only these three names are ever queued (entity presave, entity delete,
 * anomaly alert). The settings form and both enqueue paths read this
 * list so a typo cannot persist as a filter or leave the process.
 */
final class McpWebhookEvents {

  /**
   * Entity write, before the commit. Nothing dispatches mcp.entity.save.
   */
  public const ENTITY_PRESAVE = 'mcp.entity.presave';

  /**
   * Entity delete, after the commit.
   */
  public const ENTITY_DELETE = 'mcp.entity.delete';

  /**
   * Anomaly alert from McpAlertDispatcher.
   */
  public const ANOMALY_ALERT = 'mcp.anomaly.alert';

  /**
   * Retired filter name. Historical tests stored this; nothing queues it.
   *
   * Shown as stored. Saving it is a validation error that names the
   * live replacement. Do not rewrite it on save: that would start
   * outbound delivery nobody chose.
   */
  public const RETIRED_ENTITY_SAVE = 'mcp.entity.save';

  /**
   * The only event names that may be stored on a filter or enqueued.
   *
   * Empty filter still means "all of these", not an open string. An
   * empty list would refuse every name (fail closed).
   *
   * @var list<string>
   */
  public const LIVE = [
    self::ENTITY_PRESAVE,
    self::ENTITY_DELETE,
    self::ANOMALY_ALERT,
  ];

  /**
   * Whether $name is one of the three live events.
   *
   * Comparison is strict. Case variants and the retired save name
   * are not live.
   *
   * @param string $name
   *   Candidate event name.
   *
   * @return bool
   *   TRUE only when $name is in LIVE.
   */
  public static function isLive(string $name): bool {
    return in_array($name, self::LIVE, TRUE);
  }

}
