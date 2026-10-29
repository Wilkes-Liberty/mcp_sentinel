<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

/**
 * Live webhook event names. Unknown names are never saved or dispatched.
 *
 * Only these three names are ever queued (entity presave, entity delete,
 * anomaly alert). The settings form, dispatch, enqueue, worker, requeue,
 * and replay read this list so a typo cannot persist as a filter or
 * leave the process.
 *
 * Kept as a final class rather than a backed enum in src/Enum/: that
 * directory holds closed variant sets, and this allowlist still needs
 * a retired historical name plus overlapping LIVE and ENTITY lists.
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
   * Longest event name stored in audit or shown to the operator.
   *
   * Matches the delivery-row event_name column. Count is characters
   * after invalid UTF-8 is scrubbed, not raw bytes.
   */
  public const NAME_MAX = 128;

  /**
   * Longest endpoint id stored on a webhook_event_refused audit row.
   *
   * Count is characters after invalid UTF-8 is scrubbed, not raw
   * bytes. Matches the settings-form machine-id maxlength.
   */
  public const ENDPOINT_ID_MAX = 64;

  /**
   * Event names that carry an EntityInterface (dispatch() only).
   *
   * An empty list refuses every name (fail closed). LIVE is this list
   * plus the anomaly alert.
   *
   * @var list<string>
   */
  public const ENTITY = [
    self::ENTITY_PRESAVE,
    self::ENTITY_DELETE,
  ];

  /**
   * The only event names that may be stored on a filter or enqueued.
   *
   * Empty filter still means "all of these", not an open string. An
   * empty list would refuse every name (fail closed).
   *
   * @var list<string>
   */
  public const LIVE = [
    ...self::ENTITY,
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

  /**
   * Whether $name is an entity event that dispatch() may fire.
   *
   * The mcp.anomaly.alert name is live and may be enqueued, but it is not an
   * entity event. dispatch() takes an EntityInterface and must not
   * fire an entity-shaped event under the alert name.
   *
   * @param string $name
   *   Candidate event name.
   *
   * @return bool
   *   TRUE only when $name is in ENTITY.
   */
  public static function isEntityEvent(string $name): bool {
    return in_array($name, self::ENTITY, TRUE);
  }

  /**
   * Cuts $text to $max characters of valid UTF-8.
   *
   * Invalid sequences are scrubbed first so a mid-codepoint cut
   * cannot land in audit metadata or an operator message.
   *
   * @param string $text
   *   Raw text.
   * @param int $max
   *   Maximum character count.
   *
   * @return string
   *   Valid UTF-8, at most $max characters.
   */
  public static function boundText(string $text, int $max): string {
    return mb_substr(mb_scrub($text, 'UTF-8'), 0, $max, 'UTF-8');
  }

  /**
   * Cuts $name to NAME_MAX characters of valid UTF-8.
   *
   * @param string $name
   *   Candidate event name.
   *
   * @return string
   *   Valid UTF-8, at most NAME_MAX characters.
   */
  public static function boundName(string $name): string {
    return self::boundText($name, self::NAME_MAX);
  }

}
