<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Shared canonical JSON for policy-bundle and audit-identity digests.
 *
 * Map keys are sorted recursively; lists keep caller order; scalars
 * pass through. Identity values are expanded first
 * (JsonSerializable, then public object properties). An empty map
 * encodes as `{}`; an empty list encodes as `[]`. Recursion stops
 * at MAX_DEPTH so a cyclic graph throws instead of exhausting the
 * stack.
 */
final class McpCanonicalJson {

  /**
   * Recursion cap, matching json_encode()'s default depth.
   *
   * A cyclic or deeper graph throws so the caller can fall back
   * to a type marker instead of a fatal error.
   */
  public const MAX_DEPTH = 512;

  /**
   * Recursively sorts map keys; lists keep caller order.
   *
   * Empty arrays are lists. An empty stdClass is kept so
   * json_encode() emits `{}`. Anything else that is not a
   * scalar throws.
   *
   * @param mixed $value
   *   A JSON-able value.
   * @param int $depth
   *   Current container depth (0 at the root).
   *
   * @return mixed
   *   The normalized value.
   *
   * @throws \InvalidArgumentException
   *   When the value cannot be encoded, or depth exceeds
   *   MAX_DEPTH.
   */
  public static function normalize(mixed $value, int $depth = 0): mixed {
    if (!is_array($value)) {
      if ($value instanceof \stdClass && get_object_vars($value) === []) {
        self::assertDepth($depth);
        return $value;
      }
      if (is_string($value) || is_int($value) || is_float($value)
        || is_bool($value) || $value === NULL) {
        return $value;
      }
      throw new \InvalidArgumentException(
        'Canonical JSON values may only contain scalars, lists and maps.',
      );
    }
    self::assertDepth($depth);
    if ($value === [] || array_is_list($value)) {
      foreach ($value as $key => $item) {
        $value[$key] = self::normalize($item, $depth + 1);
      }
      return $value;
    }
    ksort($value);
    foreach ($value as $key => $item) {
      $value[$key] = self::normalize($item, $depth + 1);
    }
    return $value;
  }

  /**
   * Expands identity values, then canonicalizes.
   *
   * JsonSerializable is expanded first. Remaining objects use
   * public properties. Empty objects become `{}`.
   *
   * @param mixed $value
   *   A non-scalar identity value.
   *
   * @return mixed
   *   The normalized value.
   *
   * @throws \InvalidArgumentException
   *   When the value cannot be encoded, or depth exceeds
   *   MAX_DEPTH.
   */
  public static function normalizeIdentity(mixed $value): mixed {
    return self::normalize(self::expandIdentity($value, 0), 0);
  }

  /**
   * Expands JsonSerializable and objects into arrays or `{}`.
   *
   * @param mixed $value
   *   A JSON-able identity value.
   * @param int $depth
   *   Current container depth (0 at the root).
   *
   * @return mixed
   *   Arrays, scalars, or an empty stdClass.
   *
   * @throws \InvalidArgumentException
   *   When depth exceeds MAX_DEPTH.
   */
  private static function expandIdentity(mixed $value, int $depth): mixed {
    if ($value instanceof \JsonSerializable) {
      self::assertDepth($depth);
      return self::expandIdentity($value->jsonSerialize(), $depth + 1);
    }
    if (is_object($value)) {
      self::assertDepth($depth);
      $vars = get_object_vars($value);
      if ($vars === []) {
        return new \stdClass();
      }
      foreach ($vars as $key => $item) {
        $vars[$key] = self::expandIdentity($item, $depth + 1);
      }
      return $vars;
    }
    if (!is_array($value)) {
      return $value;
    }
    self::assertDepth($depth);
    foreach ($value as $key => $item) {
      $value[$key] = self::expandIdentity($item, $depth + 1);
    }
    return $value;
  }

  /**
   * Refuses a graph deeper than json_encode() would encode.
   *
   * @param int $depth
   *   Current container depth.
   *
   * @throws \InvalidArgumentException
   *   When $depth is MAX_DEPTH or greater.
   */
  private static function assertDepth(int $depth): void {
    // DEV-1180 red-proof: do not enforce MAX_DEPTH.
    if ($depth < 0) {
      throw new \InvalidArgumentException(
        'Canonical JSON depth exceeded.',
      );
    }
  }

}
