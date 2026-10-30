<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Shared canonical JSON for policy-bundle and audit-identity digests.
 *
 * Map keys are sorted recursively; lists keep caller order; scalars
 * pass through. Policy claims stay arrays and scalars — an empty
 * stdClass is still rejected with the historical message. Identity
 * values expand JsonSerializable, then public object properties,
 * before the same sorter. get_object_vars() only sees public
 * properties; private and protected fields are omitted. Numeric
 * property names become integer array keys, so an object whose
 * public properties are "0", "1", "2", ... is canonicalized as a list
 * (caller order), not a map. An empty identity object encodes as
 * `{}`; an empty list encodes as `[]`. Recursion stops at MAX_DEPTH.
 * A visited-object set refuses a cycle. A node budget counts
 * every container and scalar so a wide list cannot hide
 * behind a small container count. A byte budget refuses
 * repeated large strings before copies or json_encode().
 * Those throws are catchable InvalidArgumentException so the
 * caller can fall back to a type marker.
 */
final class McpCanonicalJson {

  /**
   * Recursion cap, matching json_encode()'s default depth.
   *
   * A cyclic, over-budget, or deeper graph throws so the
   * caller can fall back to a type marker instead of a fatal.
   */
  public const MAX_DEPTH = 512;

  /**
   * Maximum values visited in one canonicalize walk.
   *
   * Containers and scalars both count. A chain of 22 objects
   * where each points to the next twice ($m->l = $m->r = $n)
   * is only depth 22, but expansion duplicates every level
   * and reaches ~2G without this cap. A wide list of scalars
   * (array_fill of array_fill) stays shallow and still trips
   * this budget.
   */
  public const MAX_NODES = 4096;

  /**
   * Maximum payload bytes counted in one canonicalize walk.
   *
   * String values and map keys add their strlen(). Other
   * scalars add one byte. Shared large strings are counted
   * on every visit so encoding cannot blow memory while
   * staying under MAX_NODES.
   */
  public const MAX_BYTES = 65536;

  /**
   * Recursively sorts map keys; lists keep caller order.
   *
   * Policy claims: arrays and scalars only. Empty arrays are
   * lists. An empty stdClass is rejected with the historical
   * policy-bundle message. Depth is private; callers cannot
   * pass it.
   *
   * @param mixed $value
   *   A JSON-able claims value.
   *
   * @return mixed
   *   The normalized value.
   *
   * @throws \InvalidArgumentException
   *   When the value cannot be encoded, or the graph exceeds
   *   MAX_DEPTH, MAX_NODES, or MAX_BYTES.
   */
  public static function normalize(mixed $value): mixed {
    $nodes = 0;
    $bytes = 0;
    return self::canonicalize($value, 0, [], $nodes, $bytes, FALSE);
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
   *   When the value cannot be encoded, a cycle is found, or
   *   the graph exceeds MAX_DEPTH, MAX_NODES, or MAX_BYTES.
   */
  public static function normalizeIdentity(mixed $value): mixed {
    $nodes = 0;
    $bytes = 0;
    return self::canonicalize($value, 0, [], $nodes, $bytes, TRUE);
  }

  /**
   * One walk: optional identity expansion, then the shared sort.
   *
   * @param mixed $value
   *   A JSON-able value.
   * @param int $depth
   *   Current container depth (0 at the root).
   * @param array<int, true> $visited
   *   Object ids on the current expansion path.
   * @param int $nodes
   *   Values counted so far. Incremented for each visit.
   * @param int $bytes
   *   Payload bytes counted so far.
   * @param bool $identity
   *   TRUE to expand objects; FALSE to keep the policy
   *   arrays-and-scalars contract.
   *
   * @return mixed
   *   The normalized value.
   *
   * @throws \InvalidArgumentException
   *   When the value cannot be encoded, a cycle is found, or
   *   the graph exceeds MAX_DEPTH, MAX_NODES, or MAX_BYTES.
   */
  private static function canonicalize(
    mixed $value,
    int $depth,
    array $visited,
    int &$nodes,
    int &$bytes,
    bool $identity,
  ): mixed {
    if ($identity && is_object($value)) {
      return self::canonicalizeIdentityObject(
        $value,
        $depth,
        $visited,
        $nodes,
        $bytes,
      );
    }
    if (!is_array($value)) {
      if (is_string($value) || is_int($value) || is_float($value)
        || is_bool($value) || $value === NULL) {
        self::consumeNode($nodes);
        self::consumeBytes(
          $bytes,
          is_string($value) ? strlen($value) : 1,
        );
        return $value;
      }
      throw new \InvalidArgumentException(
        $identity
          ? 'Canonical JSON values may only contain scalars, lists and maps.'
          : 'Policy bundle claims may only contain scalars, lists and maps.',
      );
    }
    self::assertDepth($depth);
    self::consumeNode($nodes);
    if ($value === [] || array_is_list($value)) {
      foreach ($value as $key => $item) {
        $value[$key] = self::canonicalize(
          $item,
          $depth + 1,
          $visited,
          $nodes,
          $bytes,
          $identity,
        );
      }
      return $value;
    }
    ksort($value);
    foreach ($value as $key => $item) {
      if (is_string($key)) {
        self::consumeBytes($bytes, strlen($key));
      }
      $value[$key] = self::canonicalize(
        $item,
        $depth + 1,
        $visited,
        $nodes,
        $bytes,
        $identity,
      );
    }
    return $value;
  }

  /**
   * Expands one identity object, then continues the shared walk.
   *
   * @param object $value
   *   JsonSerializable or a public-property object.
   * @param int $depth
   *   Current container depth.
   * @param array<int, true> $visited
   *   Object ids on the current expansion path.
   * @param int $nodes
   *   Values counted so far.
   * @param int $bytes
   *   Payload bytes counted so far.
   *
   * @return mixed
   *   The normalized value.
   *
   * @throws \InvalidArgumentException
   *   When a cycle is found or the graph exceeds the limits.
   */
  private static function canonicalizeIdentityObject(
    object $value,
    int $depth,
    array $visited,
    int &$nodes,
    int &$bytes,
  ): mixed {
    self::assertDepth($depth);
    $id = spl_object_id($value);
    if (isset($visited[$id])) {
      throw new \InvalidArgumentException(
        'Canonical JSON depth exceeded.',
      );
    }
    $visited[$id] = TRUE;
    self::consumeNode($nodes);
    if ($value instanceof \JsonSerializable) {
      return self::canonicalize(
        $value->jsonSerialize(),
        $depth + 1,
        $visited,
        $nodes,
        $bytes,
        TRUE,
      );
    }
    $vars = get_object_vars($value);
    if ($vars === []) {
      return new \stdClass();
    }
    return self::canonicalize(
      $vars,
      $depth + 1,
      $visited,
      $nodes,
      $bytes,
      TRUE,
    );
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
    if ($depth >= self::MAX_DEPTH) {
      throw new \InvalidArgumentException(
        'Canonical JSON depth exceeded.',
      );
    }
  }

  /**
   * Counts one value and refuses a shared-reference fan-out.
   *
   * @param int $nodes
   *   Values counted so far.
   *
   * @throws \InvalidArgumentException
   *   When the walk exceeds MAX_NODES.
   */
  private static function consumeNode(int &$nodes): void {
    $nodes++;
    if ($nodes > self::MAX_NODES) {
      throw new \InvalidArgumentException(
        'Canonical JSON depth exceeded.',
      );
    }
  }

  /**
   * Counts payload bytes before a copy or encode can grow.
   *
   * @param int $bytes
   *   Payload bytes counted so far.
   * @param int $added
   *   Bytes from this value or key.
   *
   * @throws \InvalidArgumentException
   *   When the walk exceeds MAX_BYTES.
   */
  private static function consumeBytes(int &$bytes, int $added): void {
    $bytes += $added;
    if ($bytes > self::MAX_BYTES) {
      throw new \InvalidArgumentException(
        'Canonical JSON depth exceeded.',
      );
    }
  }

}
