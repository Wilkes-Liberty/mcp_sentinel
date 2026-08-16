<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Immutable sealed action manifest (slice 2 of #3616538).
 *
 * The claims plus an HMAC over their canonical JSON. The seal is the
 * contract that later slices bind approval and execution to. Slice 2
 * ships dark: nothing requires a valid manifest to execute.
 */
final class McpActionManifest {

  /**
   * Schema version of the claims document.
   */
  public const int VERSION = 1;

  /**
   * Claim keys in canonical (sorted) order.
   */
  private const CLAIM_KEYS = [
    'actor_uid',
    'arguments',
    'delegation',
    'expires',
    'id',
    'idempotency_key',
    'operation',
    'policy_digest',
    'preconditions',
    'target',
    'v',
  ];

  /**
   * Constructs a sealed manifest.
   *
   * @param array<string, mixed> $claims
   *   Canonical claims (no seal).
   * @param string $seal
   *   hmac-sha256:<hex> over the canonical claims JSON.
   */
  private function __construct(
    private readonly array $claims,
    private readonly string $seal,
  ) {}

  /**
   * Builds a manifest from already-verified claims and seal.
   *
   * Callers that have not verified the seal must not use this.
   *
   * @param array<string, mixed> $claims
   *   Canonical claims.
   * @param string $seal
   *   The matching seal.
   *
   * @return self
   *   The manifest.
   */
  public static function fromVerifiedClaims(array $claims, string $seal): self {
    return new self($claims, $seal);
  }

  /**
   * Canonical JSON of the claims (the HMAC input).
   *
   * @param array<string, mixed> $claims
   *   Claims without a seal.
   *
   * @return string
   *   Stable JSON.
   */
  public static function canonicalJson(array $claims): string {
    $normalized = self::normalize($claims);
    return json_encode(
      $normalized,
      JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
    );
  }

  /**
   * Recursively sorts object keys; leaves lists in caller order.
   *
   * @param mixed $value
   *   A JSON-able value.
   *
   * @return mixed
   *   The normalized value.
   */
  public static function normalize(mixed $value): mixed {
    if (!is_array($value)) {
      if (is_string($value) || is_int($value) || is_float($value) || is_bool($value) || $value === NULL) {
        return $value;
      }
      throw new \InvalidArgumentException(
        'Manifest claims may only contain scalars, lists and maps.',
      );
    }
    if ($value === []) {
      return [];
    }
    $isList = array_is_list($value);
    if (!$isList) {
      ksort($value);
    }
    foreach ($value as $key => $item) {
      $value[$key] = self::normalize($item);
    }
    return $value;
  }

  /**
   * Whether the given map has exactly the claim keys.
   *
   * @param array<string, mixed> $claims
   *   Candidate claims.
   */
  public static function hasClaimShape(array $claims): bool {
    $keys = array_keys($claims);
    sort($keys);
    return $keys === self::CLAIM_KEYS;
  }

  /**
   * Manifest id.
   */
  public function id(): string {
    return (string) $this->claims['id'];
  }

  /**
   * Actor uid.
   */
  public function actorUid(): int {
    return (int) $this->claims['actor_uid'];
  }

  /**
   * Operation id.
   */
  public function operation(): string {
    return (string) $this->claims['operation'];
  }

  /**
   * Expiry as a unix timestamp.
   */
  public function expires(): int {
    return (int) $this->claims['expires'];
  }

  /**
   * Single-use idempotency key.
   */
  public function idempotencyKey(): string {
    return (string) $this->claims['idempotency_key'];
  }

  /**
   * Target descriptor.
   *
   * @return array{type: string, id: string, uuid: ?string, revision: ?string}
   *   Target.
   */
  public function target(): array {
    return $this->claims['target'];
  }

  /**
   * Normalized arguments.
   *
   * @return array<string, mixed>
   *   Arguments.
   */
  public function arguments(): array {
    return $this->claims['arguments'];
  }

  /**
   * Delegation (consumer and caller request id).
   *
   * @return array{consumer_client_id: ?string, request_id: ?string}
   *   Delegation.
   */
  public function delegation(): array {
    return $this->claims['delegation'];
  }

  /**
   * Policy digest, if a profile resolved at mint time.
   */
  public function policyDigest(): ?string {
    $digest = $this->claims['policy_digest'];
    return $digest === NULL ? NULL : (string) $digest;
  }

  /**
   * Preconditions encoded at mint time.
   *
   * @return list<string>
   *   Stable precondition codes.
   */
  public function preconditions(): array {
    return $this->claims['preconditions'];
  }

  /**
   * The HMAC seal.
   */
  public function seal(): string {
    return $this->seal;
  }

  /**
   * Claims without the seal.
   *
   * @return array<string, mixed>
   *   Claims.
   */
  public function claims(): array {
    return $this->claims;
  }

  /**
   * JSON-ready document. Never contains the signing key.
   *
   * @return array<string, mixed>
   *   Claims plus seal.
   */
  public function toArray(): array {
    return $this->claims + ['seal' => $this->seal];
  }

  /**
   * Sealed JSON document.
   */
  public function toJson(): string {
    return json_encode(
      $this->toArray(),
      JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
    );
  }

}
