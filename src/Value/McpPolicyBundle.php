<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Versioned, digest-addressed portable policy bundle (d.o #3616536).
 *
 * The claims are immutable once sealed. The digest is SHA-256 of the
 * canonical JSON; the seal is HMAC-SHA256 of that digest with the
 * audit-chain signing key. A missing key cannot mint or verify.
 */
final class McpPolicyBundle {

  /**
   * Schema version.
   */
  public const int VERSION = 1;

  /**
   * Seal prefix.
   */
  public const string SEAL_PREFIX = 'hmac-sha256:';

  /**
   * Constructs a verified bundle.
   *
   * @param array<string, mixed> $claims
   *   Canonical claims without a seal.
   * @param string $digest
   *   Hex SHA-256 of the canonical claims.
   * @param string $seal
   *   HMAC-SHA256 hex over the digest, with the standard prefix.
   */
  private function __construct(
    private readonly array $claims,
    private readonly string $digest,
    private readonly string $seal,
  ) {}

  /**
   * Builds a bundle from already-verified claims, digest and seal.
   *
   * @param array<string, mixed> $claims
   *   Claims.
   * @param string $digest
   *   Digest.
   * @param string $seal
   *   Seal.
   */
  public static function fromVerified(array $claims, string $digest, string $seal): self {
    return new self($claims, $digest, $seal);
  }

  /**
   * Canonical JSON (HMAC / digest input).
   *
   * @param array<string, mixed> $claims
   *   Claims without a seal.
   */
  public static function canonicalJson(array $claims): string {
    return json_encode(
      self::normalize($claims),
      JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
    );
  }

  /**
   * Recursively sorts map keys; lists keep caller order.
   */
  public static function normalize(mixed $value): mixed {
    if (!is_array($value)) {
      if (is_string($value) || is_int($value) || is_float($value) || is_bool($value) || $value === NULL) {
        return $value;
      }
      throw new \InvalidArgumentException('Policy bundle claims may only contain scalars, lists and maps.');
    }
    $isList = array_is_list($value);
    if ($isList) {
      return array_map(self::normalize(...), $value);
    }
    ksort($value);
    foreach ($value as $key => $item) {
      $value[$key] = self::normalize($item);
    }
    return $value;
  }

  /**
   * Hex SHA-256 of the canonical claims.
   *
   * @param array<string, mixed> $claims
   *   Claims.
   */
  public static function digestOf(array $claims): string {
    return hash('sha256', self::canonicalJson($claims));
  }

  /**
   * The immutable digest.
   */
  public function digest(): string {
    return $this->digest;
  }

  /**
   * The HMAC seal.
   */
  public function seal(): string {
    return $this->seal;
  }

  /**
   * Schema version.
   */
  public function version(): int {
    return (int) ($this->claims['v'] ?? 0);
  }

  /**
   * Expiry unix timestamp, or 0 when none.
   */
  public function expires(): int {
    return (int) ($this->claims['expires'] ?? 0);
  }

  /**
   * Whether the bundle has expired at $now.
   */
  public function isExpired(int $now): bool {
    $expires = $this->expires();
    return $expires > 0 && $now >= $expires;
  }

  /**
   * Denied operations named by the bundle (the portable floor).
   *
   * @return string[]
   *   Operation ids.
   */
  public function deniedOperations(): array {
    $denials = $this->claims['denials'] ?? [];
    if (!is_array($denials)) {
      return [];
    }
    $ops = $denials['operations'] ?? [];
    return is_array($ops) ? array_values(array_map('strval', $ops)) : [];
  }

  /**
   * Whether the bundle refuses this operation.
   */
  public function denies(string $operation): bool {
    return in_array($operation, $this->deniedOperations(), TRUE);
  }

  /**
   * Claims without the seal, for export.
   *
   * @return array<string, mixed>
   *   Claims.
   */
  public function claims(): array {
    return $this->claims;
  }

  /**
   * Portable document including digest and seal.
   *
   * @return array<string, mixed>
   *   Export shape.
   */
  public function toArray(): array {
    return $this->claims + [
      'digest' => $this->digest,
      'seal' => $this->seal,
    ];
  }

}
