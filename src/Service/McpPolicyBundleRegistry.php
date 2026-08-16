<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\State\StateInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\mcp_sentinel\Value\McpPolicyBundle;

/**
 * Signs, verifies, activates and rolls back portable policy bundles.
 *
 * Provider-neutral: the only store is Drupal state plus the audit-chain
 * signing key. A missing key cannot mint, verify or activate — local
 * profile denials still apply (deny more, never less).
 */
final class McpPolicyBundleRegistry {

  /**
   * State key for the active attestation.
   */
  public const string STATE_ACTIVE = 'mcp_sentinel.policy_bundle.active';

  /**
   * State key for revoked digests.
   */
  public const string STATE_REVOKED = 'mcp_sentinel.policy_bundle.revoked';

  /**
   * State key for last-known-good attestation.
   */
  public const string STATE_LAST_GOOD = 'mcp_sentinel.policy_bundle.last_good';

  /**
   * Default bundle lifetime.
   */
  public const int DEFAULT_TTL = 86400 * 30;

  /**
   * Emergency-deny operation token used by simulate().
   */
  public const string EMERGENCY_DENY = '*';

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StateInterface $state,
    private readonly TimeInterface $time,
    private readonly UuidInterface $uuid,
    private readonly ?KeyRepositoryInterface $keyRepository = NULL,
  ) {}

  /**
   * Whether the signing key resolves.
   */
  public function canSeal(): bool {
    return $this->signingKeyMaterial() !== NULL;
  }

  /**
   * Mints a sealed bundle, or NULL when the key will not resolve.
   *
   * @param string[] $deniedOperations
   *   Operations the portable floor refuses.
   * @param int|null $ttl
   *   Lifetime in seconds.
   */
  public function mint(array $deniedOperations, ?int $ttl = NULL): ?McpPolicyBundle {
    $material = $this->signingKeyMaterial();
    if ($material === NULL) {
      return NULL;
    }
    $now = $this->time->getRequestTime();
    $claims = [
      'denials' => [
        'operations' => array_values(array_unique(array_map('strval', $deniedOperations))),
      ],
      'expires' => $now + ($ttl ?? self::DEFAULT_TTL),
      'id' => $this->uuid->generate(),
      'issued' => $now,
      'v' => McpPolicyBundle::VERSION,
    ];
    $digest = McpPolicyBundle::digestOf($claims);
    $seal = McpPolicyBundle::SEAL_PREFIX . hash_hmac('sha256', $digest, $material);
    return McpPolicyBundle::fromVerified($claims, $digest, $seal);
  }

  /**
   * Verifies a portable document. Rejects invalid, revoked or expired.
   *
   * @param array<string, mixed> $document
   *   Claims plus digest and seal.
   *
   * @return \Drupal\mcp_sentinel\Value\McpPolicyBundle|null
   *   The bundle, or NULL when it must not be trusted.
   */
  public function verify(array $document): ?McpPolicyBundle {
    $material = $this->signingKeyMaterial();
    if ($material === NULL) {
      return NULL;
    }
    $seal = $document['seal'] ?? NULL;
    $claimedDigest = $document['digest'] ?? NULL;
    unset($document['seal'], $document['digest']);
    if (!is_string($seal) || !str_starts_with($seal, McpPolicyBundle::SEAL_PREFIX)) {
      return NULL;
    }
    if ((int) ($document['v'] ?? 0) !== McpPolicyBundle::VERSION) {
      return NULL;
    }
    $digest = McpPolicyBundle::digestOf($document);
    if (!is_string($claimedDigest) || !hash_equals($digest, $claimedDigest)) {
      return NULL;
    }
    $expected = McpPolicyBundle::SEAL_PREFIX . hash_hmac('sha256', $digest, $material);
    if (!hash_equals($expected, $seal)) {
      return NULL;
    }
    $bundle = McpPolicyBundle::fromVerified($document, $digest, $seal);
    if ($bundle->isExpired($this->time->getRequestTime())) {
      return NULL;
    }
    if ($this->isRevoked($digest)) {
      return NULL;
    }
    return $bundle;
  }

  /**
   * Activates a verified bundle and attests the exact digest.
   *
   * Atomic: the previous attestation is stored as last-known-good first.
   *
   * @return array{digest: string, activated_at: int, previous: string|null}|null
   *   The new attestation, or NULL when the key is missing.
   */
  public function activate(McpPolicyBundle $bundle): ?array {
    if ($this->signingKeyMaterial() === NULL) {
      return NULL;
    }
    $current = $this->attestation();
    if (is_array($current) && isset($current['digest'])) {
      $this->state->set(self::STATE_LAST_GOOD, $current);
    }
    $attestation = [
      'digest' => $bundle->digest(),
      'activated_at' => $this->time->getRequestTime(),
      'previous' => is_array($current) ? (string) ($current['digest'] ?? '') : NULL,
      'bundle' => $bundle->toArray(),
    ];
    $this->state->set(self::STATE_ACTIVE, $attestation);
    return [
      'digest' => $attestation['digest'],
      'activated_at' => $attestation['activated_at'],
      'previous' => $attestation['previous'] !== '' ? $attestation['previous'] : NULL,
    ];
  }

  /**
   * The active attestation, or NULL when none.
   *
   * @return array<string, mixed>|null
   *   Attestation.
   */
  public function attestation(): ?array {
    $stored = $this->state->get(self::STATE_ACTIVE);
    return is_array($stored) ? $stored : NULL;
  }

  /**
   * Active bundle digest, or NULL.
   */
  public function activeDigest(): ?string {
    $attestation = $this->attestation();
    $digest = $attestation['digest'] ?? NULL;
    return is_string($digest) && $digest !== '' ? $digest : NULL;
  }

  /**
   * Simulates an operation against the candidate without executing.
   *
   * Local denials always win: an upstream allow cannot widen a local deny.
   *
   * @param string $operation
   *   Operation id.
   * @param bool $localDenies
   *   Whether the live local profile already refuses this operation.
   * @param \Drupal\mcp_sentinel\Value\McpPolicyBundle|null $candidate
   *   Bundle to evaluate, or NULL for the active one.
   *
   * @return array{allow: bool, reason: string, digest: string|null}
   *   Simulation result. never mutates state.
   */
  public function simulate(string $operation, bool $localDenies, ?McpPolicyBundle $candidate = NULL): array {
    $digest = $candidate?->digest() ?? $this->activeDigest();
    if ($localDenies) {
      return ['allow' => FALSE, 'reason' => 'local_deny', 'digest' => $digest];
    }
    $attestation = $this->attestation();
    if ($candidate === NULL && is_array($attestation) && !empty($attestation['emergency'])) {
      return [
        'allow' => FALSE,
        'reason' => 'emergency_deny',
        'digest' => $digest ?? 'emergency-deny',
      ];
    }
    $bundle = $candidate;
    if ($bundle === NULL) {
      $document = is_array($attestation) ? ($attestation['bundle'] ?? NULL) : NULL;
      $bundle = is_array($document) ? $this->verify($document) : NULL;
    }
    if ($bundle !== NULL && ($bundle->denies($operation) || $bundle->denies(self::EMERGENCY_DENY))) {
      return ['allow' => FALSE, 'reason' => 'bundle_deny', 'digest' => $bundle->digest()];
    }
    return ['allow' => TRUE, 'reason' => 'allow', 'digest' => $digest];
  }

  /**
   * Revokes a digest. If it is active, emergency-deny is armed.
   */
  public function revoke(string $digest): void {
    $revoked = $this->revoked();
    $revoked[$digest] = $this->time->getRequestTime();
    $this->state->set(self::STATE_REVOKED, $revoked);
    if ($this->activeDigest() === $digest) {
      $this->emergencyDeny();
    }
  }

  /**
   * Whether a digest has been revoked.
   */
  public function isRevoked(string $digest): bool {
    return isset($this->revoked()[$digest]);
  }

  /**
   * Rolls back to last-known-good. No-op when none exists.
   *
   * @return array<string, mixed>|null
   *   The restored attestation, or NULL.
   */
  public function rollback(): ?array {
    $last = $this->state->get(self::STATE_LAST_GOOD);
    if (!is_array($last) || !isset($last['digest'])) {
      return NULL;
    }
    $digest = (string) $last['digest'];
    if ($this->isRevoked($digest)) {
      return NULL;
    }
    $this->state->set(self::STATE_ACTIVE, $last);
    return $last;
  }

  /**
   * Activates a deny-all floor without minting new authority when offline.
   *
   * Does not mint a new signed bundle — it only records a deny attestation
   * so disconnected operation cannot grant more than it already had.
   */
  public function emergencyDeny(): void {
    $current = $this->attestation();
    if (is_array($current) && isset($current['digest'])) {
      $this->state->set(self::STATE_LAST_GOOD, $current);
    }
    $this->state->set(self::STATE_ACTIVE, [
      'digest' => 'emergency-deny',
      'activated_at' => $this->time->getRequestTime(),
      'previous' => is_array($current) ? (string) ($current['digest'] ?? '') : NULL,
      'emergency' => TRUE,
      'bundle' => [
        'v' => McpPolicyBundle::VERSION,
        'denials' => ['operations' => [self::EMERGENCY_DENY]],
        'expires' => 0,
        'id' => 'emergency-deny',
        'issued' => $this->time->getRequestTime(),
      ],
    ]);
  }

  /**
   * Revoked digest => revoked-at timestamp.
   *
   * @return array<string, int>
   *   Map.
   */
  private function revoked(): array {
    $stored = $this->state->get(self::STATE_REVOKED);
    if (!is_array($stored)) {
      return [];
    }
    $out = [];
    foreach ($stored as $digest => $when) {
      $out[(string) $digest] = (int) $when;
    }
    return $out;
  }

  /**
   * Signing key material, or NULL.
   */
  private function signingKeyMaterial(): ?string {
    $keyId = (string) ($this->configFactory->get('audit_chain.settings')->get('hash_key') ?? '');
    if ($keyId === '' || $this->keyRepository === NULL) {
      return NULL;
    }
    $key = $this->keyRepository->getKey($keyId);
    if ($key === NULL) {
      return NULL;
    }
    $material = (string) $key->getKeyValue();
    return $material !== '' ? $material : NULL;
  }

}
