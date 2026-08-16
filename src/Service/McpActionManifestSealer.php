<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\mcp_sentinel\Value\McpActionManifest;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Mints and verifies HMAC-sealed action manifests.
 *
 * Uses the same audit-chain signing key the evidence guard fails
 * closed on (audit_chain.settings:hash_key). A missing or empty key
 * means this sealer cannot mint or verify — slice 2 then stores
 * nothing, and execution is unchanged. Slice 3 is what starts
 * refusing an unsealed high-impact path.
 */
final class McpActionManifestSealer {

  /**
   * Default manifest lifetime, in seconds.
   */
  public const int DEFAULT_TTL = 86400;

  /**
   * Seal prefix. The hex HMAC follows.
   */
  public const string SEAL_PREFIX = 'hmac-sha256:';

  /**
   * Constructs the sealer.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\key\KeyRepositoryInterface|null $keyRepository
   *   The key repository. NULL when the key module is absent; that
   *   cannot seal.
   * @param \Drupal\mcp_sentinel\Service\McpOauthContext $oauthContext
   *   Validated OAuth delegation (consumer client id).
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack, for X-Request-Id.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Clock for expiry.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   UUID generator for id and idempotency key.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ?KeyRepositoryInterface $keyRepository,
    private readonly McpOauthContext $oauthContext,
    private readonly RequestStack $requestStack,
    private readonly TimeInterface $time,
    private readonly UuidInterface $uuid,
  ) {}

  /**
   * Whether the audit-chain signing key resolves to usable material.
   */
  public function canSeal(): bool {
    return $this->signingKeyMaterial() !== NULL;
  }

  /**
   * Mints a sealed manifest, or NULL when the signing key will not resolve.
   *
   * Failures other than a missing key also return NULL so slice 2 cannot
   * take down the existing approval queue.
   *
   * @param \Drupal\Core\Session\AccountInterface $actor
   *   The requesting principal.
   * @param string $operation
   *   Operation id (e.g. delete).
   * @param array{type: string, id: string, uuid?: ?string, revision?: ?string} $target
   *   Target descriptor.
   * @param array<string, mixed> $arguments
   *   Normalized replay arguments.
   * @param string|null $policyDigest
   *   sha256: digest of the active profile, or NULL when none resolved.
   *
   * @return \Drupal\mcp_sentinel\Value\McpActionManifest|null
   *   The sealed manifest, or NULL when it cannot be minted.
   */
  public function tryMint(
    AccountInterface $actor,
    string $operation,
    array $target,
    array $arguments,
    ?string $policyDigest = NULL,
  ): ?McpActionManifest {
    try {
      $material = $this->signingKeyMaterial();
      if ($material === NULL) {
        return NULL;
      }
      return $this->mint($actor, $operation, $target, $arguments, $policyDigest, $material);
    }
    catch (\Throwable) {
      return NULL;
    }
  }

  /**
   * Parses and verifies a sealed JSON document.
   *
   * @param string $json
   *   The stored document.
   *
   * @return \Drupal\mcp_sentinel\Value\McpActionManifest|null
   *   The manifest when the seal matches; NULL when it does not, the
   *   key is missing, or the document is malformed.
   */
  public function open(string $json): ?McpActionManifest {
    $material = $this->signingKeyMaterial();
    if ($material === NULL || $json === '') {
      return NULL;
    }
    try {
      $decoded = json_decode($json, TRUE, 512, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException) {
      return NULL;
    }
    if (!is_array($decoded) || !isset($decoded['seal']) || !is_string($decoded['seal'])) {
      return NULL;
    }
    $seal = $decoded['seal'];
    unset($decoded['seal']);
    if (!McpActionManifest::hasClaimShape($decoded)) {
      return NULL;
    }
    if ((int) ($decoded['v'] ?? 0) !== McpActionManifest::VERSION) {
      return NULL;
    }
    $expected = $this->computeSeal(
      McpActionManifest::canonicalJson($decoded),
      $material,
    );
    if (!hash_equals($expected, $seal)) {
      return NULL;
    }
    return McpActionManifest::fromVerifiedClaims($decoded, $seal);
  }

  /**
   * Mints with already-resolved key material.
   *
   * @param \Drupal\Core\Session\AccountInterface $actor
   *   Actor.
   * @param string $operation
   *   Operation.
   * @param array{type: string, id: string, uuid?: ?string, revision?: ?string} $target
   *   Target.
   * @param array<string, mixed> $arguments
   *   Arguments.
   * @param string|null $policyDigest
   *   Policy digest.
   * @param string $material
   *   Signing key material.
   *
   * @return \Drupal\mcp_sentinel\Value\McpActionManifest
   *   The sealed manifest.
   */
  private function mint(
    AccountInterface $actor,
    string $operation,
    array $target,
    array $arguments,
    ?string $policyDigest,
    string $material,
  ): McpActionManifest {
    $now = $this->time->getRequestTime();
    $uuid = $target['uuid'] ?? NULL;
    $revision = $target['revision'] ?? NULL;
    $preconditions = [];
    if (is_string($uuid) && $uuid !== '') {
      $preconditions[] = 'target_uuid';
    }
    if (is_string($revision) && $revision !== '') {
      $preconditions[] = 'target_revision';
    }
    $requestId = $this->currentRequestId();
    $claims = [
      'actor_uid' => (int) $actor->id(),
      'arguments' => $arguments,
      'delegation' => [
        'consumer_client_id' => $this->oauthContext->clientId(),
        'request_id' => $requestId,
      ],
      'expires' => $now + self::DEFAULT_TTL,
      'id' => $this->uuid->generate(),
      'idempotency_key' => $this->uuid->generate(),
      'operation' => $operation,
      'policy_digest' => $policyDigest,
      'preconditions' => $preconditions,
      'target' => [
        'type' => $target['type'],
        'id' => $target['id'],
        'uuid' => is_string($uuid) && $uuid !== '' ? $uuid : NULL,
        'revision' => is_string($revision) && $revision !== '' ? $revision : NULL,
      ],
      'v' => McpActionManifest::VERSION,
    ];
    $canonical = McpActionManifest::canonicalJson($claims);
    $decoded = json_decode($canonical, TRUE, 512, JSON_THROW_ON_ERROR);
    $seal = $this->computeSeal($canonical, $material);
    return McpActionManifest::fromVerifiedClaims($decoded, $seal);
  }

  /**
   * HMAC over the canonical claims JSON.
   */
  private function computeSeal(string $canonical, string $material): string {
    return self::SEAL_PREFIX . hash_hmac('sha256', $canonical, $material);
  }

  /**
   * Signing key material, or NULL when the evidence-guard path would fail.
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
    return $material === '' ? NULL : $material;
  }

  /**
   * Caller's X-Request-Id, or NULL.
   */
  private function currentRequestId(): ?string {
    $request = $this->requestStack->getCurrentRequest();
    $id = $request ? (string) $request->headers->get('X-Request-Id', '') : '';
    return $id === '' ? NULL : substr($id, 0, 128);
  }

}
