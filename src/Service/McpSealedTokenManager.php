<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\PrivateKey;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Site\Settings;
use Drupal\user\UserInterface;

/**
 * Mints, verifies, and revokes short-lived client-bound sealed tokens.
 *
 * The raw secret is returned once at mint time and is never stored. The
 * table holds only a SHA-256 of the bearer, metadata, and a revoke flag.
 */
final class McpSealedTokenManager {

  /**
   * Token prefix so auth can apply without parsing OAuth JWTs.
   */
  public const PREFIX = 'mcs1.';

  /**
   * Default lifetime, in seconds.
   */
  public const DEFAULT_TTL = 3600;

  /**
   * Maximum lifetime, in seconds.
   */
  public const MAX_TTL = 86400;

  /**
   * Allowed TTL choices for the mint UI.
   */
  public const TTL_CHOICES = [
    900 => '15 minutes',
    3600 => '1 hour',
    28800 => '8 hours',
    86400 => '24 hours',
  ];

  /**
   * Table name.
   */
  public const TABLE = 'mcp_sentinel_sealed_token';

  /**
   * Constructs the manager.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly TimeInterface $time,
    private readonly UuidInterface $uuid,
    private readonly PrivateKey $privateKey,
    private readonly Settings $settings,
    private readonly McpAuditLogger $auditLogger,
  ) {}

  /**
   * Designated agent client ids from settings.
   *
   * @return string[]
   *   Non-empty client ids.
   */
  public function designatedClientIds(): array {
    $ids = [];
    foreach ((array) ($this->configFactory->get('mcp_sentinel.settings')->get('agent_oauth_clients') ?? []) as $id) {
      if (is_string($id) && trim($id) !== '') {
        $ids[] = trim($id);
      }
    }
    return array_values(array_unique($ids));
  }

  /**
   * Mints a sealed token bound to a designated client.
   *
   * @param string $clientId
   *   Designated consumer client_id.
   * @param int $ttl
   *   Lifetime in seconds, clamped to MAX_TTL.
   * @param \Drupal\Core\Session\AccountInterface $operator
   *   The minting administrator.
   *
   * @return array{token: string, jti: string, client_id: string, expires: int, ttl: int, scopes: string[]}
   *   One-time plaintext plus metadata. The token key must not be logged.
   *
   * @throws \InvalidArgumentException
   *   When the client is not designated or cannot mint.
   */
  public function mint(string $clientId, int $ttl, AccountInterface $operator): array {
    $clientId = trim($clientId);
    if (!in_array($clientId, $this->designatedClientIds(), TRUE)) {
      throw new \InvalidArgumentException('Sealed tokens can only be bound to a designated agent client.');
    }
    $consumer = $this->loadConsumer($clientId);
    if (!$consumer instanceof ConsumerInterface || !$consumer->isPublished()) {
      throw new \InvalidArgumentException('The designated Consumer is missing or disabled.');
    }
    $account = $this->entityTypeManager->getStorage('user')->load($consumer->getOwnerId());
    if (!$account instanceof UserInterface || !$account->isActive()) {
      throw new \InvalidArgumentException('The designated Consumer has no active owner account.');
    }

    $ttl = $this->clampTtl($ttl);
    $now = $this->time->getRequestTime();
    $expires = $now + $ttl;
    $jti = $this->uuid->generate();
    $scopes = $this->scopesForConsumer($consumer);
    $body = [
      'v' => 1,
      'jti' => $jti,
      'cid' => $clientId,
      'uid' => (int) $account->id(),
      'scp' => $scopes,
      'exp' => $expires,
    ];
    $bodyEncoded = $this->b64(json_encode($body, JSON_THROW_ON_ERROR));
    $sig = $this->b64(hash_hmac('sha256', $jti . '.' . $bodyEncoded, $this->material(), TRUE));
    $token = self::PREFIX . $jti . '.' . $bodyEncoded . '.' . $sig;

    $this->database->insert(self::TABLE)->fields([
      'jti' => $jti,
      'client_id' => $clientId,
      'uid' => (int) $account->id(),
      'scopes' => implode(' ', $scopes),
      'token_hash' => $this->hashToken($token),
      'expires' => $expires,
      'revoked' => 0,
      'minted_by' => (int) $operator->id(),
      'minted_at' => $now,
    ])->execute();

    $this->auditLogger->log('sealed_token_mint', [
      'jti' => $jti,
      'client_id' => $clientId,
      'uid' => (int) $account->id(),
      'expires' => $expires,
      'ttl' => $ttl,
      'minted_by' => (int) $operator->id(),
    ]);

    return [
      'token' => $token,
      'jti' => $jti,
      'client_id' => $clientId,
      'expires' => $expires,
      'ttl' => $ttl,
      'scopes' => $scopes,
    ];
  }

  /**
   * Verifies a bearer and returns claims, or NULL when it is not valid.
   *
   * @param string $token
   *   Raw bearer value.
   *
   * @return array{jti: string, client_id: string, uid: int, scopes: string[], expires: int}|null
   *   Claims when valid.
   */
  public function verify(string $token): ?array {
    $token = trim($token);
    if (!str_starts_with($token, self::PREFIX)) {
      return NULL;
    }
    $parts = explode('.', substr($token, strlen(self::PREFIX)));
    if (count($parts) !== 3) {
      return NULL;
    }
    [$jti, $bodyEncoded, $sig] = $parts;
    if ($jti === '' || $bodyEncoded === '' || $sig === '') {
      return NULL;
    }
    $expected = $this->b64(hash_hmac('sha256', $jti . '.' . $bodyEncoded, $this->material(), TRUE));
    if (!hash_equals($expected, $sig)) {
      return NULL;
    }
    $body = json_decode((string) $this->unb64($bodyEncoded), TRUE);
    if (!is_array($body)
      || ($body['jti'] ?? NULL) !== $jti
      || !is_string($body['cid'] ?? NULL)
      || !isset($body['uid'], $body['exp'])
    ) {
      return NULL;
    }
    $now = $this->time->getRequestTime();
    if ((int) $body['exp'] <= $now) {
      return NULL;
    }

    $row = $this->database->select(self::TABLE, 't')
      ->fields('t')
      ->condition('jti', $jti)
      ->execute()
      ->fetchAssoc();
    if (!is_array($row) || (int) $row['revoked'] === 1) {
      return NULL;
    }
    if ((int) $row['expires'] <= $now) {
      return NULL;
    }
    if (!hash_equals((string) $row['token_hash'], $this->hashToken($token))) {
      return NULL;
    }
    if (!in_array((string) $row['client_id'], $this->designatedClientIds(), TRUE)) {
      return NULL;
    }
    if ((string) $row['client_id'] !== $body['cid'] || (int) $row['uid'] !== (int) $body['uid']) {
      return NULL;
    }

    $scopes = is_array($body['scp'] ?? NULL)
      ? array_values(array_filter($body['scp'], 'is_string'))
      : [];
    return [
      'jti' => $jti,
      'client_id' => (string) $row['client_id'],
      'uid' => (int) $row['uid'],
      'scopes' => $scopes,
      'expires' => (int) $row['expires'],
    ];
  }

  /**
   * Revokes a token by jti. Returns TRUE when a live row was revoked.
   */
  public function revoke(string $jti, AccountInterface $operator): bool {
    $jti = trim($jti);
    if ($jti === '') {
      return FALSE;
    }
    $updated = (int) $this->database->update(self::TABLE)
      ->fields(['revoked' => 1])
      ->condition('jti', $jti)
      ->condition('revoked', 0)
      ->execute();
    if ($updated < 1) {
      return FALSE;
    }
    $this->auditLogger->log('sealed_token_revoke', [
      'jti' => $jti,
      'revoked_by' => (int) $operator->id(),
    ]);
    return TRUE;
  }

  /**
   * Lists minted tokens, newest first. Never includes the secret.
   *
   * @return array<int, array<string, mixed>>
   *   Metadata rows.
   */
  public function list(): array {
    $now = $this->time->getRequestTime();
    $rows = $this->database->select(self::TABLE, 't')
      ->fields('t')
      ->orderBy('minted_at', 'DESC')
      ->range(0, 50)
      ->execute()
      ->fetchAll(\PDO::FETCH_ASSOC);
    $out = [];
    foreach ($rows as $row) {
      $out[] = [
        'jti' => (string) $row['jti'],
        'client_id' => (string) $row['client_id'],
        'uid' => (int) $row['uid'],
        'scopes' => (string) $row['scopes'],
        'expires' => (int) $row['expires'],
        'revoked' => (int) $row['revoked'] === 1,
        'expired' => (int) $row['expires'] <= $now,
        'minted_by' => (int) $row['minted_by'],
        'minted_at' => (int) $row['minted_at'],
      ];
    }
    return $out;
  }

  /**
   * Deletes expired revoked or expired rows. Live unexpired tokens stay.
   */
  public function pruneExpired(): int {
    return (int) $this->database->delete(self::TABLE)
      ->condition('expires', $this->time->getRequestTime(), '<')
      ->execute();
  }

  /**
   * Clamps a requested TTL to the allowed set.
   */
  public function clampTtl(int $ttl): int {
    if (isset(self::TTL_CHOICES[$ttl])) {
      return $ttl;
    }
    return self::DEFAULT_TTL;
  }

  /**
   * Loads a Consumer by client_id.
   */
  private function loadConsumer(string $clientId): ?ConsumerInterface {
    if (!$this->entityTypeManager->hasDefinition('consumer')) {
      return NULL;
    }
    $found = $this->entityTypeManager
      ->getStorage('consumer')
      ->loadByProperties(['client_id' => $clientId]);
    $consumer = $found ? reset($found) : NULL;
    return $consumer instanceof ConsumerInterface ? $consumer : NULL;
  }

  /**
   * Scopes granted on the consumer, falling back to configured agent_scopes.
   *
   * @return string[]
   *   Scope names.
   */
  private function scopesForConsumer(ConsumerInterface $consumer): array {
    $scopes = [];
    if ($consumer->hasField('scopes')) {
      $value = $consumer->get('scopes')->getValue();
      foreach ($value as $item) {
        if (isset($item['scope_id']) && is_string($item['scope_id']) && $item['scope_id'] !== '') {
          $scopes[] = $item['scope_id'];
        }
      }
    }
    if ($scopes === []) {
      foreach ((array) ($this->configFactory->get('mcp_sentinel.settings')->get('agent_scopes') ?? []) as $scope) {
        if (is_string($scope) && $scope !== '') {
          $scopes[] = $scope;
        }
      }
    }
    return array_values(array_unique($scopes));
  }

  /**
   * HMAC material. Site-local; never exported as config.
   */
  private function material(): string {
    return hash('sha256', (string) $this->settings->get('hash_salt', '') . $this->privateKey->get(), TRUE);
  }

  /**
   * SHA-256 of the raw bearer. Stored so the secret itself is never kept.
   */
  private function hashToken(string $token): string {
    return hash('sha256', $token);
  }

  /**
   * URL-safe base64 without padding.
   */
  private function b64(string $raw): string {
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
  }

  /**
   * Inverse of b64().
   */
  private function unb64(string $encoded): string|false {
    return base64_decode(strtr($encoded, '-_', '+/'), TRUE);
  }

}
