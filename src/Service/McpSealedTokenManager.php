<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\PrivateKey;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Site\Settings;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason;
use Drupal\user\UserInterface;
use Symfony\Component\HttpFoundation\RequestStack;

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
   * Issuer (iss) carried by every verified sealed token.
   *
   * Sealed tokens are minted by this module, not by an IdP, so the
   * issuer is a fixed URN. The subject is the designated Consumer
   * owner's UUID and the authorized party is the client_id.
   */
  public const ISSUER = 'urn:mcp-sentinel:sealed-token';

  /**
   * Maximum length of a tenant claim minted into a sealed token.
   */
  public const MAX_TENANT_LENGTH = 256;

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
   * Private tempstore TTL for the copy-once reveal handoff, in seconds.
   *
   * The table stores a hash only. Tempstore holds the plaintext until the
   * reveal GET deletes it, or this TTL elapses. It is not durable storage.
   * Core's PrivateTempStoreFactory::get() takes only the collection name, so
   * this value is the factory's expire (see revealTempStore()), not a second
   * argument to get().
   */
  public const REVEAL_STORE_TTL = 120;

  /**
   * Builds the copy-once reveal tempstore.
   *
   * The site-wide private tempstore lives for days. This factory uses
   * REVEAL_STORE_TTL so a secret left unread is gone after two minutes.
   *
   * @param \Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface $storage_factory
   *   The key/value factory.
   * @param \Drupal\Core\Lock\LockBackendInterface $lock_backend
   *   The lock backend.
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user. Private tempstore keys are per account.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   *
   * @return \Drupal\Core\TempStore\PrivateTempStoreFactory
   *   A factory whose stores expire after REVEAL_STORE_TTL seconds.
   */
  public static function revealTempStore(
    KeyValueExpirableFactoryInterface $storage_factory,
    LockBackendInterface $lock_backend,
    AccountProxyInterface $current_user,
    RequestStack $request_stack,
  ): PrivateTempStoreFactory {
    return new PrivateTempStoreFactory(
      $storage_factory,
      $lock_backend,
      $current_user,
      $request_stack,
      self::REVEAL_STORE_TTL,
    );
  }

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
    private readonly McpSealedTokenDenialAuditor $denialAuditor,
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
   * @param string|null $tenant
   *   Tenant claim sealed into the token. Governed tools refuse a
   *   sealed-token HTTP call whose token carries no tenant, so a token
   *   minted without one can only be used by surfaces that do not go
   *   through the principal-context dispatcher.
   *
   * @return array{token: string, jti: string, client_id: string, expires: int, ttl: int, scopes: string[], tenant: string|null}
   *   One-time plaintext plus metadata. The token key must not be logged.
   *
   * @throws \InvalidArgumentException
   *   When the client is not designated, cannot mint, or the tenant is
   *   malformed.
   */
  public function mint(string $clientId, int $ttl, AccountInterface $operator, ?string $tenant = NULL): array {
    $clientId = trim($clientId);
    $tenant = $this->normalizeTenant($tenant);
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
    if ($tenant !== NULL) {
      $body['tnt'] = $tenant;
    }
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
      'tenant' => $tenant,
    ]);

    return [
      'token' => $token,
      'jti' => $jti,
      'client_id' => $clientId,
      'expires' => $expires,
      'ttl' => $ttl,
      'scopes' => $scopes,
      'tenant' => $tenant,
    ];
  }

  /**
   * Verifies a bearer and returns claims, or NULL when it is not valid.
   *
   * @param string $token
   *   Raw bearer value.
   *
   *   The returned claims carry the principal the dispatcher needs: iss
   *   (ISSUER), sub (the Consumer owner's UUID), azp (the client_id), and
   *   tenant when the token was minted with one.
   *
   * @return array{jti: string, client_id: string, uid: int, scopes: string[], expires: int, iss: string, sub: string, azp: string, tenant?: string}|null
   *   Claims when valid.
   */
  public function verify(string $token): ?array {
    $token = trim($token);
    if (!str_starts_with($token, self::PREFIX)) {
      return $this->deny(McpSealedTokenDenyReason::Malformed, [
        'token_hash_prefix' => $this->tokenHashPrefix($token),
      ]);
    }
    $parts = explode('.', substr($token, strlen(self::PREFIX)));
    if (count($parts) !== 3) {
      return $this->deny(McpSealedTokenDenyReason::Malformed, [
        'token_hash_prefix' => $this->tokenHashPrefix($token),
      ]);
    }
    [$jti, $bodyEncoded, $sig] = $parts;
    if ($jti === '' || $bodyEncoded === '' || $sig === '') {
      return $this->deny(McpSealedTokenDenyReason::Malformed, [
        'jti' => $jti,
        'token_hash_prefix' => $this->tokenHashPrefix($token),
      ]);
    }
    $expected = $this->b64(hash_hmac(
      'sha256',
      $jti . '.' . $bodyEncoded,
      $this->material(),
      TRUE,
    ));
    if (!hash_equals($expected, $sig)) {
      return $this->deny(McpSealedTokenDenyReason::BadSignature, [
        'jti' => $jti,
      ]);
    }
    $body = json_decode((string) $this->unb64($bodyEncoded), TRUE);
    if (!is_array($body)
      || ($body['jti'] ?? NULL) !== $jti
      || !is_string($body['cid'] ?? NULL)
      || !isset($body['uid'], $body['exp'])
    ) {
      return $this->deny(McpSealedTokenDenyReason::Malformed, [
        'jti' => $jti,
      ]);
    }
    $now = $this->time->getRequestTime();
    $uid = (int) $body['uid'];
    $clientId = (string) $body['cid'];
    if ((int) $body['exp'] <= $now) {
      return $this->deny(McpSealedTokenDenyReason::Expired, [
        'jti' => $jti,
        'uid' => $uid,
        'client_id' => $clientId,
      ]);
    }

    $row = $this->database->select(self::TABLE, 't')
      ->fields('t')
      ->condition('jti', $jti)
      ->execute()
      ->fetchAssoc();
    if (!is_array($row)) {
      return $this->deny(McpSealedTokenDenyReason::UnknownToken, [
        'jti' => $jti,
        'uid' => $uid,
        'client_id' => $clientId,
      ]);
    }
    $rowContext = $this->rowContext($jti, $row);
    if ((int) $row['revoked'] === 1) {
      return $this->deny(McpSealedTokenDenyReason::Revoked, $rowContext);
    }
    if ((int) $row['expires'] <= $now) {
      return $this->deny(McpSealedTokenDenyReason::Expired, $rowContext);
    }
    if (!hash_equals((string) $row['token_hash'], $this->hashToken($token))) {
      return $this->deny(McpSealedTokenDenyReason::HashMismatch, $rowContext);
    }
    if (!in_array((string) $row['client_id'], $this->designatedClientIds(), TRUE)) {
      return $this->deny(McpSealedTokenDenyReason::ClientNotDesignated, $rowContext);
    }
    if ((string) $row['client_id'] !== $clientId) {
      return $this->deny(McpSealedTokenDenyReason::AudienceMismatch, $rowContext);
    }
    if ((int) $row['uid'] !== $uid) {
      return $this->deny(McpSealedTokenDenyReason::AudienceMismatch, $rowContext);
    }
    $consumer = $this->loadConsumer((string) $row['client_id']);
    if (!$consumer instanceof ConsumerInterface) {
      return $this->deny(McpSealedTokenDenyReason::ConsumerMissing, $rowContext);
    }
    if (!$consumer->isPublished()) {
      return $this->deny(McpSealedTokenDenyReason::ConsumerUnpublished, $rowContext);
    }
    if ((int) $consumer->getOwnerId() !== (int) $row['uid']) {
      return $this->deny(McpSealedTokenDenyReason::OwnerMismatch, $rowContext);
    }
    $owner = $this->entityTypeManager->getStorage('user')->load((int) $row['uid']);
    if (!$owner instanceof UserInterface) {
      return $this->deny(McpSealedTokenDenyReason::AccountMissing, $rowContext);
    }
    if (!$owner->isActive()) {
      return $this->deny(McpSealedTokenDenyReason::AccountBlocked, $rowContext);
    }

    $scopes = is_array($body['scp'] ?? NULL)
      ? array_values(array_filter($body['scp'], 'is_string'))
      : [];
    $claims = [
      'jti' => $jti,
      'client_id' => (string) $row['client_id'],
      'uid' => (int) $row['uid'],
      'scopes' => $scopes,
      'expires' => (int) $row['expires'],
      'iss' => self::ISSUER,
      'sub' => (string) $owner->uuid(),
      'azp' => (string) $row['client_id'],
    ];
    $tenant = $this->normalizeTenant(is_string($body['tnt'] ?? NULL) ? $body['tnt'] : NULL);
    if ($tenant !== NULL) {
      $claims['tenant'] = $tenant;
    }
    return $claims;
  }

  /**
   * Trims a tenant claim and refuses an unusable one.
   *
   * @param string|null $tenant
   *   Raw tenant, or NULL when none was given.
   *
   * @return string|null
   *   The trimmed tenant, or NULL when none was given.
   *
   * @throws \InvalidArgumentException
   *   When the tenant is empty after trimming, over-long, or carries
   *   control characters.
   */
  private function normalizeTenant(?string $tenant): ?string {
    if ($tenant === NULL) {
      return NULL;
    }
    $tenant = trim($tenant);
    if ($tenant === ''
      || mb_strlen($tenant, 'UTF-8') > self::MAX_TENANT_LENGTH
      || preg_match('/\p{C}/u', $tenant) !== 0) {
      throw new \InvalidArgumentException(
        'The tenant claim must be 1 to ' . (string) self::MAX_TENANT_LENGTH
        . ' visible characters.',
      );
    }
    return $tenant;
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
   * Deletes expired rows. Live unexpired tokens stay.
   *
   * Returns 0 when the table is missing. Cron can run after this code is
   * deployed and before update.php has created the table.
   *
   * @return int
   *   The number of rows deleted.
   */
  public function pruneExpired(): int {
    if (!$this->database->schema()->tableExists(self::TABLE)) {
      return 0;
    }
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
    return hash(
      'sha256',
      (string) $this->settings->get('hash_salt', '') . $this->privateKey->get(),
      TRUE,
    );
  }

  /**
   * Non-secret context taken from a stored token row.
   *
   * @param string $jti
   *   Token id.
   * @param array<string, mixed> $row
   *   Database row.
   *
   * @return array{jti: string, uid: int, client_id: string}
   *   Context for auditDenial().
   */
  private function rowContext(string $jti, array $row): array {
    return [
      'jti' => $jti,
      'uid' => (int) $row['uid'],
      'client_id' => (string) $row['client_id'],
    ];
  }

  /**
   * Writes a sealed-token denial audit row and returns NULL.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Enumerated denial reason.
   * @param array<string, mixed> $context
   *   Non-secret context (jti, uid, client_id, hash prefix).
   *
   * @return null
   *   Always NULL so verify() stays fail-closed.
   */
  private function deny(McpSealedTokenDenyReason $reason, array $context = []): ?array {
    $this->auditDenial($reason, $context);
    return NULL;
  }

  /**
   * Records one sealed-token authentication denial.
   *
   * Used by verify() and by the auth provider after a missing or
   * blocked account. A throwing writer still leaves the caller denied.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Enumerated denial reason.
   * @param array<string, mixed> $context
   *   Non-secret context. Never the bearer or signature.
   */
  public function auditDenial(McpSealedTokenDenyReason $reason, array $context = []): void {
    $this->denialAuditor->record($reason, $context);
  }

  /**
   * SHA-256 of the raw bearer. Stored so the secret itself is never kept.
   */
  private function hashToken(string $token): string {
    return hash('sha256', $token);
  }

  /**
   * Non-secret prefix of the stored token hash, used when no jti is known.
   */
  private function tokenHashPrefix(string $token): string {
    return substr(
      $this->hashToken($token),
      0,
      McpSealedTokenDenialAuditor::HASH_PREFIX_LENGTH,
    );
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
