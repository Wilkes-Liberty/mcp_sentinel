<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\IntegrityConstraintViolationException;
use Drupal\Core\Database\Transaction;
use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\user\UserInterface;

/**
 * Binds Paladin identities to Drupal operator accounts (DEV-986).
 *
 * Bind maps a Paladin iss|sub to one Drupal uid. The token claim
 * pinned in settings.php (default preferred_username) must match
 * the account name, case-sensitive. When a mail claim is pinned,
 * the token must carry email_verified === true and that mail
 * must match the account. A mail-type name claim is refused
 * unless a mail claim is also pinned. A uid may be bound to only
 * one iss|sub, enforced by a database unique constraint. Migrated
 * uid = 0 rows are not first-come: they re-bind only when that
 * token passes the claim match. Distinct operators compare
 * iss|sub and mapped uids. Unbind needs two distinct verified
 * operators.
 */
final class McpOperatorBinding {

  /**
   * Operator-binding table.
   */
  public const TABLE = 'mcp_sentinel_operator_binding';

  /**
   * Per-driver unique index: one uid greater than 0 per iss|sub.
   */
  public const UID_UNIQUE_INDEX = McpOperatorBindingUidSchema::INDEX;

  /**
   * Audit operation for a successful bind.
   */
  public const AUDIT_BIND = 'operator_bind';

  /**
   * Audit operation for a refused bind.
   */
  public const AUDIT_BIND_REFUSED = 'operator_bind_refused';

  /**
   * Audit operation for an unbind request (still pending).
   */
  public const AUDIT_UNBIND_REQUEST = 'operator_unbind_request';

  /**
   * Audit operation for a completed unbind.
   */
  public const AUDIT_UNBIND = 'operator_unbind';

  /**
   * Audit operation for a refused unbind.
   */
  public const AUDIT_UNBIND_REFUSED = 'operator_unbind_refused';

  /**
   * PHPUnit-only: skip same-identity unbind/confirm refusal.
   */
  public const WEAKEN_SKIP_SAME_OPERATOR = 'skip_same_operator';

  /**
   * PHPUnit-only: skip the mapped-Drupal-uid distinct-operator check.
   */
  public const WEAKEN_SKIP_UID_MATCH = 'skip_uid_match';

  /**
   * PHPUnit-only: skip bind-time claim match to the Drupal account.
   */
  public const WEAKEN_SKIP_BIND_CLAIM_MATCH = 'skip_bind_claim_match';

  /**
   * PHPUnit-only: skip one-uid-to-one-iss-sub uniqueness.
   */
  public const WEAKEN_SKIP_UID_UNIQUE = 'skip_uid_unique';

  /**
   * Settings.php pin for the bind name claim. Default preferred_username.
   */
  public const SETTING_NAME_CLAIM = 'mcp_sentinel.paladin.operator_name_claim';

  /**
   * Settings.php pin for the optional bind mail claim.
   */
  public const SETTING_MAIL_CLAIM = 'mcp_sentinel.paladin.operator_mail_claim';

  /**
   * Name-claim keys that are mail addresses and need a mail pin.
   */
  private const MAIL_TYPE_NAME_CLAIMS = [
    'email',
    'mail',
  ];

  /**
   * Test-only weaken flags. Empty in production.
   *
   * @var array<string, true>
   */
  private array $weakenForTest = [];

  /**
   * PHPUnit-only callback invoked immediately before an insert.
   */
  private mixed $beforeUpsertForTest = NULL;

  /**
   * Constructs the binding store.
   *
   * @param \Drupal\Core\Database\Connection $connection
   *   Database connection.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   Operator record and unbind batch ids.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   HMAC audit chain writer.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Clock used for the unbind confirm window.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Confirm window.
   * @param \Drupal\mcp_sentinel\Service\McpPaladinIntrospection $introspection
   *   Paladin token introspection.
   * @param \Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory $identities
   *   Advisory OS process metadata for audit rows.
   * @param \Drupal\Core\Site\Settings $settings
   *   Bind claim name and optional mail pins.
   */
  public function __construct(
    private readonly Connection $connection,
    private readonly UuidInterface $uuid,
    private readonly McpAuditLogger $auditLogger,
    private readonly TimeInterface $time,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly McpPaladinIntrospection $introspection,
    private readonly McpOperatorIdentityFactory $identities,
    private readonly Settings $settings,
  ) {}

  /**
   * Bind a Paladin identity from an introspected token to an account.
   *
   * The iss|sub comes from an active introspection response. The
   * pinned name claim must match the account name. A uid = 0 row
   * for this identity may be upgraded only after that match.
   *
   * @param string $token
   *   Paladin access token. Never logged.
   * @param \Drupal\user\UserInterface $account
   *   Drupal account to bind. Anonymous is refused.
   *
   * @return string
   *   Operator record id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function bindFromToken(string $token, UserInterface $account): string {
    try {
      $payload = $this->introspection->activePayload($token);
      $this->assertBindClaims($payload, $account);
      $paladin = $this->introspection->identityFromPayload($payload);
    }
    catch (McpKillSwitchException $e) {
      $this->auditIdentityFailure(self::AUDIT_BIND_REFUSED, $e);
    }
    return $this->bindToAccount($paladin, (int) $account->id());
  }

  /**
   * PHPUnit-only seed of a Paladin identity. Does not run claim matching.
   *
   * @internal
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function bindIdentityForTest(McpOperatorIdentity $identity, int $uid): string {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'bindIdentityForTest exists only under PHPUnit.',
      );
    }
    return $this->bindToAccount($identity, $uid);
  }

  /**
   * Bind one verified identity to a Drupal account.
   *
   * Claim proof is structural: the only production caller is
   * bindFromToken() after assertBindClaims(). A uid may belong
   * to only one iss|sub. A uid = 0 row upgrades to $uid.
   *
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $identity
   *   Paladin identity.
   * @param int $uid
   *   Drupal account id. Anonymous is refused.
   *
   * @return string
   *   Operator record id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function bindToAccount(McpOperatorIdentity $identity, int $uid): string {
    try {
      $this->assertVerified($identity);
      if ($uid <= 0) {
        throw new McpKillSwitchException(
          McpKillSwitchException::MISSING_OPERATOR,
          'An operator account is required.',
        );
      }
      $this->requireTable();
      $txn = $this->connection->startTransaction();
      try {
        $existing = $this->recordId($identity->kind, $identity->id);
        if ($existing !== NULL) {
          $boundUid = $this->uidFor($identity);
          if ($boundUid === $uid) {
            $this->audit(self::AUDIT_BIND, $identity, $existing);
            unset($txn);
            return $existing;
          }
          if ($boundUid === 0) {
            $this->connection->update(self::TABLE)
              ->fields(['uid' => $uid])
              ->condition('identity_hash', $this->identityHash($identity->kind, $identity->id))
              ->execute();
            $this->audit(self::AUDIT_BIND, $identity, $existing);
            unset($txn);
            return $existing;
          }
          throw new McpKillSwitchException(
            McpKillSwitchException::OPERATOR_BINDING_CONFLICT,
            'Those identities are already bound to different operator records.',
          );
        }
        $operatorId = $this->uuid->generate();
        $this->upsert($identity, $operatorId, $uid);
        $this->audit(self::AUDIT_BIND, $identity, $operatorId);
        unset($txn);
        return $operatorId;
      }
      catch (\Throwable $e) {
        $txn->rollBack();
        if ($e instanceof IntegrityConstraintViolationException) {
          throw new McpKillSwitchException(
            McpKillSwitchException::OPERATOR_BINDING_CONFLICT,
            'Those identities are already bound to different operator records.',
          );
        }
        throw $e;
      }
    }
    catch (McpKillSwitchException $e) {
      $this->auditRefusal(self::AUDIT_BIND_REFUSED, $e, $identity, NULL);
    }
  }

  /**
   * Request unbind of this operator's bound record.
   *
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Verified Paladin operator.
   *
   * @return string
   *   Unbind batch id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function requestUnbind(McpOperatorIdentity $operator): string {
    try {
      $this->assertVerified($operator);
      $this->requireTable();
      $operatorId = $this->recordId($operator->kind, $operator->id);
      if ($operatorId === NULL) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNBOUND_OPERATOR,
          'This Paladin identity is not bound to a Drupal operator account.',
        );
      }
      $now = $this->time->getRequestTime();
      $batchId = $this->uuid->generate();
      $this->connection->update(self::TABLE)
        ->fields([
          'unbind_batch_id' => $batchId,
          'unbind_requested_by' => $operator->storageId(),
          'unbind_requested_at' => $now,
          'unbind_confirm_until' => $now + $this->confirmWindow(),
        ])
        ->condition('operator_id', $operatorId)
        ->execute();
      $this->auditLogger->logAlways(self::AUDIT_UNBIND_REQUEST, [
        'actor' => $operator->storageId(),
        'operator_id' => $operatorId,
        'batch_id' => $batchId,
        'second_confirmer' => '',
      ]);
      return $batchId;
    }
    catch (McpKillSwitchException $e) {
      $this->auditRefusal(self::AUDIT_UNBIND_REFUSED, $e, $operator, NULL);
    }
  }

  /**
   * Second operator confirms a pending unbind.
   *
   * @param string $batchId
   *   Batch id from requestUnbind().
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Distinct verified confirmer.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function confirmUnbind(string $batchId, McpOperatorIdentity $operator): void {
    try {
      $this->assertVerified($operator);
      $this->requireTable();
      $batchId = trim($batchId);
      if ($batchId === '') {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNKNOWN_BATCH,
          'No pending unbind matches that batch.',
        );
      }
      $now = $this->time->getRequestTime();
      $txn = $this->connection->startTransaction();
      try {
        $statement = $this->connection->select(self::TABLE, 'b')
          ->fields('b', [
            'operator_id',
            'unbind_requested_by',
            'unbind_confirm_until',
          ])
          ->condition('unbind_batch_id', $batchId)
          ->execute();
        $rows = [];
        if ($statement !== NULL) {
          while (TRUE) {
            $fetched = $statement->fetchAssoc();
            if ($fetched === FALSE) {
              break;
            }
            $rows[] = $fetched;
          }
        }
        if ($rows === []) {
          throw new McpKillSwitchException(
            McpKillSwitchException::UNKNOWN_BATCH,
            'No pending unbind matches that batch.',
          );
        }
        $operatorId = '';
        $requestedBy = '';
        foreach ($rows as $row) {
          $confirmUntil = $row['unbind_confirm_until'] ?? 0;
          if (!is_numeric($confirmUntil) || (int) $confirmUntil <= $now) {
            throw new McpKillSwitchException(
              McpKillSwitchException::CONFIRM_EXPIRED,
              'The confirm window has elapsed.',
            );
          }
          $requestedByRaw = $row['unbind_requested_by'] ?? '';
          $operatorIdRaw = $row['operator_id'] ?? '';
          $requestedBy = is_string($requestedByRaw) ? $requestedByRaw : '';
          $operatorId = is_string($operatorIdRaw) ? $operatorIdRaw : '';
        }
        $this->assertDistinctOperators($requestedBy, $operator->storageId());
        $this->connection->delete(self::TABLE)
          ->condition('operator_id', $operatorId)
          ->execute();
        unset($txn);
      }
      catch (\Throwable $e) {
        if ($txn instanceof Transaction) {
          $txn->rollBack();
        }
        throw $e;
      }
      $this->auditLogger->logAlways(self::AUDIT_UNBIND, [
        'actor' => $operator->storageId(),
        'operator_id' => $operatorId,
        'batch_id' => $batchId,
        'second_confirmer' => $operator->storageId(),
      ]);
    }
    catch (McpKillSwitchException $e) {
      $this->auditRefusal(self::AUDIT_UNBIND_REFUSED, $e, $operator, NULL);
    }
  }

  /**
   * Distinct confirmer. Same verified identity twice is refused.
   *
   * Two Paladin identities that map to the same Drupal uid are
   * SAME_OPERATOR. The same-identity flag does not skip the uid
   * check.
   *
   * @param string $first
   *   Stored operator id of the requester.
   * @param string $second
   *   Stored operator id of the confirmer.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function assertDistinctOperators(string $first, string $second): void {
    if ($first === '' || $second === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $same = strlen($first) === strlen($second) && hash_equals($first, $second);
    if ($same && !$this->weakened(self::WEAKEN_SKIP_SAME_OPERATOR)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::SAME_OPERATOR,
        'The named second person (secondary account holder) must be a distinct operator account.',
      );
    }
    $firstUid = $this->uidForStorageId($first);
    $secondUid = $this->uidForStorageId($second);
    if ($firstUid > 0 && $secondUid > 0 && $firstUid === $secondUid
      && !$this->weakened(self::WEAKEN_SKIP_UID_MATCH)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::SAME_OPERATOR,
        'The named second person (secondary account holder) must be a distinct operator account.',
      );
    }
  }

  /**
   * Bound operator record for a kind and identity id, or NULL.
   *
   * Missing table: NULL (unbound identities then refuse).
   *
   * @param string $kind
   *   Paladin or leftover drush kind from a pre-10037 row.
   * @param string $id
   *   Human key or leftover Drush fingerprint.
   *
   * @return string|null
   *   Operator record id, or NULL when unbound or the table is missing.
   */
  public function recordId(string $kind, string $id): ?string {
    if ($kind === '' || $id === '' || !$this->tableReady()) {
      return NULL;
    }
    $statement = $this->connection->select(self::TABLE, 'b')
      ->fields('b', ['operator_id'])
      ->condition('identity_hash', $this->identityHash($kind, $id))
      ->execute();
    if ($statement === NULL) {
      return NULL;
    }
    $row = $statement->fetchAssoc();
    if ($row === FALSE) {
      return NULL;
    }
    $operatorId = $row['operator_id'] ?? '';
    return is_string($operatorId) && $operatorId !== '' ? $operatorId : NULL;
  }

  /**
   * Constant-time equality of two operator record ids.
   *
   * @param string $first
   *   Left operator record id.
   * @param string $second
   *   Right operator record id.
   *
   * @return bool
   *   TRUE when both ids are the same record.
   */
  public function sameRecord(string $first, string $second): bool {
    return strlen($first) === strlen($second) && hash_equals($first, $second);
  }

  /**
   * PHPUnit-only injection that disables bind or unbind invariants.
   *
   * Impossible outside the PHPUnit process. Used so unbound, same-
   * person, uniqueness, and same-operator unbind tests can fail.
   *
   * @param string $flag
   *   One of the WEAKEN_* constants.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function weakenForTest(string $flag): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Operator-binding weaken flags can be set only under PHPUnit.',
      );
    }
    $this->weakenForTest[$flag] = TRUE;
    if ($flag === self::WEAKEN_SKIP_UID_UNIQUE) {
      (new McpOperatorBindingUidSchema($this->connection))->drop();
    }
  }

  /**
   * PHPUnit-only hook that runs after the uniqueness read, before insert.
   *
   * Used so a concurrent insert can be shown to become an audited
   * binding-conflict refusal.
   *
   * @param callable $callback
   *   Receives the identity about to be inserted.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function beforeUpsertForTest(callable $callback): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Operator-binding upsert hooks can be set only under PHPUnit.',
      );
    }
    $this->beforeUpsertForTest = $callback;
  }

  /**
   * Mapped Drupal uid for a verified identity, or 0 when unbound.
   */
  public function uidFor(McpOperatorIdentity $identity): int {
    return $this->uidForKindAndId($identity->kind, $identity->id);
  }

  /**
   * Mapped Drupal uid for a stored operator id, or 0 when unbound.
   */
  public function uidForStorageId(string $storageId): int {
    $kind = $this->storageKind($storageId);
    $id = $this->storageIdentity($storageId);
    return $this->uidForKindAndId($kind, $id);
  }

  /**
   * OS process fields for audit rows. Never used as identity.
   *
   * @return array<string, string>
   *   euid, process user, and SUDO_USER when present.
   */
  public function advisoryProcessMetadata(): array {
    return $this->identities->advisoryProcessMetadata();
  }

  /**
   * Inserts an identity row, or confirms it already matches this record.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function upsert(McpOperatorIdentity $identity, string $operatorId, int $uid = 0): void {
    $existing = $this->recordId($identity->kind, $identity->id);
    if ($existing !== NULL) {
      if (!$this->sameRecord($existing, $operatorId)) {
        throw new McpKillSwitchException(
          McpKillSwitchException::OPERATOR_BINDING_CONFLICT,
          'Those identities are already bound to different operator records.',
        );
      }
      return;
    }
    if (is_callable($this->beforeUpsertForTest)) {
      ($this->beforeUpsertForTest)($identity, $operatorId);
    }
    $this->connection->insert(self::TABLE)
      ->fields([
        'identity_hash' => $this->identityHash($identity->kind, $identity->id),
        'identity_kind' => $identity->kind,
        'identity_id' => $identity->id,
        'operator_id' => $operatorId,
        'uid' => $uid,
        'unbind_batch_id' => '',
        'unbind_requested_by' => '',
        'unbind_requested_at' => 0,
        'unbind_confirm_until' => 0,
      ])
      ->execute();
  }

  /**
   * Mapped Drupal uid for a kind and identity id, or 0.
   */
  private function uidForKindAndId(string $kind, string $id): int {
    if ($kind === '' || $id === '' || !$this->tableReady()) {
      return 0;
    }
    if (!$this->connection->schema()->fieldExists(self::TABLE, 'uid')) {
      return 0;
    }
    $statement = $this->connection->select(self::TABLE, 'b')
      ->fields('b', ['uid'])
      ->condition('identity_hash', $this->identityHash($kind, $id))
      ->execute();
    if ($statement === NULL) {
      return 0;
    }
    $row = $statement->fetchAssoc();
    if ($row === FALSE) {
      return 0;
    }
    $uid = $row['uid'] ?? 0;
    return is_numeric($uid) ? (int) $uid : 0;
  }

  /**
   * SHA-256 of kind and identity id. Unique-index key, not a secret.
   */
  private function identityHash(string $kind, string $id): string {
    return hash('sha256', $kind . "\0" . $id);
  }

  /**
   * Kind prefix of a stored operator id (paladin, drush, uid).
   */
  private function storageKind(string $storageId): string {
    $pos = strpos($storageId, ':');
    if ($pos === FALSE || $pos === 0) {
      return '';
    }
    return substr($storageId, 0, $pos);
  }

  /**
   * Identity part of a stored operator id after the kind prefix.
   */
  private function storageIdentity(string $storageId): string {
    $pos = strpos($storageId, ':');
    if ($pos === FALSE) {
      return '';
    }
    return substr($storageId, $pos + 1);
  }

  /**
   * Token claims must match the Drupal account, case-sensitive.
   *
   * @param array<string, mixed> $payload
   *   Active introspection claims.
   * @param \Drupal\user\UserInterface $account
   *   Account named by --operator.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertBindClaims(array $payload, UserInterface $account): void {
    if ($this->weakened(self::WEAKEN_SKIP_BIND_CLAIM_MATCH)) {
      return;
    }
    // Drupal Settings::get() is static; the injected instance is the test seam.
    // @phpstan-ignore staticMethod.dynamicCall
    $nameClaim = $this->settings->get(self::SETTING_NAME_CLAIM, 'preferred_username');
    if (!is_string($nameClaim) || $nameClaim === '') {
      $nameClaim = 'preferred_username';
    }
    // @phpstan-ignore staticMethod.dynamicCall
    $mailClaim = $this->settings->get(self::SETTING_MAIL_CLAIM, '');
    if (!is_string($mailClaim)) {
      $mailClaim = '';
    }
    if (in_array($nameClaim, self::MAIL_TYPE_NAME_CLAIMS, TRUE) && $mailClaim === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::OPERATOR_MISMATCH,
        'A mail-type operator_name_claim requires mcp_sentinel.paladin.operator_mail_claim.',
      );
    }
    $expectedName = $account->getAccountName();
    $actualName = $payload[$nameClaim] ?? NULL;
    $nameOk = is_string($actualName)
      && $expectedName !== ''
      && strlen($actualName) === strlen($expectedName)
      && hash_equals($expectedName, $actualName);
    if (!$nameOk) {
      throw new McpKillSwitchException(
        McpKillSwitchException::OPERATOR_MISMATCH,
        'The Paladin token does not match the Drupal account in --operator.',
      );
    }
    if ($mailClaim === '') {
      return;
    }
    if (($payload['email_verified'] ?? NULL) !== TRUE) {
      throw new McpKillSwitchException(
        McpKillSwitchException::OPERATOR_MISMATCH,
        'The Paladin token mail claim is missing or not verified.',
      );
    }
    $expectedMail = (string) $account->getEmail();
    $actualMail = $payload[$mailClaim] ?? NULL;
    $mailOk = is_string($actualMail)
      && $expectedMail !== ''
      && strlen($actualMail) === strlen($expectedMail)
      && hash_equals($expectedMail, $actualMail);
    if (!$mailOk) {
      throw new McpKillSwitchException(
        McpKillSwitchException::OPERATOR_MISMATCH,
        'The Paladin token does not match the Drupal account in --operator.',
      );
    }
  }

  /**
   * Paladin identities only. Leftover Drush rows are not verified.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertVerified(McpOperatorIdentity $identity): void {
    if ($identity->isVerified()) {
      return;
    }
    throw new McpKillSwitchException(
      McpKillSwitchException::UNVERIFIED_OPERATOR,
      'A verified operator identity is required.',
    );
  }

  /**
   * Binding table must exist for writes.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function requireTable(): void {
    if (!$this->tableReady()) {
      throw new McpKillSwitchException(
        McpKillSwitchException::TABLE_MISSING,
        'The operator-binding table is not installed.',
      );
    }
  }

  /**
   * Whether the binding table exists.
   */
  private function tableReady(): bool {
    return $this->connection->schema()->tableExists(self::TABLE);
  }

  /**
   * Configured confirm window.
   */
  private function confirmWindow(): int {
    $raw = $this->configFactory->get('mcp_sentinel.settings')->get('kill_switch_confirm_window');
    $value = is_numeric($raw) ? (int) $raw : McpKillTtl::CONFIRM_WINDOW_DEFAULT;
    return $value > 0 ? $value : McpKillTtl::CONFIRM_WINDOW_DEFAULT;
  }

  /**
   * Whether a PHPUnit weaken flag is on.
   */
  private function weakened(string $flag): bool {
    return isset($this->weakenForTest[$flag]);
  }

  /**
   * Successful bind audit. Never includes a token.
   */
  private function audit(
    string $operation,
    McpOperatorIdentity $identity,
    string $operatorId,
  ): void {
    $this->auditLogger->logAlways($operation, [
      'actor' => $identity->storageId(),
      'operator_id' => $operatorId,
    ]);
  }

  /**
   * Refusal before an identity exists. Never includes a token.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function auditIdentityFailure(string $operation, McpKillSwitchException $e): never {
    $this->auditLogger->logAlways($operation, [
      'reason_code' => $e->reasonCode,
      'actor' => '',
      'second_confirmer' => '',
      'operator_id' => '',
    ]);
    throw new McpKillSwitchException($e->reasonCode, $e->getMessage(), TRUE);
  }

  /**
   * Refusal audit. Never includes a token.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function auditRefusal(
    string $operation,
    McpKillSwitchException $e,
    McpOperatorIdentity $first,
    ?McpOperatorIdentity $second,
  ): never {
    if (!$e->alreadyAudited) {
      $this->auditLogger->logAlways($operation, [
        'reason_code' => $e->reasonCode,
        'actor' => $first->storageId(),
        'second_confirmer' => $second instanceof McpOperatorIdentity ? $second->storageId() : '',
        'operator_id' => '',
      ]);
    }
    throw new McpKillSwitchException($e->reasonCode, $e->getMessage(), TRUE);
  }

}
