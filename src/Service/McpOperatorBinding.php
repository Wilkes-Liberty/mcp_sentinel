<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\IntegrityConstraintViolationException;
use Drupal\Core\Database\Transaction;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;

/**
 * Binds Paladin identities to Drupal operator accounts (DEV-986).
 *
 * Bind maps a Paladin iss|sub to one Drupal uid. Joining a second
 * identity onto an already-bound record is refused. Distinct
 * operators compare iss|sub and mapped uids. Mixed-channel confirm
 * (Paladin request, Drush confirm, or the reverse) still requires
 * both identities to resolve to bound records when OS assertion is
 * enabled. Bind takes iss|sub only from Paladin introspection.
 * Unbind needs two distinct verified operators.
 */
final class McpOperatorBinding {

  /**
   * Operator-binding table.
   */
  public const TABLE = 'mcp_sentinel_operator_binding';

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
   * PHPUnit-only: skip mixed-channel unbound/same-person and squat refusal.
   */
  public const WEAKEN_SKIP_MIXED_CHANNEL = 'skip_mixed_channel';

  /**
   * PHPUnit-only: skip same-identity unbind/confirm refusal.
   */
  public const WEAKEN_SKIP_SAME_OPERATOR = 'skip_same_operator';

  /**
   * PHPUnit-only: allow joining a second identity onto a bound record.
   */
  public const WEAKEN_SKIP_JOIN_REFUSAL = 'skip_join_refusal';

  /**
   * PHPUnit-only: skip the mapped-Drupal-uid distinct-operator check.
   */
  public const WEAKEN_SKIP_UID_MATCH = 'skip_uid_match';

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
   *   Drush OS-assertion identity.
   */
  public function __construct(
    private readonly Connection $connection,
    private readonly UuidInterface $uuid,
    private readonly McpAuditLogger $auditLogger,
    private readonly TimeInterface $time,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly McpPaladinIntrospection $introspection,
    private readonly McpOperatorIdentityFactory $identities,
  ) {}

  /**
   * Bind a Paladin identity from an introspected token to a Drupal uid.
   *
   * The iss|sub comes from an active introspection response, never from
   * a --human-key string.
   *
   * @param string $token
   *   Paladin access token. Never logged.
   * @param int $uid
   *   Drupal account id to bind. Anonymous is refused.
   *
   * @return string
   *   Operator record id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function bindFromToken(string $token, int $uid): string {
    try {
      $paladin = $this->introspection->activeIdentity($token);
    }
    catch (McpKillSwitchException $e) {
      $this->auditIdentityFailure(self::AUDIT_BIND_REFUSED, $e);
    }
    return $this->bindToAccount($paladin, $uid);
  }

  /**
   * Bind one verified identity to a Drupal account.
   *
   * A second identity is not added to an existing record.
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
  public function bindToAccount(McpOperatorIdentity $identity, int $uid): string {
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
          if ($boundUid === $uid || $boundUid === 0) {
            if ($boundUid === 0) {
              $this->connection->update(self::TABLE)
                ->fields(['uid' => $uid])
                ->condition('identity_hash', $this->identityHash($identity->kind, $identity->id))
                ->execute();
            }
            $this->audit(self::AUDIT_BIND, $identity, $identity, $existing);
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
        $this->audit(self::AUDIT_BIND, $identity, $identity, $operatorId);
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
      throw $e;
    }
  }

  /**
   * Bind two verified identities to one operator record.
   *
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $first
   *   Paladin or Drush identity.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $second
   *   Paladin or Drush identity.
   *
   * @return string
   *   Operator record id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When an identity is unverified, the table is missing, or the
   *   identities already belong to different records.
   */
  public function bind(McpOperatorIdentity $first, McpOperatorIdentity $second): string {
    try {
      $this->assertVerified($first);
      $this->assertVerified($second);
      $this->requireTable();

      $txn = $this->connection->startTransaction();
      try {
        $firstRecord = $this->recordId($first->kind, $first->id);
        $secondRecord = $this->recordId($second->kind, $second->id);
        if ($firstRecord !== NULL && $secondRecord !== NULL) {
          if (!$this->sameRecord($firstRecord, $secondRecord)) {
            if ($this->weakened(self::WEAKEN_SKIP_MIXED_CHANNEL)) {
              $this->audit(self::AUDIT_BIND, $first, $second, $firstRecord);
              unset($txn);
              return $firstRecord;
            }
            throw new McpKillSwitchException(
              McpKillSwitchException::OPERATOR_BINDING_CONFLICT,
              'Those identities are already bound to different operator records.',
            );
          }
          $this->audit(self::AUDIT_BIND, $first, $second, $firstRecord);
          unset($txn);
          return $firstRecord;
        }
        $joinedExisting = ($firstRecord === NULL) !== ($secondRecord === NULL);
        if ($joinedExisting && !$this->weakened(self::WEAKEN_SKIP_JOIN_REFUSAL)
          && !$this->weakened(self::WEAKEN_SKIP_MIXED_CHANNEL)) {
          throw new McpKillSwitchException(
            McpKillSwitchException::OPERATOR_BINDING_CONFLICT,
            'Those identities are already bound to different operator records.',
          );
        }
        $operatorId = $firstRecord ?? $secondRecord ?? $this->uuid->generate();
        $this->upsert($first, $operatorId);
        $this->upsert($second, $operatorId);
        $this->audit(self::AUDIT_BIND, $first, $second, $operatorId, $joinedExisting);
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
      $this->auditRefusal(self::AUDIT_BIND_REFUSED, $e, $first, $second);
      throw $e;
    }
  }

  /**
   * Request unbind of the Paladin identity's operator record.
   *
   * @param string $token
   *   Paladin access token. Never logged.
   *
   * @return string
   *   Unbind batch id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function requestUnbindFromToken(string $token): string {
    try {
      $operator = $this->introspection->activeIdentity($token);
    }
    catch (McpKillSwitchException $e) {
      $this->auditIdentityFailure(self::AUDIT_UNBIND_REFUSED, $e);
    }
    return $this->requestUnbind($operator);
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
          'Paladin and Drush operator identities must resolve to one bound operator record.',
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
      throw $e;
    }
  }

  /**
   * Second operator confirms a pending unbind.
   *
   * @param string $token
   *   Paladin access token. Never logged.
   * @param string $batchId
   *   Batch id from requestUnbindFromToken().
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function confirmUnbindFromToken(string $token, string $batchId): void {
    try {
      $operator = $this->introspection->activeIdentity($token);
    }
    catch (McpKillSwitchException $e) {
      $this->auditIdentityFailure(self::AUDIT_UNBIND_REFUSED, $e);
    }
    $this->confirmUnbind($batchId, $operator);
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
        $rows = $statement === NULL ? [] : $statement->fetchAll(\PDO::FETCH_ASSOC);
        if ($rows === []) {
          throw new McpKillSwitchException(
            McpKillSwitchException::UNKNOWN_BATCH,
            'No pending unbind matches that batch.',
          );
        }
        $operatorId = '';
        $requestedBy = '';
        foreach ($rows as $row) {
          if (!is_array($row)) {
            continue;
          }
          if ((int) ($row['unbind_confirm_until'] ?? 0) <= $now) {
            throw new McpKillSwitchException(
              McpKillSwitchException::CONFIRM_EXPIRED,
              'The confirm window has elapsed.',
            );
          }
          $requestedBy = (string) ($row['unbind_requested_by'] ?? '');
          $operatorId = (string) ($row['operator_id'] ?? '');
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
      throw $e;
    }
  }

  /**
   * Distinct confirmer. Same verified identity twice is refused.
   *
   * Mixed-channel identities must resolve to bound records. A shared
   * bound record is SAME_OPERATOR. Unbound mixed-channel is refused.
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
      && !$this->weakened(self::WEAKEN_SKIP_SAME_OPERATOR)
      && !$this->weakened(self::WEAKEN_SKIP_UID_MATCH)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::SAME_OPERATOR,
        'The named second person (secondary account holder) must be a distinct operator account.',
      );
    }
    if ($this->weakened(self::WEAKEN_SKIP_MIXED_CHANNEL)) {
      return;
    }
    $firstKind = $this->storageKind($first);
    $secondKind = $this->storageKind($second);
    $firstRecord = $this->recordId($firstKind, $this->storageIdentity($first));
    $secondRecord = $this->recordId($secondKind, $this->storageIdentity($second));
    if ($firstKind === '' || $secondKind === '' || $firstKind !== $secondKind) {
      if ($firstRecord === NULL || $secondRecord === NULL) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNBOUND_OPERATOR,
          'Paladin and Drush operator identities must resolve to one bound operator record.',
        );
      }
      if ($this->sameRecord($firstRecord, $secondRecord)) {
        throw new McpKillSwitchException(
          McpKillSwitchException::SAME_OPERATOR,
          'The named second person (secondary account holder) must be a distinct operator account.',
        );
      }
      return;
    }
    if ($firstRecord !== NULL && $secondRecord !== NULL
      && $this->sameRecord($firstRecord, $secondRecord)
      && !$this->weakened(self::WEAKEN_SKIP_SAME_OPERATOR)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::SAME_OPERATOR,
        'The named second person (secondary account holder) must be a distinct operator account.',
      );
    }
  }

  /**
   * Bound operator record for a kind and identity id, or NULL.
   *
   * Missing table: NULL (mixed-channel confirm then refuses).
   *
   * @param string $kind
   *   Paladin or drush.
   * @param string $id
   *   Human key or HMAC fingerprint.
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
    if (!is_array($row) || !isset($row['operator_id']) || $row['operator_id'] === '') {
      return NULL;
    }
    return (string) $row['operator_id'];
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
   * person, squat-refusal, and same-operator unbind tests can fail.
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
        if ($this->weakened(self::WEAKEN_SKIP_MIXED_CHANNEL)) {
          return;
        }
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
    if (!is_array($row) || !isset($row['uid'])) {
      return 0;
    }
    return (int) $row['uid'];
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
   * Paladin or Drush assertion only.
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
    $value = (int) ($this->configFactory->get('mcp_sentinel.settings')->get('kill_switch_confirm_window') ?? McpKillTtl::CONFIRM_WINDOW_DEFAULT);
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
    McpOperatorIdentity $first,
    McpOperatorIdentity $second,
    string $operatorId,
    bool $addedToExisting = FALSE,
  ): void {
    $this->auditLogger->logAlways($operation, [
      'actor' => $first->storageId(),
      'second_confirmer' => $second->storageId(),
      'operator_id' => $operatorId,
      'added_to_existing' => $addedToExisting,
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
    throw $e;
  }

  /**
   * Refusal audit. Never includes a token.
   */
  private function auditRefusal(
    string $operation,
    McpKillSwitchException $e,
    McpOperatorIdentity $first,
    ?McpOperatorIdentity $second,
  ): void {
    $this->auditLogger->logAlways($operation, [
      'reason_code' => $e->reasonCode,
      'actor' => $first->storageId(),
      'second_confirmer' => $second instanceof McpOperatorIdentity ? $second->storageId() : '',
      'operator_id' => '',
    ]);
  }

}
