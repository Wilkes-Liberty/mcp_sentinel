<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Access\AccessException;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\StatementInterface;
use Drupal\Core\Database\Transaction;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Enum\McpKillSelectorType;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpCarriedPrincipal;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillSwitchResult;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;

/**
 * Durable agent kill registry and two-person operator API (DEV-846).
 *
 * Storage is keyed by principal_key (iss|sub|actor), human_key
 * (iss|sub, all agents of this person), or tenant. Writes are
 * transactional. Re-killing extends block_until up to the 7 d cap.
 * Tokens never appear in audit metadata.
 */
final class McpKillSwitch implements McpKillEnforcerInterface {

  /**
   * Kill-block table.
   */
  public const TABLE = 'mcp_sentinel_kill_block';

  /**
   * Restricted permission for operator kill commands.
   */
  public const PERMISSION = 'administer agent kill switch';

  /**
   * Audit operation for a kill that is in force.
   */
  public const AUDIT_KILL = 'agent_kill';

  /**
   * Audit operation for a second-operator confirm.
   */
  public const AUDIT_CONFIRM = 'agent_kill_confirm';

  /**
   * Audit operation for TTL or confirm-window expiry.
   */
  public const AUDIT_EXPIRE = 'agent_kill_expire';

  /**
   * Audit operation for an un-kill request (still pending).
   */
  public const AUDIT_UNKILL_REQUEST = 'agent_unkill_request';

  /**
   * Audit operation for a completed un-kill.
   */
  public const AUDIT_UNKILL = 'agent_unkill';

  /**
   * Deny-row reason. Never sent to the caller as an exception code.
   */
  public const DENY_REASON = 'principal_killed';

  /**
   * Constructs the registry.
   *
   * @param \Drupal\Core\Database\Connection $connection
   *   Database connection.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Site settings (TTL and confirm window).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Clock used for TTL and expiry.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   HMAC audit chain writer.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   Sealed / carried principal for pre-commit re-checks.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextGuard $guard
   *   Same on/off switch as admit(). Pre-commit re-checks skip when
   *   disableForTest() is injected so a red run can fail.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   Invokes the unavailable-confirmer hook (the event is dispatched
   *   from that hook so this service does not depend on the event
   *   dispatcher: config-save subscribers also consult the registry).
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   Batch ids.
   */
  public function __construct(
    private readonly Connection $connection,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
    private readonly McpAuditLogger $auditLogger,
    private readonly McpPrincipalContextHolder $holder,
    private readonly McpPrincipalContextGuard $guard,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly UuidInterface $uuid,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function isKilled(string $principalKey, string $humanKey = '', string $tenant = ''): bool {
    if (!$this->tableReady()) {
      return TRUE;
    }
    $this->expireDue();
    $hashes = $this->lookupHashes($principalKey, $humanKey, $tenant);
    if ($hashes === []) {
      return FALSE;
    }
    $now = $this->time->getRequestTime();
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k', ['status', 'block_until'])
      ->condition('selector_hash', $hashes, 'IN')
      ->execute();
    if ($statement === NULL) {
      return TRUE;
    }
    while ($row = $statement->fetchAssoc()) {
      $status = McpKillBlockStatus::tryFrom((string) $row['status']);
      if ($status === NULL) {
        return TRUE;
      }
      if ($status->isBlocking((int) $row['block_until'], $now)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function isContextKilled(?McpPrincipalContext $ctx, ?McpCarriedPrincipal $carried = NULL): bool {
    [$principalKey, $humanKey, $tenant] = $this->keysOf($ctx, $carried);
    if ($principalKey === '' && $humanKey === '' && $tenant === '') {
      return FALSE;
    }
    return $this->isKilled($principalKey, $humanKey, $tenant);
  }

  /**
   * {@inheritdoc}
   */
  public function assertNotKilledAtCommit(): void {
    if (!$this->guard->required()) {
      return;
    }
    $ctx = $this->holder->get();
    $carried = $this->holder->carriedPrincipal();
    if (!$this->isContextKilled($ctx, $carried)) {
      return;
    }
    $this->writeDenialAudit($ctx, $carried);
    throw new McpPrincipalContextDeniedException(
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      McpPrincipalContextDispatcher::GENERIC_REFUSAL,
    );
  }

  /**
   * Refuses a governed write as a generic access exception.
   *
   * Used from hook_entity_presave() so entity storage rolls the
   * mutation back. The audit row still records principal_killed.
   *
   * @throws \Drupal\Core\Access\AccessException
   */
  public function assertNotKilledAtCommitOrAccess(): void {
    try {
      $this->assertNotKilledAtCommit();
    }
    catch (McpPrincipalContextDeniedException $e) {
      throw new AccessException($e->getMessage(), 0, $e);
    }
  }

  /**
   * Whether the current account may operate the kill switch.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function assertOperatorAccess(AccountInterface $account): void {
    if ((int) $account->id() === 0) {
      throw new McpKillSwitchException(
        McpKillSwitchException::MISSING_OPERATOR,
        'An operator account is required.',
      );
    }
    if (!$account->hasPermission(self::PERMISSION)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::PERMISSION_DENIED,
        'The administer agent kill switch permission is required.',
      );
    }
  }

  /**
   * Requests a kill for one or more selectors.
   *
   * A single principal_key is applied immediately. More than one
   * principal, or any human_key / tenant selector, stays pending
   * until a distinct operator confirms.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Targets. Empty is refused.
   * @param string $reason
   *   Operator reason. Must not contain a token.
   * @param string $operatorId
   *   Account id of the operator. Never a username.
   * @param int|null $ttl
   *   Requested lifetime in seconds, or NULL for the default.
   *
   * @return \Drupal\mcp_sentinel\Value\McpKillSwitchResult
   *   Applied or pending result.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function kill(array $selectors, string $reason, string $operatorId, ?int $ttl = NULL): McpKillSwitchResult {
    $this->assertWritable($operatorId, $reason);
    $selectors = $this->uniqueSelectors($selectors);
    if ($selectors === []) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_SELECTOR,
        'A kill requires at least one selector.',
      );
    }
    $ttl = McpKillTtl::resolve($ttl, $this->defaultTtl(), $this->maxTtl());
    $now = $this->time->getRequestTime();
    $blockUntil = McpKillTtl::blockUntil($now, $ttl);
    $mass = $this->isMass($selectors);
    $status = $mass ? McpKillBlockStatus::KillPending : McpKillBlockStatus::Killed;
    $batchId = $this->uuid->generate();
    $confirmUntil = $mass ? $now + $this->confirmWindow() : 0;

    $txn = $this->connection->startTransaction();
    try {
      foreach ($this->sortedSelectors($selectors) as $selector) {
        $this->writeKillRow(
          $selector,
          $status,
          $batchId,
          $blockUntil,
          $ttl,
          $reason,
          $operatorId,
          $now,
          $confirmUntil,
        );
      }
      unset($txn);
    }
    catch (\Throwable $e) {
      if ($txn instanceof Transaction) {
        $txn->rollBack();
      }
      throw $e;
    }

    $this->auditTransition(self::AUDIT_KILL, [
      'actor' => $operatorId,
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'status' => $status->value,
      'second_confirmer' => '',
      'needs_confirm' => $mass ? '1' : '0',
    ]);

    return new McpKillSwitchResult(
      $status,
      $batchId,
      $mass,
      $mass ? 0 : $blockUntil,
      $ttl,
      $selectors,
    );
  }

  /**
   * Second operator confirms a pending mass kill.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function confirm(string $batchId, string $operatorId): McpKillSwitchResult {
    $this->assertOperatorId($operatorId);
    $this->requireTable();
    $this->expireDue();
    $now = $this->time->getRequestTime();

    $txn = $this->connection->startTransaction();
    try {
      $rows = $this->lockBatch($batchId);
      if ($rows === []) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNKNOWN_BATCH,
          'No pending kill matches that batch.',
        );
      }
      $selectors = [];
      $ttl = 0;
      $blockUntil = 0;
      $reason = '';
      foreach ($rows as $row) {
        $status = McpKillBlockStatus::tryFrom((string) $row['status']);
        if ($status !== McpKillBlockStatus::KillPending) {
          throw new McpKillSwitchException(
            McpKillSwitchException::NOT_PENDING,
            'That batch is not waiting for kill confirmation.',
          );
        }
        if ((int) $row['confirm_until'] <= $now) {
          throw new McpKillSwitchException(
            McpKillSwitchException::CONFIRM_EXPIRED,
            'The confirm window has elapsed.',
          );
        }
        $this->assertDistinctOperator((string) $row['requested_by'], $operatorId);
        $selectors[] = new McpKillSelector(
          McpKillSelectorType::from((string) $row['selector_type']),
          (string) $row['selector_key'],
        );
        $ttl = (int) $row['ttl'];
        $blockUntil = (int) $row['block_until'];
        $reason = (string) $row['reason'];
      }
      $this->connection->update(self::TABLE)
        ->fields([
          'status' => McpKillBlockStatus::Killed->value,
          'confirmed_by' => $operatorId,
          'confirmed_at' => $now,
          'changed' => $now,
        ])
        ->condition('batch_id', $batchId)
        ->condition('status', McpKillBlockStatus::KillPending->value)
        ->execute();
      unset($txn);
    }
    catch (\Throwable $e) {
      if ($txn instanceof Transaction) {
        $txn->rollBack();
      }
      throw $e;
    }

    $this->auditTransition(self::AUDIT_CONFIRM, [
      'actor' => $operatorId,
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'status' => McpKillBlockStatus::Killed->value,
      'second_confirmer' => $operatorId,
    ]);

    return new McpKillSwitchResult(
      McpKillBlockStatus::Killed,
      $batchId,
      FALSE,
      $blockUntil,
      $ttl,
      $selectors,
    );
  }

  /**
   * Requests an un-kill. Always pending until a second operator confirms.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Targets currently killed.
   * @param string $reason
   *   Operator reason.
   * @param string $operatorId
   *   Account id of the operator.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function requestUnkill(array $selectors, string $reason, string $operatorId): McpKillSwitchResult {
    $this->assertWritable($operatorId, $reason);
    $selectors = $this->uniqueSelectors($selectors);
    if ($selectors === []) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_SELECTOR,
        'An un-kill requires at least one selector.',
      );
    }
    $now = $this->time->getRequestTime();
    $this->expireDue();
    $batchId = $this->uuid->generate();
    $confirmUntil = $now + $this->confirmWindow();
    $ttl = 0;
    $blockUntil = 0;

    $txn = $this->connection->startTransaction();
    try {
      foreach ($this->sortedSelectors($selectors) as $selector) {
        $row = $this->lockSelector($selector);
        if ($row === NULL) {
          throw new McpKillSwitchException(
            McpKillSwitchException::NOT_PENDING,
            'No active kill-block matches that selector.',
          );
        }
        $status = McpKillBlockStatus::tryFrom((string) $row['status']);
        if ($status !== McpKillBlockStatus::Killed
          && $status !== McpKillBlockStatus::UnkillPending) {
          throw new McpKillSwitchException(
            McpKillSwitchException::NOT_PENDING,
            'That selector is not currently killed.',
          );
        }
        if ((int) $row['block_until'] <= $now) {
          throw new McpKillSwitchException(
            McpKillSwitchException::NOT_PENDING,
            'That kill-block has already expired.',
          );
        }
        $ttl = (int) $row['ttl'];
        $blockUntil = (int) $row['block_until'];
        $this->connection->update(self::TABLE)
          ->fields([
            'status' => McpKillBlockStatus::UnkillPending->value,
            'unkill_batch_id' => $batchId,
            'unkill_requested_by' => $operatorId,
            'unkill_requested_at' => $now,
            'unkill_confirm_until' => $confirmUntil,
            'changed' => $now,
          ])
          ->condition('selector_hash', $selector->hash())
          ->execute();
      }
      unset($txn);
    }
    catch (\Throwable $e) {
      if ($txn instanceof Transaction) {
        $txn->rollBack();
      }
      throw $e;
    }

    $this->auditTransition(self::AUDIT_UNKILL_REQUEST, [
      'actor' => $operatorId,
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'status' => McpKillBlockStatus::UnkillPending->value,
      'second_confirmer' => '',
      'needs_confirm' => '1',
    ]);

    return new McpKillSwitchResult(
      McpKillBlockStatus::UnkillPending,
      $batchId,
      TRUE,
      $blockUntil,
      $ttl,
      $selectors,
    );
  }

  /**
   * Second operator confirms an un-kill.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function confirmUnkill(string $batchId, string $operatorId): McpKillSwitchResult {
    $this->assertOperatorId($operatorId);
    $this->requireTable();
    $this->expireDue();
    $now = $this->time->getRequestTime();

    $txn = $this->connection->startTransaction();
    try {
      $rows = $this->lockUnkillBatch($batchId);
      if ($rows === []) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNKNOWN_BATCH,
          'No pending un-kill matches that batch.',
        );
      }
      $selectors = [];
      $ttl = 0;
      $blockUntil = 0;
      $reason = '';
      foreach ($rows as $row) {
        $status = McpKillBlockStatus::tryFrom((string) $row['status']);
        if ($status !== McpKillBlockStatus::UnkillPending) {
          throw new McpKillSwitchException(
            McpKillSwitchException::NOT_PENDING,
            'That batch is not waiting for un-kill confirmation.',
          );
        }
        if ((int) $row['unkill_confirm_until'] <= $now) {
          throw new McpKillSwitchException(
            McpKillSwitchException::CONFIRM_EXPIRED,
            'The confirm window has elapsed.',
          );
        }
        $this->assertDistinctOperator(
          (string) $row['unkill_requested_by'],
          $operatorId,
        );
        $selectors[] = new McpKillSelector(
          McpKillSelectorType::from((string) $row['selector_type']),
          (string) $row['selector_key'],
        );
        $ttl = (int) $row['ttl'];
        $blockUntil = (int) $row['block_until'];
        $reason = (string) $row['reason'];
      }
      $this->connection->update(self::TABLE)
        ->fields([
          'status' => McpKillBlockStatus::Expired->value,
          'unkill_confirmed_by' => $operatorId,
          'unkill_confirmed_at' => $now,
          'changed' => $now,
        ])
        ->condition('unkill_batch_id', $batchId)
        ->condition('status', McpKillBlockStatus::UnkillPending->value)
        ->execute();
      unset($txn);
    }
    catch (\Throwable $e) {
      if ($txn instanceof Transaction) {
        $txn->rollBack();
      }
      throw $e;
    }

    $this->auditTransition(self::AUDIT_UNKILL, [
      'actor' => $operatorId,
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'status' => McpKillBlockStatus::Expired->value,
      'second_confirmer' => $operatorId,
    ]);

    return new McpKillSwitchResult(
      McpKillBlockStatus::Expired,
      $batchId,
      FALSE,
      0,
      $ttl,
      $selectors,
    );
  }

  /**
   * Current row for a selector, after applying due expiry.
   *
   * @return array<string, mixed>|null
   *   Associative row, or NULL when absent / not blocking.
   */
  public function status(McpKillSelector $selector): ?array {
    if (!$this->tableReady()) {
      return NULL;
    }
    $this->expireDue();
    $row = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('selector_hash', $selector->hash())
      ->range(0, 1)
      ->execute()
      ?->fetchAssoc();
    return is_array($row) ? $row : NULL;
  }

  /**
   * Expires due kill-blocks and elapsed confirm windows.
   *
   * @return int
   *   Rows transitioned.
   */
  public function expireDue(): int {
    if (!$this->tableReady()) {
      return 0;
    }
    $now = $this->time->getRequestTime();
    $changed = 0;
    $changed += $this->expireBlocking($now);
    $changed += $this->expirePendingKills($now);
    $changed += $this->expirePendingUnkillWindows($now);
    return $changed;
  }

  /**
   * Writes a denied_access row for a killed principal.
   */
  public function writeDenialAudit(?McpPrincipalContext $ctx, ?McpCarriedPrincipal $carried): void {
    $empty = new McpPrincipalContext('', '', '', '', [], '', [], FALSE);
    $meta = McpPrincipalContextDispatcher::denialAuditMetadata(
      'mcp_kill_switch',
      self::DENY_REASON,
      $ctx ?? $empty,
    );
    if ($carried !== NULL) {
      if ($carried->principalKey !== '') {
        $meta['principal_key'] = $carried->principalKey;
      }
      if ($carried->humanKey !== '') {
        $meta['human_key'] = $carried->humanKey;
      }
      if ($carried->tenant !== '') {
        $meta['tenant'] = $carried->tenant;
      }
    }
    $this->auditLogger->logSurvivingRollback('denied_access', $meta, TRUE);
  }

  /**
   * Unique selectors, preserving order.
   *
   * @param array $selectors
   *   Input. Each value must be an McpKillSelector.
   *
   * @return list<\Drupal\mcp_sentinel\Value\McpKillSelector>
   *   Deduped list.
   */
  private function uniqueSelectors(array $selectors): array {
    $seen = [];
    $out = [];
    foreach ($selectors as $selector) {
      if (!$selector instanceof McpKillSelector) {
        throw new McpKillSwitchException(
          McpKillSwitchException::INVALID_SELECTOR,
          'Each kill target must be an McpKillSelector.',
        );
      }
      $hash = $selector->hash();
      if (isset($seen[$hash])) {
        continue;
      }
      $seen[$hash] = TRUE;
      $out[] = $selector;
    }
    return $out;
  }

  /**
   * Selectors ordered by hash so row locks cannot deadlock.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Unique selectors.
   *
   * @return list<\Drupal\mcp_sentinel\Value\McpKillSelector>
   *   Sorted copy.
   */
  private function sortedSelectors(array $selectors): array {
    $copy = $selectors;
    usort(
      $copy,
      static fn (McpKillSelector $a, McpKillSelector $b): int => strcmp($a->hash(), $b->hash()),
    );
    return $copy;
  }

  /**
   * Whether this request is a mass kill.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Unique selectors.
   */
  private function isMass(array $selectors): bool {
    if (count($selectors) > 1) {
      return TRUE;
    }
    $first = $selectors[0];
    return $first->type->isMassByItself();
  }

  /**
   * Inserts or extends one kill row.
   */
  private function writeKillRow(
    McpKillSelector $selector,
    McpKillBlockStatus $status,
    string $batchId,
    int $blockUntil,
    int $ttl,
    string $reason,
    string $operatorId,
    int $now,
    int $confirmUntil,
  ): void {
    $existing = $this->lockSelector($selector);
    if ($existing !== NULL) {
      $existingStatus = McpKillBlockStatus::tryFrom((string) $existing['status']);
      $newUntil = max((int) $existing['block_until'], $blockUntil);
      $cap = $now + $this->maxTtl();
      $newUntil = min($newUntil, $cap);
      $fields = [
        'status' => $status->value,
        'batch_id' => $batchId,
        'block_until' => $newUntil,
        'ttl' => $ttl,
        'reason' => $reason,
        'requested_by' => $operatorId,
        'requested_at' => $now,
        'confirm_until' => $confirmUntil,
        'changed' => $now,
      ];
      if ($existingStatus === McpKillBlockStatus::Killed
        && $status === McpKillBlockStatus::Killed) {
        $fields['confirmed_by'] = (string) $existing['confirmed_by'];
        $fields['confirmed_at'] = (int) $existing['confirmed_at'];
      }
      else {
        $fields['confirmed_by'] = '';
        $fields['confirmed_at'] = 0;
      }
      $this->connection->update(self::TABLE)
        ->fields($fields)
        ->condition('selector_hash', $selector->hash())
        ->execute();
      return;
    }
    $this->connection->insert(self::TABLE)
      ->fields([
        'selector_hash' => $selector->hash(),
        'selector_type' => $selector->type->value,
        'selector_key' => $selector->key,
        'status' => $status->value,
        'batch_id' => $batchId,
        'block_until' => $blockUntil,
        'ttl' => $ttl,
        'reason' => $reason,
        'requested_by' => $operatorId,
        'requested_at' => $now,
        'confirmed_by' => '',
        'confirmed_at' => 0,
        'confirm_until' => $confirmUntil,
        'unkill_batch_id' => '',
        'unkill_requested_by' => '',
        'unkill_requested_at' => 0,
        'unkill_confirm_until' => 0,
        'unkill_confirmed_by' => '',
        'unkill_confirmed_at' => 0,
        'changed' => $now,
      ])
      ->execute();
  }

  /**
   * Locks one selector row.
   *
   * @return array<string, mixed>|null
   *   Row or NULL.
   */
  private function lockSelector(McpKillSelector $selector): ?array {
    $this->requireTable();
    $query = $this->connection->select(self::TABLE, 'k');
    $query->fields('k');
    $query->condition('selector_hash', $selector->hash());
    $query->forUpdate();
    $row = $query->execute()?->fetchAssoc();
    return is_array($row) ? $row : NULL;
  }

  /**
   * Locks every kill-pending row in a batch.
   *
   * @return list<array<string, mixed>>
   *   Rows.
   */
  private function lockBatch(string $batchId): array {
    if ($batchId === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNKNOWN_BATCH,
        'A batch id is required.',
      );
    }
    $query = $this->connection->select(self::TABLE, 'k');
    $query->fields('k');
    $query->condition('batch_id', $batchId);
    $query->orderBy('selector_hash');
    $query->forUpdate();
    $statement = $query->execute();
    if ($statement === NULL) {
      throw new McpKillSwitchException(
        McpKillSwitchException::TABLE_MISSING,
        'The kill-block table could not be queried.',
      );
    }
    return $this->assocRows($statement);
  }

  /**
   * Locks every unkill-pending row in a batch.
   *
   * @return list<array<string, mixed>>
   *   Rows.
   */
  private function lockUnkillBatch(string $batchId): array {
    if ($batchId === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNKNOWN_BATCH,
        'A batch id is required.',
      );
    }
    $query = $this->connection->select(self::TABLE, 'k');
    $query->fields('k');
    $query->condition('unkill_batch_id', $batchId);
    $query->orderBy('selector_hash');
    $query->forUpdate();
    $statement = $query->execute();
    if ($statement === NULL) {
      throw new McpKillSwitchException(
        McpKillSwitchException::TABLE_MISSING,
        'The kill-block table could not be queried.',
      );
    }
    return $this->assocRows($statement);
  }

  /**
   * Fetches every row as an associative array.
   *
   * @param \Drupal\Core\Database\StatementInterface $statement
   *   Query result.
   *
   * @return list<array<string, mixed>>
   *   Rows.
   */
  private function assocRows(StatementInterface $statement): array {
    $rows = [];
    while ($row = $statement->fetchAssoc()) {
      $rows[] = $row;
    }
    return $rows;
  }

  /**
   * Expires killed rows whose block_until has passed.
   */
  private function expireBlocking(int $now): int {
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', [
        McpKillBlockStatus::Killed->value,
        McpKillBlockStatus::UnkillPending->value,
      ], 'IN')
      ->condition('block_until', $now, '<=')
      ->execute();
    if ($statement === NULL) {
      return 0;
    }
    $count = 0;
    foreach ($this->assocRows($statement) as $row) {
      $this->markExpired($row, 'ttl', $now);
      $count++;
    }
    return $count;
  }

  /**
   * Drops pending mass kills whose confirm window elapsed.
   *
   * Does not apply the kill. Invokes the unavailable-confirmer hook
   * with no fallback that would let a single operator proceed.
   */
  private function expirePendingKills(int $now): int {
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', McpKillBlockStatus::KillPending->value)
      ->condition('confirm_until', $now, '<=')
      ->condition('confirm_until', 0, '>')
      ->execute();
    if ($statement === NULL) {
      return 0;
    }
    $count = 0;
    foreach ($this->assocRows($statement) as $row) {
      $this->notifyUnavailableConfirmer($row, 'kill');
      $this->markExpired($row, 'confirm_window', $now);
      $count++;
    }
    return $count;
  }

  /**
   * Restores killed (still blocking) when an un-kill confirm window elapses.
   *
   * The two-person un-kill does not complete. The block stays in force.
   */
  private function expirePendingUnkillWindows(int $now): int {
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', McpKillBlockStatus::UnkillPending->value)
      ->condition('unkill_confirm_until', $now, '<=')
      ->condition('unkill_confirm_until', 0, '>')
      ->condition('block_until', $now, '>')
      ->execute();
    if ($statement === NULL) {
      return 0;
    }
    $count = 0;
    foreach ($this->assocRows($statement) as $row) {
      $this->notifyUnavailableConfirmer($row, 'unkill');
      $this->connection->update(self::TABLE)
        ->fields([
          'status' => McpKillBlockStatus::Killed->value,
          'unkill_batch_id' => '',
          'unkill_confirm_until' => 0,
          'changed' => $now,
        ])
        ->condition('selector_hash', (string) $row['selector_hash'])
        ->execute();
      $this->auditTransition(self::AUDIT_EXPIRE, [
        'actor' => '',
        'target_selector' => (string) $row['selector_type'] . ':' . (string) $row['selector_key'],
        'reason' => 'unkill_confirm_window',
        'ttl' => (string) $row['ttl'],
        'block_until' => (string) $row['block_until'],
        'batch_id' => (string) $row['unkill_batch_id'],
        'status' => McpKillBlockStatus::Killed->value,
        'second_confirmer' => '',
      ]);
      $count++;
    }
    return $count;
  }

  /**
   * Marks a row expired and writes the expire audit row.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   * @param string $why
   *   Expiry cause recorded on the audit row (ttl or confirm_window).
   * @param int $now
   *   Current request time.
   */
  private function markExpired(array $row, string $why, int $now): void {
    $this->connection->update(self::TABLE)
      ->fields([
        'status' => McpKillBlockStatus::Expired->value,
        'changed' => $now,
      ])
      ->condition('selector_hash', (string) $row['selector_hash'])
      ->execute();
    $this->auditTransition(self::AUDIT_EXPIRE, [
      'actor' => '',
      'target_selector' => (string) $row['selector_type'] . ':' . (string) $row['selector_key'],
      'reason' => $why,
      'ttl' => (string) $row['ttl'],
      'block_until' => (string) $row['block_until'],
      'batch_id' => (string) ($row['batch_id'] ?? ''),
      'status' => McpKillBlockStatus::Expired->value,
      'second_confirmer' => (string) ($row['confirmed_by'] ?? ''),
    ]);
  }

  /**
   * Operator-decision hook. Does not apply or skip the two-person rule.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   * @param string $transition
   *   Kill or unkill.
   */
  private function notifyUnavailableConfirmer(array $row, string $transition): void {
    $selector = new McpKillSelector(
      McpKillSelectorType::from((string) $row['selector_type']),
      (string) $row['selector_key'],
    );
    $first = $transition === 'unkill'
      ? (string) $row['unkill_requested_by']
      : (string) $row['requested_by'];
    $batchId = $transition === 'unkill'
      ? (string) $row['unkill_batch_id']
      : (string) $row['batch_id'];
    $context = [
      'batch_id' => $batchId,
      'transition' => $transition,
      'first_operator_id' => $first,
      'selector_type' => $selector->type->value,
      'selector_key' => $selector->key,
      // @todo DEV-846 operator decision: when the named second person
      //   (secondary account holder) is unavailable, the two-person
      //   rule must not be weakened. This hook is the decision point.
      //   There is no timeout-to-single-operator and no break-glass skip.
    ];
    $this->moduleHandler->invokeAll(
      'mcp_sentinel_kill_unavailable_confirmer',
      [$context],
    );
  }

  /**
   * Audit metadata for a kill-switch transition. Never includes tokens.
   *
   * @param string $operation
   *   Audit operation name.
   * @param array<string, string> $metadata
   *   Actor, selector, reason, TTL, confirmer.
   */
  private function auditTransition(string $operation, array $metadata): void {
    $this->auditLogger->logAlways($operation, $metadata);
  }

  /**
   * Comma-separated type:key list for the audit row.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Selectors.
   */
  private function selectorList(array $selectors): string {
    $parts = [];
    foreach ($selectors as $selector) {
      $parts[] = $selector->type->value . ':' . $selector->key;
    }
    return implode(',', $parts);
  }

  /**
   * Lookup hashes for the three key kinds.
   *
   * @return list<string>
   *   Hashes to query.
   */
  private function lookupHashes(string $principalKey, string $humanKey, string $tenant): array {
    $hashes = [];
    if ($principalKey !== '') {
      $hashes[] = (new McpKillSelector(McpKillSelectorType::PrincipalKey, $principalKey))->hash();
    }
    if ($humanKey !== '') {
      $hashes[] = (new McpKillSelector(McpKillSelectorType::HumanKey, $humanKey))->hash();
    }
    if ($tenant !== '') {
      $hashes[] = (new McpKillSelector(McpKillSelectorType::Tenant, $tenant))->hash();
    }
    return $hashes;
  }

  /**
   * Principal / human / tenant keys from a sealed or carried principal.
   *
   * @return array{0: string, 1: string, 2: string}
   *   principalKey, humanKey, tenant.
   */
  private function keysOf(?McpPrincipalContext $ctx, ?McpCarriedPrincipal $carried): array {
    $principalKey = '';
    $humanKey = '';
    $tenant = '';
    if ($ctx !== NULL) {
      try {
        $keys = McpPrincipalKey::fromClaims($ctx->keyClaims());
        $principalKey = $keys['principalKey'];
        $humanKey = $keys['humanKey'];
      }
      catch (McpPrincipalKeyException) {
      }
      $tenant = $ctx->tenant();
    }
    if ($carried !== NULL) {
      if ($principalKey === '') {
        $principalKey = $carried->principalKey;
      }
      if ($humanKey === '') {
        $humanKey = $carried->humanKey;
      }
      if ($tenant === '') {
        $tenant = $carried->tenant;
      }
    }
    return [$principalKey, $humanKey, $tenant];
  }

  /**
   * Configured default TTL.
   */
  private function defaultTtl(): int {
    $value = (int) ($this->configFactory->get('mcp_sentinel.settings')->get('kill_switch_default_ttl') ?? McpKillTtl::DEFAULT);
    return $value > 0 ? $value : McpKillTtl::DEFAULT;
  }

  /**
   * Configured maximum TTL.
   */
  private function maxTtl(): int {
    $value = (int) ($this->configFactory->get('mcp_sentinel.settings')->get('kill_switch_max_ttl') ?? McpKillTtl::MAX);
    return $value > 0 ? $value : McpKillTtl::MAX;
  }

  /**
   * Configured confirm window.
   */
  private function confirmWindow(): int {
    $value = (int) ($this->configFactory->get('mcp_sentinel.settings')->get('kill_switch_confirm_window') ?? McpKillTtl::CONFIRM_WINDOW_DEFAULT);
    return $value > 0 ? $value : McpKillTtl::CONFIRM_WINDOW_DEFAULT;
  }

  /**
   * Operator id and reason gates shared by mutating commands.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertWritable(string $operatorId, string $reason): void {
    $this->assertOperatorId($operatorId);
    $this->assertReason($reason);
    $this->requireTable();
  }

  /**
   * Non-anonymous operator account id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertOperatorId(string $operatorId): void {
    if ($operatorId === '' || $operatorId === '0') {
      throw new McpKillSwitchException(
        McpKillSwitchException::MISSING_OPERATOR,
        'An operator account is required.',
      );
    }
  }

  /**
   * Distinct confirmer. Same account twice is refused.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertDistinctOperator(string $first, string $second): void {
    if ($first === '' || $second === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::SAME_OPERATOR,
        'The named second person (secondary account holder) must be a distinct operator account.',
      );
    }
    $same = strlen($first) === strlen($second) && hash_equals($first, $second);
    if ($same) {
      throw new McpKillSwitchException(
        McpKillSwitchException::SAME_OPERATOR,
        'The named second person (secondary account holder) must be a distinct operator account.',
      );
    }
  }

  /**
   * Reason is required and must not look like a bearer token.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertReason(string $reason): void {
    $reason = trim($reason);
    if ($reason === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_REASON,
        'A kill reason is required.',
      );
    }
    if (str_starts_with($reason, 'eyJ') || str_contains($reason, 'Bearer ')) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_REASON,
        'Kill metadata must not include tokens.',
      );
    }
  }

  /**
   * Fail closed when the table is not installed.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function requireTable(): void {
    if (!$this->tableReady()) {
      throw new McpKillSwitchException(
        McpKillSwitchException::TABLE_MISSING,
        'The kill-block table is not installed.',
      );
    }
  }

  /**
   * Whether the kill-block table exists.
   */
  private function tableReady(): bool {
    return $this->connection->schema()->tableExists(self::TABLE);
  }

}
