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
use Drupal\Core\Site\Settings;
use Drupal\Core\State\StateInterface;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Enum\McpKillSelectorType;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpCarriedPrincipal;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillSwitchResult;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Psr\Log\LoggerInterface;

/**
 * Durable agent kill registry and two-person operator API.
 *
 * DEV-846 and DEV-985. Storage is keyed by principal_key
 * (iss|sub|actor), human_key (iss|sub, all agents of this person),
 * or tenant. Writes are transactional. A killed row is never
 * downgraded to kill_pending.
 * Re-killing stays killed and may extend block_until up to 7 d
 * from now. A person-wide or tenant-wide stop freezes immediately:
 * in-scope agents are refused before a second operator confirms.
 * The confirm window never lifts that freeze; it escalates through
 * the unavailable-confirmer hook. Lifting a mass freeze always
 * takes two operators. Two-person confirm binds Paladin iss|sub
 * and mapped Drupal uids, never the OS user. Tokens never appear
 * in audit metadata. expireDue() runs from hook_cron, not admit()
 * or save.
 * Queued webhook deliveries in scope are held on any stop;
 * lifting never releases them.
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
   * Audit operation for a kill that is in force (single agent).
   */
  public const AUDIT_KILL = 'agent_kill';

  /**
   * Audit operation for an immediate mass freeze.
   */
  public const AUDIT_FREEZE = 'agent_kill_freeze';

  /**
   * Audit operation for a second-operator confirm.
   */
  public const AUDIT_CONFIRM = 'agent_kill_confirm';

  /**
   * Audit operation for a second-operator TTL extend.
   */
  public const AUDIT_EXTEND = 'agent_kill_extend';

  /**
   * Audit operation for a second-operator lift of a mass freeze.
   */
  public const AUDIT_LIFT = 'agent_kill_lift';

  /**
   * Audit operation for an unconfirmed-freeze escalation.
   */
  public const AUDIT_ESCALATE = 'agent_kill_escalate';

  /**
   * Audit operation for break-glass keep, extend, or lift.
   */
  public const AUDIT_BREAK_GLASS = 'agent_kill_break_glass';

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
   * Audit operation for a refused operator action.
   */
  public const AUDIT_REFUSE = 'agent_kill_refuse';

  /**
   * Deny-row reason. Never sent to the caller as an exception code.
   */
  public const DENY_REASON = 'principal_killed';

  /**
   * State key for freezes already recorded as kept by update 10037.
   */
  public const STATE_UPGRADE_KEPT = 'mcp_sentinel.upgrade_10037_kept';

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
   * @param \Drupal\mcp_sentinel\Service\McpOperatorBinding $bindings
   *   Paladin-to-Drupal-account bindings for distinct-operator confirm.
   * @param \Drupal\mcp_sentinel\Service\McpWebhookQueueManager $webhookQueue
   *   Holds queued webhook deliveries in the stopped scope.
   * @param \Drupal\Core\Site\Settings $settings
   *   Settings.php pin for the break-glass operator.
   * @param \Drupal\Core\State\StateInterface $state
   *   Durable marker for freezes already kept by update 10037.
   * @param \Psr\Log\LoggerInterface $logger
   *   Watchdog channel for notify failures after a claim or expire.
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
    private readonly McpOperatorBinding $bindings,
    private readonly McpWebhookQueueManager $webhookQueue,
    private readonly Settings $settings,
    private readonly StateInterface $state,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function isKilled(string $principalKey, string $humanKey = '', string $tenant = ''): bool {
    if (!$this->tableReady()) {
      return TRUE;
    }
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
    while ($raw = $statement->fetchAssoc()) {
      $row = $this->assocRow($raw);
      if ($row === NULL) {
        return TRUE;
      }
      $status = McpKillBlockStatus::tryFrom($this->rowString($row, 'status'));
      if ($status === NULL) {
        return TRUE;
      }
      $blockUntil = $this->rowBlockUntil($row);
      if ($blockUntil === NULL) {
        return TRUE;
      }
      if ($status->isBlocking($blockUntil, $now)) {
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
    if ($account->isAnonymous()) {
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
   * A single principal_key is applied immediately as killed. More
   * than one principal, or any human_key / tenant selector, freezes
   * immediately (in-scope agents are refused) and still needs a
   * distinct operator to confirm, extend, or lift.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Targets. Empty is refused.
   * @param string $reason
   *   Operator reason. Must not contain a token.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Verified Paladin identity. Never a Drupal uid.
   * @param int|null $ttl
   *   Requested lifetime in seconds, or NULL for the default.
   *
   * @return \Drupal\mcp_sentinel\Value\McpKillSwitchResult
   *   Applied or pending result.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function kill(array $selectors, string $reason, McpOperatorIdentity $operator, ?int $ttl = NULL): McpKillSwitchResult {
    $this->assertWritable($operator, $reason);
    $selectors = $this->uniqueSelectors($selectors);
    if ($selectors === []) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_SELECTOR,
        'A kill requires at least one selector.',
      );
    }
    $ttl = $this->resolveTtl($ttl);
    $now = $this->time->getRequestTime();
    $blockUntil = McpKillTtl::blockUntil($now, $ttl);
    $mass = $this->isMass($selectors);
    $status = $mass ? McpKillBlockStatus::KillPending : McpKillBlockStatus::Killed;
    $batchId = $this->uuid->generate();
    $confirmUntil = $mass ? $now + $this->confirmWindow() : 0;
    $operatorId = $operator->storageId();

    $txn = $this->connection->startTransaction();
    $anyPending = FALSE;
    try {
      foreach ($this->sortedSelectors($selectors) as $selector) {
        $stored = $this->writeKillRow(
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
        if ($stored === McpKillBlockStatus::KillPending) {
          $anyPending = TRUE;
        }
      }
      $this->webhookQueue->holdMatching($selectors, $operator, $batchId);
      unset($txn);
    }
    catch (\Throwable $e) {
      if ($txn instanceof Transaction) {
        $txn->rollBack();
      }
      throw $e;
    }

    // A mass request whose every target was already blocking did not
    // open a confirm batch. Reporting kill_pending here would invite
    // a confirm of a batch that has no rows.
    $resultStatus = $anyPending ? McpKillBlockStatus::KillPending : McpKillBlockStatus::Killed;
    $resultBatch = ($mass && !$anyPending) ? '' : $batchId;
    $auditOp = $anyPending ? self::AUDIT_FREEZE : self::AUDIT_KILL;
    $this->auditTransition($auditOp, [
      'actor' => $operatorId,
      'scope' => $this->selectorList($selectors),
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'correlation_id' => $batchId,
      'status' => $resultStatus->value,
      'second_confirmer' => '',
      'needs_confirm' => $anyPending ? '1' : '0',
      'timestamp' => (string) $now,
    ]);

    return new McpKillSwitchResult(
      $resultStatus,
      $resultBatch,
      $anyPending,
      $blockUntil,
      $ttl,
      $selectors,
    );
  }

  /**
   * Second operator confirms a pending mass kill.
   *
   * @param string $batchId
   *   Batch id from a pending mass kill.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Distinct verified confirmer.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function confirm(string $batchId, McpOperatorIdentity $operator): McpKillSwitchResult {
    return $this->confirmFreeze($batchId, $operator, FALSE);
  }

  /**
   * Confirms an unconfirmed mass freeze.
   */
  private function confirmFreeze(
    string $batchId,
    McpOperatorIdentity $operator,
    bool $breakGlass,
  ): McpKillSwitchResult {
    $this->assertOperatorIdentity($operator);
    $this->requireTable();
    $operatorId = $operator->storageId();
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
          $this->refuse(
            McpKillSwitchException::NOT_PENDING,
            'That batch is not waiting for kill confirmation.',
            $operatorId,
            $batchId,
          );
        }
        $this->assertDistinctOperator((string) $row['requested_by'], $operatorId, $batchId);
        $selectors[] = new McpKillSelector(
          McpKillSelectorType::from((string) $row['selector_type']),
          (string) $row['selector_key'],
        );
        $ttl = (int) $row['ttl'];
        $blockUntil = (int) $row['block_until'];
        $reason = (string) $row['reason'];
      }
      $blockUntil = min(
        $now + McpKillTtl::MAX,
        max($blockUntil, McpKillTtl::blockUntil($now, $ttl)),
      );
      $this->connection->update(self::TABLE)
        ->fields([
          'status' => McpKillBlockStatus::Killed->value,
          'confirmed_by' => $operatorId,
          'confirmed_at' => $now,
          'block_until' => $blockUntil,
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

    $this->clearUpgradePendingKeptForBatch($batchId);

    $this->auditConfirmOrBreakGlass(
      $breakGlass,
      McpKillBreakGlassAction::Keep,
      $operatorId,
      $selectors,
      $reason,
      $ttl,
      $blockUntil,
      $batchId,
      $now,
    );

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
   * Second operator extends a mass freeze, capped at 7 days from now.
   *
   * @param string $batchId
   *   Batch id from a mass freeze.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Distinct verified confirmer.
   * @param int|null $ttl
   *   Requested lifetime in seconds, or NULL for the default.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function extend(string $batchId, McpOperatorIdentity $operator, ?int $ttl = NULL): McpKillSwitchResult {
    return $this->extendFreeze($batchId, $operator, $ttl, FALSE);
  }

  /**
   * Second operator lifts an unconfirmed mass freeze.
   *
   * Confirmed kills still use requestUnkill() plus confirmUnkill().
   * Held side effects stay held.
   *
   * @param string $batchId
   *   Batch id from a mass freeze.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Distinct verified confirmer.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function lift(string $batchId, McpOperatorIdentity $operator): McpKillSwitchResult {
    return $this->liftFreeze($batchId, $operator, FALSE);
  }

  /**
   * Break-glass keep, extend, or lift when the second person is unreachable.
   *
   * Still requires a distinct verified operator. Audited as
   * break-glass use, not as a confirm/extend/lift row.
   *
   * @param string $batchId
   *   Batch id from a mass freeze.
   * @param \Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction $action
   *   Keep, extend, or lift.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Distinct verified break-glass operator.
   * @param int|null $ttl
   *   Requested lifetime when extending.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function breakGlass(
    string $batchId,
    McpKillBreakGlassAction $action,
    McpOperatorIdentity $operator,
    ?int $ttl = NULL,
  ): McpKillSwitchResult {
    $this->assertBreakGlassIdentity($operator);
    return match ($action) {
      McpKillBreakGlassAction::Keep => $this->confirmFreeze($batchId, $operator, TRUE),
      McpKillBreakGlassAction::Extend => $this->extendFreeze($batchId, $operator, $ttl, TRUE),
      McpKillBreakGlassAction::Lift => $this->liftFreeze($batchId, $operator, TRUE),
    };
  }

  /**
   * Active kill-block rows for the Drupal-side UI (DEV-925).
   *
   * @return list<array<string, mixed>>
   *   Associative rows that currently refuse.
   */
  public function listActiveBlocks(): array {
    if (!$this->tableReady()) {
      return [];
    }
    $now = $this->time->getRequestTime();
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', [
        McpKillBlockStatus::Killed->value,
        McpKillBlockStatus::KillPending->value,
        McpKillBlockStatus::UnkillPending->value,
      ], 'IN')
      ->orderBy('selector_hash')
      ->execute();
    if ($statement === NULL) {
      return [];
    }
    $active = [];
    foreach ($this->assocRows($statement) as $row) {
      $status = McpKillBlockStatus::tryFrom((string) $row['status']);
      if ($status === NULL) {
        continue;
      }
      if ($status === McpKillBlockStatus::KillPending) {
        $active[] = $row;
        continue;
      }
      $blockUntil = $this->rowBlockUntil($row);
      if ($blockUntil === NULL || $status->isBlocking($blockUntil, $now)) {
        $active[] = $row;
      }
    }
    return $active;
  }

  /**
   * Requests an un-kill. Always pending until a second operator confirms.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Targets currently killed.
   * @param string $reason
   *   Operator reason.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Verified Paladin identity.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function requestUnkill(array $selectors, string $reason, McpOperatorIdentity $operator): McpKillSwitchResult {
    $this->assertWritable($operator, $reason);
    $selectors = $this->uniqueSelectors($selectors);
    if ($selectors === []) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_SELECTOR,
        'An un-kill requires at least one selector.',
      );
    }
    $now = $this->time->getRequestTime();
    $operatorId = $operator->storageId();
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
        if ($status === McpKillBlockStatus::KillPending) {
          throw new McpKillSwitchException(
            McpKillSwitchException::INVALID_ACTION,
            'Un-kill a confirmed stop. Lift an unconfirmed freeze with mcp-sentinel:kill-lift.',
          );
        }
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
   * @param string $batchId
   *   Batch id from a pending un-kill.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Distinct verified confirmer.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function confirmUnkill(string $batchId, McpOperatorIdentity $operator): McpKillSwitchResult {
    $this->assertOperatorIdentity($operator);
    $this->requireTable();
    $operatorId = $operator->storageId();
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
          $this->refuse(
            McpKillSwitchException::NOT_PENDING,
            'That batch is not waiting for un-kill confirmation.',
            $operatorId,
            $batchId,
          );
        }
        if ((int) $row['unkill_confirm_until'] <= $now) {
          $this->refuse(
            McpKillSwitchException::CONFIRM_EXPIRED,
            'The confirm window has elapsed.',
            $operatorId,
            $batchId,
          );
        }
        $this->assertDistinctOperator(
          (string) $row['unkill_requested_by'],
          $operatorId,
          $batchId,
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
   * Current row for a selector. Does not write expiry.
   *
   * @return array<string, mixed>|null
   *   Associative row, or NULL when absent.
   */
  public function status(McpKillSelector $selector): ?array {
    if (!$this->tableReady()) {
      return NULL;
    }
    $row = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('selector_hash', $selector->hash())
      ->range(0, 1)
      ->execute()
      ?->fetchAssoc();
    return is_array($row) ? $row : NULL;
  }

  /**
   * Expires due kill-blocks and escalates unconfirmed freezes.
   *
   * Called from hook_cron. admit() and governed saves treat an
   * elapsed block_until as not blocking without writing. An
   * elapsed confirm window never lifts a mass freeze.
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
    $changed += $this->escalateUnconfirmedFreezes($now);
    $changed += $this->expirePendingUnkillWindows($now);
    return $changed;
  }

  /**
   * Upgrade helper: keep Drush-requested freezes and revert Drush unkills.
   *
   * Unconfirmed freezes stay frozen. An audit row is written per
   * freeze. Pending unkills revert to killed. The unavailable-
   * confirmer hook is not invoked from this path.
   *
   * @return int
   *   Rows audited or reverted.
   */
  public function keepDrushRequestedPendingAndRevertUnkill(): int {
    if (!$this->tableReady()) {
      return 0;
    }
    $now = $this->time->getRequestTime();
    $changed = 0;
    $pending = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', McpKillBlockStatus::KillPending->value)
      ->condition('requested_by', 'drush:%', 'LIKE')
      ->execute();
    if ($pending !== NULL) {
      foreach ($this->assocRows($pending) as $row) {
        $target = $this->rowString($row, 'selector_type')
          . ':' . $this->rowString($row, 'selector_key');
        $batchId = $this->rowString($row, 'batch_id');
        if ($this->upgradePendingAlreadyKept($batchId, $target)) {
          continue;
        }
        $txn = $this->connection->startTransaction();
        try {
          $this->auditLogger->logAlways('operator_binding_upgrade_pending_kept', [
            'actor' => $this->rowString($row, 'requested_by'),
            'target_selector' => $target,
            'batch_id' => $batchId,
            'status' => McpKillBlockStatus::KillPending->value,
          ]);
          $this->markUpgradePendingKept($batchId, $target);
          unset($txn);
        }
        catch (\Throwable $e) {
          if ($txn instanceof Transaction) {
            $txn->rollBack();
          }
          throw $e;
        }
        $changed++;
      }
    }
    $unkill = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', McpKillBlockStatus::UnkillPending->value)
      ->condition('unkill_requested_by', 'drush:%', 'LIKE')
      ->execute();
    if ($unkill !== NULL) {
      foreach ($this->assocRows($unkill) as $row) {
        $this->revertExpiredUnkill($row, $now, 'operator_binding_upgrade');
        $changed++;
      }
    }
    $this->pruneUpgradePendingKept();
    return $changed;
  }

  /**
   * Whether this freeze was already recorded as kept by update 10037.
   *
   * A retry of update 10037 must not write a second keep audit
   * or lift the freeze. The marker is durable site state, not
   * the audit display helper.
   *
   * @return bool
   *   TRUE when this selector was already recorded as kept.
   */
  private function upgradePendingAlreadyKept(string $batchId, string $target): bool {
    if ($batchId === '' || $target === '') {
      return FALSE;
    }
    $kept = $this->state->get(self::STATE_UPGRADE_KEPT, []);
    return is_array($kept) && isset($kept[$this->upgradeKeptKey($batchId, $target)]);
  }

  /**
   * Records that update 10037 already kept this freeze.
   */
  private function markUpgradePendingKept(string $batchId, string $target): void {
    if ($batchId === '' || $target === '') {
      return;
    }
    $kept = $this->state->get(self::STATE_UPGRADE_KEPT, []);
    if (!is_array($kept)) {
      $kept = [];
    }
    $kept[$this->upgradeKeptKey($batchId, $target)] = TRUE;
    $this->state->set(self::STATE_UPGRADE_KEPT, $kept);
  }

  /**
   * Durable state key for one kept freeze.
   */
  private function upgradeKeptKey(string $batchId, string $target): string {
    return $batchId . "\0" . $target;
  }

  /**
   * Drops kept markers for a batch after confirm or lift.
   */
  private function clearUpgradePendingKeptForBatch(string $batchId): void {
    if ($batchId === '') {
      return;
    }
    $kept = $this->state->get(self::STATE_UPGRADE_KEPT, []);
    if (!is_array($kept) || $kept === []) {
      return;
    }
    $prefix = $batchId . "\0";
    $changed = FALSE;
    foreach (array_keys($kept) as $key) {
      if (!is_string($key)) {
        continue;
      }
      if (str_starts_with($key, $prefix)) {
        unset($kept[$key]);
        $changed = TRUE;
      }
    }
    if (!$changed) {
      return;
    }
    $this->storeUpgradePendingKept($kept);
  }

  /**
   * Deletes kept markers whose batch is no longer kill_pending.
   */
  private function pruneUpgradePendingKept(): void {
    $kept = $this->state->get(self::STATE_UPGRADE_KEPT, []);
    if (!is_array($kept)) {
      return;
    }
    if ($kept === []) {
      $this->state->delete(self::STATE_UPGRADE_KEPT);
      return;
    }
    $pending = $this->pendingUpgradeKeptBatchIds();
    $pruned = [];
    foreach (array_keys($kept) as $key) {
      if (!is_string($key)) {
        continue;
      }
      $pos = strpos($key, "\0");
      if ($pos === FALSE) {
        continue;
      }
      $batchId = substr($key, 0, $pos);
      if (isset($pending[$batchId])) {
        $pruned[$key] = TRUE;
      }
    }
    $this->storeUpgradePendingKept($pruned);
  }

  /**
   * Kill-pending batch ids that still need a kept marker.
   *
   * @return array<string, true>
   *   Batch id keys that are still kill_pending.
   */
  private function pendingUpgradeKeptBatchIds(): array {
    if (!$this->tableReady()) {
      return [];
    }
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k', ['batch_id'])
      ->condition('status', McpKillBlockStatus::KillPending->value)
      ->execute();
    if ($statement === NULL) {
      throw new McpKillSwitchException(
        McpKillSwitchException::TABLE_MISSING,
        'Kill-block select returned no statement.',
      );
    }
    $pending = [];
    foreach ($this->assocRows($statement) as $row) {
      $batchId = $this->rowString($row, 'batch_id');
      if ($batchId !== '') {
        $pending[$batchId] = TRUE;
      }
    }
    return $pending;
  }

  /**
   * Writes or deletes the kept-marker state array.
   *
   * @param array<mixed, mixed> $kept
   *   Remaining markers.
   */
  private function storeUpgradePendingKept(array $kept): void {
    if ($kept === []) {
      $this->state->delete(self::STATE_UPGRADE_KEPT);
      return;
    }
    $this->state->set(self::STATE_UPGRADE_KEPT, $kept);
  }

  /**
   * {@inheritdoc}
   */
  public function hasActiveStop(): bool {
    if (!$this->tableReady()) {
      return TRUE;
    }
    $now = $this->time->getRequestTime();
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k', ['status', 'block_until'])
      ->condition('status', [
        McpKillBlockStatus::Killed->value,
        McpKillBlockStatus::KillPending->value,
        McpKillBlockStatus::UnkillPending->value,
      ], 'IN')
      ->execute();
    if ($statement === NULL) {
      return TRUE;
    }
    foreach ($this->assocRows($statement) as $row) {
      $status = McpKillBlockStatus::tryFrom((string) $row['status']);
      if ($status === NULL) {
        return TRUE;
      }
      if ($status === McpKillBlockStatus::KillPending) {
        return TRUE;
      }
      $blockUntil = $this->rowBlockUntil($row);
      if ($blockUntil === NULL) {
        return TRUE;
      }
      if ($status->isBlocking($blockUntil, $now)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function wouldHoldKeys(string $principalKey, string $humanKey = '', string $tenant = ''): bool {
    return $this->shouldHoldSideEffects()
      && $this->isKilled($principalKey, $humanKey, $tenant);
  }

  /**
   * Whether a stop should hold queued side effects.
   */
  private function shouldHoldSideEffects(): bool {
    return TRUE;
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
      $meta['principal_key'] = 'unverified';
      $meta['human_key'] = 'unverified';
      $meta['principal_unverified'] = 'carried_queue_key';
    }
    $this->auditLogger->logSurvivingRollback('denied_access', $meta, TRUE);
  }

  /**
   * Extends an active mass freeze. Cap is 7 days from now.
   */
  private function extendFreeze(
    string $batchId,
    McpOperatorIdentity $operator,
    ?int $ttl,
    bool $breakGlass,
  ): McpKillSwitchResult {
    $this->assertOperatorIdentity($operator);
    $this->requireTable();
    $ttl = $this->resolveTtl($ttl);
    $operatorId = $operator->storageId();
    $now = $this->time->getRequestTime();
    $requestedUntil = McpKillTtl::blockUntil($now, $ttl);
    $cap = $now + McpKillTtl::MAX;
    $selectors = [];
    $reason = '';

    $txn = $this->connection->startTransaction();
    try {
      $rows = $this->lockBatch($batchId);
      if ($rows === []) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNKNOWN_BATCH,
          'No mass freeze matches that batch.',
        );
      }
      $existingUntil = 0;
      foreach ($rows as $row) {
        $status = McpKillBlockStatus::tryFrom((string) $row['status']);
        if ($status !== McpKillBlockStatus::KillPending
          && $status !== McpKillBlockStatus::Killed) {
          $this->refuse(
            McpKillSwitchException::NOT_FROZEN,
            'That batch is not an active mass freeze.',
            $operatorId,
            $batchId,
          );
        }
        if ((int) $row['confirm_until'] === 0) {
          $this->refuse(
            McpKillSwitchException::NOT_FROZEN,
            'That batch is not a mass freeze.',
            $operatorId,
            $batchId,
          );
        }
        if ($status === McpKillBlockStatus::Killed
          && (int) $row['block_until'] <= $now) {
          $this->refuse(
            McpKillSwitchException::NOT_FROZEN,
            'That freeze has already expired.',
            $operatorId,
            $batchId,
          );
        }
        $this->assertDistinctOperator((string) $row['requested_by'], $operatorId, $batchId);
        $selectors[] = new McpKillSelector(
          McpKillSelectorType::from((string) $row['selector_type']),
          (string) $row['selector_key'],
        );
        $reason = (string) $row['reason'];
        $existingUntil = max($existingUntil, (int) $row['block_until']);
      }
      $blockUntil = min($cap, max($existingUntil, $requestedUntil));
      $this->connection->update(self::TABLE)
        ->fields([
          'block_until' => $blockUntil,
          'ttl' => $ttl,
          'changed' => $now,
        ])
        ->condition('batch_id', $batchId)
        ->execute();
      unset($txn);
    }
    catch (\Throwable $e) {
      if ($txn instanceof Transaction) {
        $txn->rollBack();
      }
      throw $e;
    }

    $this->auditTransition($breakGlass ? self::AUDIT_BREAK_GLASS : self::AUDIT_EXTEND, [
      'actor' => $operatorId,
      'scope' => $this->selectorList($selectors),
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'correlation_id' => $batchId,
      'status' => (string) ($rows[0]['status'] ?? McpKillBlockStatus::KillPending->value),
      'second_confirmer' => $operatorId,
      'timestamp' => (string) $now,
      'break_glass_action' => $breakGlass ? McpKillBreakGlassAction::Extend->value : '',
    ]);

    return new McpKillSwitchResult(
      McpKillBlockStatus::tryFrom((string) ($rows[0]['status'] ?? '')) ?? McpKillBlockStatus::KillPending,
      $batchId,
      FALSE,
      $blockUntil,
      $ttl,
      $selectors,
    );
  }

  /**
   * Lifts an unconfirmed mass freeze. Held items stay held.
   */
  private function liftFreeze(
    string $batchId,
    McpOperatorIdentity $operator,
    bool $breakGlass,
  ): McpKillSwitchResult {
    $this->assertOperatorIdentity($operator);
    $this->requireTable();
    $operatorId = $operator->storageId();
    $now = $this->time->getRequestTime();

    $txn = $this->connection->startTransaction();
    try {
      $rows = $this->lockBatch($batchId);
      if ($rows === []) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNKNOWN_BATCH,
          'No mass freeze matches that batch.',
        );
      }
      $selectors = [];
      $ttl = 0;
      $blockUntil = 0;
      $reason = '';
      foreach ($rows as $row) {
        $status = McpKillBlockStatus::tryFrom((string) $row['status']);
        if ($status !== McpKillBlockStatus::KillPending) {
          $this->refuse(
            McpKillSwitchException::NOT_FROZEN,
            'That batch is not an unconfirmed mass freeze.',
            $operatorId,
            $batchId,
          );
        }
        $this->assertDistinctOperator((string) $row['requested_by'], $operatorId, $batchId);
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

    $this->clearUpgradePendingKeptForBatch($batchId);

    $this->auditTransition($breakGlass ? self::AUDIT_BREAK_GLASS : self::AUDIT_LIFT, [
      'actor' => $operatorId,
      'scope' => $this->selectorList($selectors),
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'correlation_id' => $batchId,
      'status' => McpKillBlockStatus::Expired->value,
      'second_confirmer' => $operatorId,
      'timestamp' => (string) $now,
      'break_glass_action' => $breakGlass ? McpKillBreakGlassAction::Lift->value : '',
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
   * Writes the confirm or break-glass keep audit row.
   *
   * @param bool $breakGlass
   *   TRUE when the write is a break-glass keep.
   * @param \Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction $action
   *   Keep, extend, or lift.
   * @param string $operatorId
   *   Confirmer storage id.
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Confirmed selectors.
   * @param string $reason
   *   Operator reason from the freeze row.
   * @param int $ttl
   *   Lifetime in seconds.
   * @param int $blockUntil
   *   Unix expiry of the kill block.
   * @param string $batchId
   *   Freeze batch id.
   * @param int $now
   *   Current request time.
   */
  private function auditConfirmOrBreakGlass(
    bool $breakGlass,
    McpKillBreakGlassAction $action,
    string $operatorId,
    array $selectors,
    string $reason,
    int $ttl,
    int $blockUntil,
    string $batchId,
    int $now,
  ): void {
    $this->auditTransition($breakGlass ? self::AUDIT_BREAK_GLASS : self::AUDIT_CONFIRM, [
      'actor' => $operatorId,
      'scope' => $this->selectorList($selectors),
      'target_selector' => $this->selectorList($selectors),
      'reason' => $reason,
      'ttl' => (string) $ttl,
      'block_until' => (string) $blockUntil,
      'batch_id' => $batchId,
      'correlation_id' => $batchId,
      'status' => McpKillBlockStatus::Killed->value,
      'second_confirmer' => $operatorId,
      'timestamp' => (string) $now,
      'break_glass_action' => $breakGlass ? $action->value : '',
    ]);
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
   *
   * A blocking row is never replaced by a non-blocking status. A new
   * kill on an in-flight un-kill cancels that un-kill and leaves the
   * row killed.
   *
   * @return \Drupal\mcp_sentinel\Enum\McpKillBlockStatus
   *   Status stored on the row.
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
  ): McpKillBlockStatus {
    $existing = $this->lockSelector($selector);
    if ($existing !== NULL) {
      $existingStatus = McpKillBlockStatus::tryFrom((string) $existing['status']);
      $newUntil = max((int) $existing['block_until'], $blockUntil);
      $cap = $now + McpKillTtl::MAX;
      if ($newUntil > $cap) {
        $newUntil = $cap;
      }
      $existingBlocking = $existingStatus !== NULL
        && $existingStatus->isBlocking((int) $existing['block_until'], $now);
      $newBlocking = $status->isBlocking($blockUntil, $now);
      $confirmedBlocking = $existingStatus === McpKillBlockStatus::Killed
        || $existingStatus === McpKillBlockStatus::UnkillPending;
      if ($confirmedBlocking && $status === McpKillBlockStatus::KillPending) {
        $this->connection->update(self::TABLE)
          ->fields([
            'status' => McpKillBlockStatus::Killed->value,
            'block_until' => $newUntil,
            'ttl' => max((int) $existing['ttl'], $ttl),
            'reason' => $reason,
            'changed' => $now,
            'unkill_batch_id' => '',
            'unkill_requested_by' => '',
            'unkill_requested_at' => 0,
            'unkill_confirm_until' => 0,
            'unkill_confirmed_by' => '',
            'unkill_confirmed_at' => 0,
          ])
          ->condition('selector_hash', $selector->hash())
          ->execute();
        return McpKillBlockStatus::Killed;
      }
      if ($existingBlocking && !$newBlocking) {
        $this->connection->update(self::TABLE)
          ->fields([
            'status' => McpKillBlockStatus::Killed->value,
            'block_until' => $newUntil,
            'ttl' => max((int) $existing['ttl'], $ttl),
            'reason' => $reason,
            'changed' => $now,
            'unkill_batch_id' => '',
            'unkill_requested_by' => '',
            'unkill_requested_at' => 0,
            'unkill_confirm_until' => 0,
            'unkill_confirmed_by' => '',
            'unkill_confirmed_at' => 0,
          ])
          ->condition('selector_hash', $selector->hash())
          ->execute();
        return McpKillBlockStatus::Killed;
      }
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
        'unkill_batch_id' => '',
        'unkill_requested_by' => '',
        'unkill_requested_at' => 0,
        'unkill_confirm_until' => 0,
        'unkill_confirmed_by' => '',
        'unkill_confirmed_at' => 0,
        'escalated_at' => 0,
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
      return $status;
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
        'escalated_at' => 0,
      ])
      ->execute();
    return $status;
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
   * Unix timestamp from a kill-block row.
   *
   * Drupal 11.3 stringifies integers on every driver. An unreadable
   * value fails closed.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   */
  private function rowBlockUntil(array $row): ?int {
    $value = $row['block_until'] ?? NULL;
    if (is_int($value)) {
      return $value;
    }
    if (is_string($value) && is_numeric($value)) {
      return (int) $value;
    }
    return NULL;
  }

  /**
   * String field from a stored row.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   * @param string $key
   *   Column name.
   */
  private function rowString(array $row, string $key): string {
    $value = $row[$key] ?? '';
    if (is_string($value)) {
      return $value;
    }
    if (is_int($value) || is_float($value)) {
      return (string) $value;
    }
    return '';
  }

  /**
   * String-keyed row from a fetchAssoc() result.
   *
   * @return array<string, mixed>|null
   *   The row, or NULL when the value is not an array.
   */
  private function assocRow(mixed $row): ?array {
    if (!is_array($row)) {
      return NULL;
    }
    $out = [];
    foreach ($row as $key => $value) {
      if (is_string($key)) {
        $out[$key] = $value;
      }
    }
    return $out;
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
   * Expires confirmed stops whose block_until has passed.
   *
   * Unconfirmed (kill_pending) freezes stay frozen past TTL until
   * two operators lift them or break-glass is used.
   */
  private function expireBlocking(int $now): int {
    $statuses = [
      McpKillBlockStatus::Killed->value,
      McpKillBlockStatus::UnkillPending->value,
    ];
    $statement = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', $statuses, 'IN')
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
   * Escalates unconfirmed mass freezes whose confirm window elapsed.
   *
   * The freeze stays in force. Invokes the unavailable-confirmer hook
   * (named second person and break-glass path) with no fallback that
   * would lift the freeze or let a single operator proceed. One audit
   * row is written per batch.
   */
  private function escalateUnconfirmedFreezes(int $now): int {
    $query = $this->connection->select(self::TABLE, 'k')
      ->fields('k')
      ->condition('status', McpKillBlockStatus::KillPending->value)
      ->condition('confirm_until', $now, '<=')
      ->condition('confirm_until', 0, '>')
      ->condition('escalated_at', 0);
    $statement = $query->execute();
    if ($statement === NULL) {
      return 0;
    }
    $byBatch = [];
    foreach ($this->assocRows($statement) as $row) {
      $batchId = (string) $row['batch_id'];
      $byBatch[$batchId][] = $row;
    }
    $count = 0;
    foreach ($byBatch as $batchId => $rows) {
      try {
        $count += $this->escalateOneBatch($batchId, $rows, $now);
      }
      catch (\Throwable $e) {
        $this->recordNotifyFailure($batchId, $rows, $e);
      }
    }
    return $count;
  }

  /**
   * Claims, audits, then notifies one unconfirmed freeze batch.
   *
   * @param string $batchId
   *   Kill batch id.
   * @param list<array<string, mixed>> $rows
   *   Stored rows in the batch.
   * @param int $now
   *   Current request time.
   */
  private function escalateOneBatch(
    string $batchId,
    array $rows,
    int $now,
  ): int {
    $first = $rows[0];
    $claimed = (int) $this->connection->update(self::TABLE)
      ->fields([
        'escalated_at' => $now,
        'changed' => $now,
      ])
      ->condition('batch_id', $batchId)
      ->condition('status', McpKillBlockStatus::KillPending->value)
      ->condition('escalated_at', 0)
      ->execute();
    if ($claimed < 1) {
      return 0;
    }
    $selectors = [];
    foreach ($rows as $row) {
      $selectors[] = new McpKillSelector(
        McpKillSelectorType::from((string) $row['selector_type']),
        (string) $row['selector_key'],
      );
    }
    $this->auditTransition(self::AUDIT_ESCALATE, [
      'actor' => McpOperatorIdentity::system()->storageId(),
    ] + $this->auditSelectorFields($selectors) + [
      'reason' => 'confirm_window',
      'ttl' => (string) $first['ttl'],
      'block_until' => (string) $first['block_until'],
      'batch_id' => $batchId,
      'correlation_id' => $batchId,
      'status' => McpKillBlockStatus::KillPending->value,
      'second_confirmer' => '',
      'timestamp' => (string) $now,
    ]);
    $this->notifyUnavailableConfirmerGuarded($rows, 'kill', $batchId);
    return $claimed;
  }

  /**
   * Restores killed (still blocking) when an un-kill confirm window elapses.
   *
   * The two-person un-kill does not complete. The block stays in force.
   * Each batch is isolated: a hook throw after revert does not stop
   * other batches.
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
    $byBatch = [];
    foreach ($this->assocRows($statement) as $row) {
      $batchId = (string) $row['unkill_batch_id'];
      $byBatch[$batchId][] = $row;
    }
    $count = 0;
    foreach ($byBatch as $batchId => $rows) {
      try {
        $count += $this->expireOneUnkillBatch($batchId, $rows, $now);
      }
      catch (\Throwable $e) {
        $this->recordNotifyFailure($batchId, $rows, $e);
      }
    }
    return $count;
  }

  /**
   * Reverts one un-kill batch (audit first), then notifies.
   *
   * @param string $batchId
   *   Un-kill batch id.
   * @param list<array<string, mixed>> $rows
   *   Stored rows in the un-kill batch.
   * @param int $now
   *   Current request time.
   */
  private function expireOneUnkillBatch(
    string $batchId,
    array $rows,
    int $now,
  ): int {
    $count = 0;
    foreach ($rows as $row) {
      $this->revertExpiredUnkill($row, $now, 'unkill_confirm_window');
      $count++;
    }
    $this->notifyUnavailableConfirmerGuarded($rows, 'unkill', $batchId);
    return $count;
  }

  /**
   * Restores killed (still blocking) for an elapsed or discarded un-kill.
   *
   * Audit is written before the unavailable-confirmer hook so a hook
   * throw cannot leave the row unkill_pending without a record.
   *
   * @param array<string, mixed> $row
   *   Stored unkill_pending row.
   * @param int $now
   *   Current request time.
   * @param string $reason
   *   Audit reason (unkill_confirm_window or operator_binding_upgrade).
   */
  private function revertExpiredUnkill(array $row, int $now, string $reason): void {
    $txn = $this->connection->startTransaction();
    try {
      $this->connection->update(self::TABLE)
        ->fields([
          'status' => McpKillBlockStatus::Killed->value,
          'unkill_batch_id' => '',
          'unkill_confirm_until' => 0,
          'changed' => $now,
        ])
        ->condition('selector_hash', $this->rowString($row, 'selector_hash'))
        ->execute();
      $this->auditTransition(self::AUDIT_EXPIRE, [
        'actor' => McpOperatorIdentity::system()->storageId(),
      ] + $this->auditSelectorFields([
        new McpKillSelector(
          McpKillSelectorType::from($this->rowString($row, 'selector_type')),
          $this->rowString($row, 'selector_key'),
        ),
      ]) + [
        'reason' => $reason,
        'ttl' => $this->rowString($row, 'ttl'),
        'block_until' => $this->rowString($row, 'block_until'),
        'batch_id' => $this->rowString($row, 'unkill_batch_id'),
        'status' => McpKillBlockStatus::Killed->value,
        'second_confirmer' => '',
      ]);
      unset($txn);
    }
    catch (\Throwable $e) {
      $txn->rollBack();
      throw $e;
    }
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
    $this->clearUpgradePendingKeptForBatch($this->rowString($row, 'batch_id'));
    $this->auditTransition(self::AUDIT_EXPIRE, [
      'actor' => McpOperatorIdentity::system()->storageId(),
    ] + $this->auditSelectorFields([
      new McpKillSelector(
        McpKillSelectorType::from((string) $row['selector_type']),
        (string) $row['selector_key'],
      ),
    ]) + [
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
   * @param list<array<string, mixed>> $rows
   *   Stored rows in the batch.
   * @param string $transition
   *   Kill or unkill.
   */
  private function notifyUnavailableConfirmer(array $rows, string $transition): void {
    if ($rows === []) {
      return;
    }
    $row = $rows[0];
    $selector = new McpKillSelector(
      McpKillSelectorType::from((string) $row['selector_type']),
      (string) $row['selector_key'],
    );
    $targets = [];
    foreach ($rows as $item) {
      $targets[] = (string) $item['selector_type'] . ':' . (string) $item['selector_key'];
    }
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
      'targets' => $targets,
    ];
    $this->moduleHandler->invokeAll(
      'mcp_sentinel_kill_unavailable_confirmer',
      [$context],
    );
  }

  /**
   * Invokes the unavailable-confirmer hook and records a throw.
   *
   * @param list<array<string, mixed>> $rows
   *   Stored rows in the batch.
   * @param string $transition
   *   Kill or unkill.
   * @param string $batchId
   *   Batch id for the watchdog and follow-up audit.
   */
  private function notifyUnavailableConfirmerGuarded(
    array $rows,
    string $transition,
    string $batchId,
  ): void {
    try {
      $this->notifyUnavailableConfirmer($rows, $transition);
    }
    catch (\Throwable $e) {
      $this->recordNotifyFailure($batchId, $rows, $e);
    }
  }

  /**
   * Logs a notify throw and writes a notify_failed follow-up audit.
   *
   * @param string $batchId
   *   Batch id written to watchdog and the follow-up audit.
   * @param list<array<string, mixed>> $rows
   *   Stored rows in the batch.
   * @param \Throwable $e
   *   Exception thrown by the hook.
   */
  private function recordNotifyFailure(
    string $batchId,
    array $rows,
    \Throwable $e,
  ): void {
    $this->logger->error(
      'Unavailable-confirmer hook failed for batch @batch: @message',
      [
        '@batch' => $batchId,
        '@message' => $e->getMessage(),
      ],
    );
    $first = $rows[0] ?? [];
    $selectors = [];
    if ($first !== []) {
      $selectors[] = new McpKillSelector(
        McpKillSelectorType::from($this->rowString($first, 'selector_type')),
        $this->rowString($first, 'selector_key'),
      );
    }
    $this->auditTransition(self::AUDIT_ESCALATE, [
      'actor' => McpOperatorIdentity::system()->storageId(),
    ] + ($selectors !== [] ? $this->auditSelectorFields($selectors) : [
      'scope' => '',
      'target_selector' => '',
    ]) + [
      'reason' => 'notify_failed',
      'ttl' => $this->rowString($first, 'ttl'),
      'block_until' => $this->rowString($first, 'block_until'),
      'batch_id' => $batchId,
      'correlation_id' => $batchId,
      'status' => $this->rowString($first, 'status'),
      'second_confirmer' => '',
      'timestamp' => (string) $this->time->getRequestTime(),
    ]);
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
    $this->auditLogger->logAlways(
      $operation,
      $metadata + $this->bindings->advisoryProcessMetadata(),
    );
  }

  /**
   * Distinct scope (every selector) and target_selector (first) fields.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Selectors.
   *
   * @return array{scope: string, target_selector: string}
   *   Audit fields.
   */
  private function auditSelectorFields(array $selectors): array {
    $scope = $this->selectorList($selectors);
    return [
      'scope' => $scope,
      'target_selector' => $selectors === []
        ? ''
        : $selectors[0]->type->value . ':' . $selectors[0]->key,
    ];
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
   * Requested TTL, or the configured default. Never above 7 d.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function resolveTtl(?int $requested): int {
    return McpKillTtl::resolve($requested, $this->defaultTtl(), $this->maxTtl());
  }

  /**
   * Configured default TTL.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the configured default exceeds 7 d.
   */
  private function defaultTtl(): int {
    $value = (int) ($this->configFactory->get('mcp_sentinel.settings')->get('kill_switch_default_ttl') ?? McpKillTtl::DEFAULT);
    if ($value > McpKillTtl::MAX) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_TTL,
        'Kill-block TTL cannot exceed 7 days.',
      );
    }
    return $value > 0 ? $value : McpKillTtl::DEFAULT;
  }

  /**
   * Configured maximum TTL. Cannot be raised above 7 d.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the configured maximum exceeds 7 d.
   */
  private function maxTtl(): int {
    $value = (int) ($this->configFactory->get('mcp_sentinel.settings')->get('kill_switch_max_ttl') ?? McpKillTtl::MAX);
    if ($value > McpKillTtl::MAX) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_TTL,
        'Kill-block TTL cannot exceed 7 days.',
      );
    }
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
   * Operator identity and reason gates shared by mutating commands.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertWritable(McpOperatorIdentity $operator, string $reason): void {
    $this->assertOperatorIdentity($operator);
    $this->assertReason($reason);
    $this->requireTable();
  }

  /**
   * Verified Paladin identity. Fail closed otherwise.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertOperatorIdentity(McpOperatorIdentity $operator): void {
    if ($operator->isVerified()) {
      return;
    }
    throw new McpKillSwitchException(
      McpKillSwitchException::UNVERIFIED_OPERATOR,
      'A verified operator identity is required.',
    );
  }

  /**
   * Break-glass is limited to the identity pinned in settings.php.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertBreakGlassIdentity(McpOperatorIdentity $operator): void {
    // Drupal Settings::get() is static; the injected instance is the test seam.
    // @phpstan-ignore staticMethod.dynamicCall
    $configured = trim((string) $this->settings->get(
      'mcp_sentinel.kill_switch.break_glass_operator',
      '',
    ));
    if ($configured === '') {
      $this->refuse(
        McpKillSwitchException::BREAK_GLASS_DENIED,
        'Break-glass is not configured. Set mcp_sentinel.kill_switch.break_glass_operator in settings.php.',
        $operator->storageId(),
      );
    }
    if ($this->matchesBreakGlassPin($operator, $configured)) {
      return;
    }
    $this->refuse(
      McpKillSwitchException::BREAK_GLASS_DENIED,
      'Break-glass is limited to the identity configured in settings.php.',
      $operator->storageId(),
    );
  }

  /**
   * Whether the operator is the pinned Paladin iss|sub.
   *
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Candidate operator.
   * @param string $configured
   *   Pin from settings.php.
   *
   * @return bool
   *   TRUE when kind is Paladin and the id matches the pin.
   */
  private function matchesBreakGlassPin(McpOperatorIdentity $operator, string $configured): bool {
    return $operator->kind === McpOperatorIdentity::KIND_PALADIN
      && $configured !== ''
      && strlen($configured) === strlen($operator->id)
      && hash_equals($configured, $operator->id);
  }

  /**
   * Distinct confirmer. Same verified identity twice is refused.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertDistinctOperator(
    string $first,
    string $second,
    string $batchId = '',
  ): void {
    try {
      $this->bindings->assertDistinctOperators($first, $second);
    }
    catch (McpKillSwitchException $e) {
      $this->refuse($e->reasonCode, $e->getMessage(), $second, $batchId);
    }
  }

  /**
   * Audits a refused operator action and throws with alreadyAudited set.
   *
   * @param string $code
   *   Stable refusal reason.
   * @param string $message
   *   Operator-facing text. Must not contain tokens.
   * @param string $actor
   *   Operator storage id, when known.
   * @param string $batchId
   *   Kill batch, when known.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function refuse(
    string $code,
    string $message,
    string $actor = '',
    string $batchId = '',
  ): never {
    $this->auditLogger->logSurvivingRollback(self::AUDIT_REFUSE, [
      'actor' => $actor,
      'reason_code' => $code,
      'reason' => $message,
      'batch_id' => $batchId,
      'correlation_id' => $batchId,
      'timestamp' => (string) $this->time->getRequestTime(),
    ] + $this->bindings->advisoryProcessMetadata(), TRUE);
    throw new McpKillSwitchException($code, $message, TRUE);
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
