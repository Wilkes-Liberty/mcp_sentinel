<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\RevisionableInterface;
use Drupal\Core\KeyValueStore\KeyValueFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Decides whether an evidence-required governed action may execute.
 *
 * The evidence-required assurance class (d.o #3616539) inverts the usual
 * relationship between an action and its log entry: the entry is not a record
 * of the action, it is a precondition for it. A governed mutation in a class
 * the profile marks evidence-required executes only when its evidence can be
 * appended to the *keyed* audit chain; otherwise the mutation is vetoed.
 * Best-effort logging and unkeyed integrity never satisfy the class — an
 * unsigned row proves ordering against casual edits, not against a writer who
 * can recompute the chain, and "we probably logged it" is exactly the state
 * this class exists to make impossible.
 *
 * The durability model is atomic co-commit: the evidence precommit row is
 * appended inside the same database transaction as the mutation, so both
 * become durable together or neither does. There is no reachable state in
 * which the mutation persists without its precommit. This matches the
 * module's existing evidence discipline (entity_save rows written from the
 * post-save hooks, refusal rows deferred past a rollback) rather than
 * introducing a second out-of-band connection.
 */
class McpEvidenceGuard {

  /**
   * Veto reason: the audit_chain module is not available.
   */
  public const REASON_CHAIN_MISSING = 'evidence_chain_missing';

  /**
   * Veto reason: auditing is disabled, so no evidence row would be written.
   */
  public const REASON_AUDIT_DISABLED = 'evidence_audit_disabled';

  /**
   * Veto reason: the chain has no resolvable signing key (unkeyed integrity).
   */
  public const REASON_UNKEYED = 'evidence_unkeyed';

  /**
   * Receipt reason: observed postconditions disagree with the sealed target.
   */
  public const REASON_POSTCONDITION_DISCREPANCY = 'postcondition_discrepancy';

  /**
   * Key-value collection of the uncertain-receipt reconciliation ledger.
   *
   * One entry per correlation id: the receipt that could not commit after its
   * mutation was already durable. Deliberately outside the chain — the ledger
   * exists precisely for the moments the chain cannot be written — and keyed
   * per correlation rather than stored as one map, so concurrent receipt
   * failures (or cron reconciliation overlapping a new record) cannot
   * last-write-wins each other's entries away.
   */
  public const STATE_UNCERTAIN = 'mcp_sentinel.evidence_uncertain';

  /**
   * Action class: governed entity create/update.
   */
  public const ACTION_ENTITY_WRITE = 'entity_write';

  /**
   * Action class: governed entity delete.
   */
  public const ACTION_ENTITY_DELETE = 'entity_delete';

  /**
   * Constructs the guard.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\audit_chain\AuditChainLoggerInterface|null $auditChain
   *   The audit chain, optional for the same container-compilation reason as
   *   McpAuditLogger: its absence is itself a veto condition, not an error.
   * @param \Drupal\key\KeyRepositoryInterface|null $keyRepository
   *   The key repository used to prove the configured signing key resolves.
   *   Optional so the container compiles without the key module; without it,
   *   keyed signing cannot be proven, which is a veto.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger the precommit and receipt rows are appended through.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   The UUID generator minting correlation ids.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The authenticated principal recorded in the precommit.
   * @param \Drupal\Core\KeyValueStore\KeyValueFactoryInterface $keyValueFactory
   *   Key-value storage backing the uncertain-receipt reconciliation ledger
   *   (one key per correlation id).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service stamping ledger entries.
   * @param \Drupal\mcp_sentinel\Service\McpOauthContext $oauthContext
   *   The validated OAuth context binding the delegation (consumer client)
   *   into the precommit.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack, read for the caller's X-Request-Id correlation
   *   header (recorded verbatim, never an enforcement signal).
   * @param \Drupal\Core\Database\Connection|null $database
   *   The database connection, used only to detect an active transaction so
   *   a receipt failure can distinguish fail-closed from uncertain. NULL is
   *   accepted for test construction, degrading to the uncertain branch.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ?AuditChainLoggerInterface $auditChain,
    private readonly ?KeyRepositoryInterface $keyRepository,
    private readonly McpAuditLogger $auditLogger,
    private readonly UuidInterface $uuid,
    private readonly AccountProxyInterface $currentUser,
    private readonly KeyValueFactoryInterface $keyValueFactory,
    private readonly TimeInterface $time,
    private readonly McpOauthContext $oauthContext,
    private readonly RequestStack $requestStack,
    private readonly ?Connection $database = NULL,
  ) {}

  /**
   * Correlation ids of precommits awaiting their receipt, by entity object.
   *
   * Request-scoped by the service's own lifetime, keyed by spl_object_id so
   * the receipt written from the post-save hook completes exactly the
   * precommit its presave wrote — the same stash pattern the
   * write-precondition boundary uses.
   *
   * @var array<int, string>
   */
  private array $pending = [];

  /**
   * Sealed target identity stashed at precommit, keyed by correlation id.
   *
   * @var array<string, array<string, mixed>>
   */
  private array $expectedPostconditions = [];

  /**
   * Whether the resolved profile requires evidence for an action class.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface|null $profile
   *   The resolved policy profile, or NULL when none resolved.
   * @param string $actionClass
   *   The action class, e.g. 'entity_write' or 'entity_delete'.
   */
  public function requiresEvidence(?McpPolicyProfileInterface $profile, string $actionClass): bool {
    return $profile !== NULL && $profile->requiresEvidenceFor($actionClass);
  }

  /**
   * Returns the veto reason when required evidence cannot commit, else NULL.
   *
   * The checks are preconditions for a durable *keyed* append, evaluated
   * before the mutation runs:
   * - the chain service must exist (no chain, no evidence);
   * - auditing must be enabled (log() would silently no-op otherwise, which
   *   is best-effort logging by another name);
   * - the configured signing key must resolve to a non-empty value — the
   *   chain itself falls back to unkeyed SHA-256 when the key is missing or
   *   unresolvable, and no fallback to unkeyed integrity satisfies this
   *   class.
   *
   * The append itself can still fail after these pass (storage outage mid
   * request); that failure aborts the surrounding transaction, which vetoes
   * the mutation with it — the atomic co-commit half of the contract.
   *
   * @return string|null
   *   One of the REASON_* codes, or NULL when evidence can commit.
   */
  public function vetoReason(): ?string {
    if ($this->auditChain === NULL) {
      return self::REASON_CHAIN_MISSING;
    }
    if (!$this->configFactory->get('mcp_sentinel.settings')->get('audit_enabled')) {
      return self::REASON_AUDIT_DISABLED;
    }
    if (!$this->signingKeyResolves()) {
      return self::REASON_UNKEYED;
    }
    return NULL;
  }

  /**
   * Builds the stable, non-sensitive veto message for a refused action.
   *
   * @param string $reason
   *   One of the REASON_* codes.
   * @param string $actionClass
   *   The action class that was refused.
   */
  public function messageFor(string $reason, string $actionClass): string {
    return sprintf(
      'MCP Sentinel evidence-required veto (%s): this governed %s action requires durable keyed evidence and the audit chain cannot provide it. The action was not executed.',
      $reason,
      $actionClass,
    );
  }

  /**
   * Appends the evidence precommit for an allowed evidence-required action.
   *
   * Called after vetoReason() returned NULL and after every shaping gate, so
   * the row records the decision for the entity as it will actually be saved.
   * The append participates in the surrounding save transaction: a failure
   * here propagates and aborts the save (the atomic co-commit contract), and
   * a save that aborts later takes this row down with it — no orphaned
   * precommits, no mutation without one.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved profile that required the evidence.
   * @param string $actionClass
   *   The action class, e.g. 'entity_write'.
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity about to be mutated.
   * @param string $operation
   *   The concrete operation, e.g. 'create', 'update', 'delete'.
   *
   * @return string
   *   The correlation id shared with the eventual receipt row.
   */
  public function precommit(McpPolicyProfileInterface $profile, string $actionClass, EntityInterface $entity, string $operation): string {
    $correlation = $this->uuid->generate();
    $this->auditLogger->logAlways('evidence_precommit', [
      'entity_type' => $entity->getEntityTypeId(),
      'bundle' => $entity->bundle(),
      'id' => $entity->id() ?: '(new)',
      'label' => $entity->label(),
      'correlation_id' => $correlation,
      'action_class' => $actionClass,
      'operation' => $operation,
      'decision' => 'allow',
      'profile' => $profile->id(),
      'policy_digest' => 'sha256:' . hash('sha256', (string) json_encode($profile->toArray())),
      'principal_uid' => (int) $this->currentUser->id(),
      // The delegation binding: which validated OAuth consumer (if any) the
      // principal acted through. NULL on the role-fallback channel. The
      // connector's self-reported X-MCP-Client label is stamped separately by
      // the audit logger, forensic-only.
      'consumer_client_id' => $this->oauthContext->clientId(),
      // The caller's request correlation header, recorded verbatim when
      // present. The correlation_id above is the identifier this module
      // mints; this one lets evidence join the caller's own tracing.
      'request_id' => $this->currentRequestId(),
      'target' => [
        'entity_type' => $entity->getEntityTypeId(),
        'bundle' => $entity->bundle(),
        'uuid' => $entity->uuid(),
        'id' => $entity->id(),
      ],
    ]);
    // Narrow the check-then-append race: the chain deliberately writes
    // unkeyed rather than dropping a row when its key stops resolving, so a
    // key deleted between vetoReason() and the append would leave an unsigned
    // precommit. Re-checking here aborts the transaction — taking the
    // unsigned row and the mutation down together — if signing degraded mid
    // request. A strict keyed-append API on the chain is the complete fix.
    if (!$this->signingKeyResolves()) {
      throw new \RuntimeException($this->messageFor(self::REASON_UNKEYED, $actionClass));
    }
    $this->pending[spl_object_id($entity)] = $correlation;
    $expected = [
      'target' => [
        'uuid' => $entity->uuid(),
      ],
    ];
    if ($entity->id()) {
      $expected['target']['id'] = (string) $entity->id();
    }
    $this->expectedPostconditions[$correlation] = $expected;
    return $correlation;
  }

  /**
   * Returns the caller's X-Request-Id header, or NULL when absent.
   */
  private function currentRequestId(): ?string {
    $request = $this->requestStack->getCurrentRequest();
    $id = $request ? (string) $request->headers->get('X-Request-Id', '') : '';
    return $id === '' ? NULL : substr($id, 0, 128);
  }

  /**
   * Takes the pending correlation id for an entity, if its presave wrote one.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The just-saved entity.
   *
   * @return string|null
   *   The correlation id, or NULL when this save carried no precommit.
   */
  public function takeCorrelation(EntityInterface $entity): ?string {
    $key = spl_object_id($entity);
    $correlation = $this->pending[$key] ?? NULL;
    unset($this->pending[$key]);
    return $correlation;
  }

  /**
   * Writes the execution receipt for a precommitted action, or refuses.
   *
   * Failure semantics depend on whether the mutation is still in flight:
   * - Inside a transaction, the failure is rethrown as-is; the rollback takes
   *   the mutation (and its precommit) with it, so the action fails closed
   *   and nothing is uncertain.
   * - Outside a transaction the mutation is already durable, so the failure
   *   is recorded in the reconciliation ledger under the correlation id and
   *   an explicit evidence_uncertain refusal is thrown — the caller is never
   *   handed an unproven success.
   *
   * When the caller supplies postconditions (what actually happened:
   * target id/uuid/revision and outcome), they are stamped on the
   * existing evidence object. An expected map — passed in or stashed
   * at precommit — is compared; a discrepancy is written onto the
   * receipt and then refused. This is the same receipt, not a second
   * evidence subsystem (#3616538 slice 3/6).
   *
   * @param string $correlation
   *   The correlation id the precommit minted.
   * @param string $rowOperation
   *   The receipt row's operation, e.g. 'entity_save' or 'entity_delete'.
   * @param array $metadata
   *   The receipt metadata; the evidence keys are stamped here.
   *   Optional `postconditions` are copied onto evidence.postconditions.
   * @param array<string, mixed>|null $expectedPostconditions
   *   Sealed or intended postconditions to compare. NULL uses the
   *   precommit stash when one exists.
   */
  public function receipt(string $correlation, string $rowOperation, array $metadata, ?array $expectedPostconditions = NULL): void {
    $postconditions = is_array($metadata['postconditions'] ?? NULL)
      ? $metadata['postconditions']
      : NULL;
    $expected = $expectedPostconditions ?? $this->expectedPostconditions[$correlation] ?? NULL;
    unset($this->expectedPostconditions[$correlation]);
    $discrepancy = is_array($expected) && is_array($postconditions)
      ? self::postconditionDiscrepancy($expected, $postconditions)
      : NULL;

    $metadata['evidence'] = [
      'correlation_id' => $correlation,
      'precommit' => TRUE,
    ];
    if ($postconditions !== NULL) {
      $metadata['evidence']['postconditions'] = $postconditions;
    }
    if ($discrepancy !== NULL) {
      $metadata['evidence']['discrepancy'] = TRUE;
      $metadata['reason'] = $discrepancy;
    }
    try {
      // logAlways, not log(): the precommit was only written because auditing
      // was enabled, and a receipt silently dropped because the flag flipped
      // mid-flight would be best-effort logging by another name.
      $this->auditLogger->logAlways($rowOperation, $metadata);
    }
    catch (\Throwable $e) {
      if ($this->database !== NULL && $this->database->inTransaction()) {
        throw $e;
      }
      $this->recordUncertain($correlation, $rowOperation, $metadata, $e);
      throw new \RuntimeException(sprintf(
        'MCP Sentinel evidence receipt uncertain (evidence_uncertain): the governed %s is durable but its execution receipt could not commit. Correlation %s is recorded for reconciliation; this outcome must not be reported as a proven success.',
        $rowOperation,
        $correlation,
      ), 0, $e);
    }
    if ($discrepancy !== NULL) {
      throw new \RuntimeException(sprintf(
        'MCP Sentinel postcondition discrepancy (%s): the execution receipt does not match the sealed target. Correlation %s.',
        $discrepancy,
        $correlation,
      ));
    }
  }

  /**
   * Observed postconditions for a live entity, or a missing one.
   *
   * @param \Drupal\Core\Entity\EntityInterface|null $entity
   *   The live entity, or NULL when it is gone.
   * @param string $outcome
   *   What the caller observed (saved, deleted, present, not_executed).
   *
   * @return array{target: array{id: string|null, uuid: string|null, revision: string|null}, outcome: string, exists: bool}
   *   What actually happened.
   */
  public static function observeEntity(?EntityInterface $entity, string $outcome): array {
    if ($entity === NULL) {
      return [
        'target' => [
          'id' => NULL,
          'uuid' => NULL,
          'revision' => NULL,
        ],
        'outcome' => $outcome,
        'exists' => FALSE,
      ];
    }
    $revision = $entity instanceof RevisionableInterface
      ? (string) $entity->getRevisionId()
      : NULL;
    $id = $entity->id();
    $uuid = $entity->uuid();
    return [
      'target' => [
        'id' => $id !== NULL && $id !== '' ? (string) $id : NULL,
        'uuid' => $uuid !== NULL && $uuid !== '' ? (string) $uuid : NULL,
        'revision' => $revision === '' ? NULL : $revision,
      ],
      'outcome' => $outcome,
      'exists' => TRUE,
    ];
  }

  /**
   * Returns the discrepancy reason when expected and observed disagree.
   *
   * Only keys present in both maps are compared. The observer may
   * record more than the seal required; extra observed fields are
   * not a discrepancy. Unassigned identities (NULL, empty, "(new)")
   * are not compared.
   *
   * @param array<string, mixed> $expected
   *   Sealed or intended postconditions.
   * @param array<string, mixed> $observed
   *   What the live target actually is.
   *
   * @return string|null
   *   REASON_POSTCONDITION_DISCREPANCY, or NULL when they agree.
   */
  public static function postconditionDiscrepancy(array $expected, array $observed): ?string {
    foreach (['outcome', 'exists'] as $key) {
      if (array_key_exists($key, $expected) && array_key_exists($key, $observed)
        && $expected[$key] !== $observed[$key]) {
        return self::REASON_POSTCONDITION_DISCREPANCY;
      }
    }
    $expectedTarget = is_array($expected['target'] ?? NULL) ? $expected['target'] : [];
    $observedTarget = is_array($observed['target'] ?? NULL) ? $observed['target'] : [];
    foreach (['id', 'uuid', 'revision'] as $key) {
      if (!array_key_exists($key, $expectedTarget) || !array_key_exists($key, $observedTarget)) {
        continue;
      }
      $left = $expectedTarget[$key];
      $right = $observedTarget[$key];
      if ($left === NULL || $right === NULL || $left === '' || $right === '') {
        continue;
      }
      if ($left === '(new)' || $right === '(new)') {
        continue;
      }
      if ((string) $left !== (string) $right) {
        return self::REASON_POSTCONDITION_DISCREPANCY;
      }
    }
    return NULL;
  }

  /**
   * Records an uncertain receipt in the reconciliation ledger, once.
   *
   * One entry per correlation id: a receipt delivered again bumps the
   * attempt count instead of multiplying entries.
   */
  public function recordUncertain(string $correlation, string $rowOperation, array $metadata, \Throwable $error): void {
    $store = $this->keyValueFactory->get(self::STATE_UNCERTAIN);
    $entry = $store->get($correlation) ?? [
      'operation' => $rowOperation,
      'metadata' => $metadata,
      'first_failed' => $this->time->getRequestTime(),
      'attempts' => 0,
    ];
    $store->set($correlation, $this->stampFailure($entry, $error));
  }

  /**
   * Bumps a ledger entry's attempt count and last error.
   */
  private function stampFailure(array $entry, \Throwable $error): array {
    $entry['attempts']++;
    $entry['last_error'] = substr($error->getMessage(), 0, 255);
    return $entry;
  }

  /**
   * Attempts to append every receipt in the ledger, marked as reconciled.
   *
   * Idempotent per entry: a reconciled receipt leaves the ledger, so a second
   * run appends nothing for it. Entries that still cannot commit stay, with
   * their attempt count and last error updated for the status report.
   *
   * @return array{reconciled: int, remaining: int}
   *   How many receipts were appended and how many are still pending.
   */
  public function reconcile(): array {
    $store = $this->keyValueFactory->get(self::STATE_UNCERTAIN);
    $reconciled = 0;
    foreach ($store->getAll() as $correlation => $entry) {
      try {
        $metadata = $entry['metadata'];
        $metadata['evidence']['reconciled'] = TRUE;
        $this->auditLogger->logAlways($entry['operation'], $metadata);
        $store->delete($correlation);
        $reconciled++;
      }
      catch (\Throwable $e) {
        $store->set($correlation, $this->stampFailure($entry, $e));
      }
    }
    return ['reconciled' => $reconciled, 'remaining' => count($store->getAll())];
  }

  /**
   * How many uncertain receipts await reconciliation.
   */
  public function uncertainCount(): int {
    return count($this->keyValueFactory->get(self::STATE_UNCERTAIN)->getAll());
  }

  /**
   * Whether the chain's configured signing key resolves to usable material.
   *
   * Public so the install verifier can report keyed-evidence posture
   * without re-deriving the resolution the guard already performs.
   *
   * @return bool
   *   TRUE when the configured key exists and has material.
   */
  public function signingKeyIsResolved(): bool {
    return $this->signingKeyResolves();
  }

  /**
   * Whether the chain's configured signing key resolves to usable material.
   *
   * Mirrors the resolution audit_chain itself performs on append, because the
   * chain deliberately *writes unkeyed* rather than dropping a row when the
   * key will not resolve — correct for ordinary auditing, disqualifying for
   * the evidence-required class. A first-class signing-status API on the
   * chain would remove this duplication; until then the check reads the same
   * config key and Key entity the chain does.
   */
  private function signingKeyResolves(): bool {
    $keyId = (string) ($this->configFactory->get('audit_chain.settings')->get('hash_key') ?? '');
    if ($keyId === '' || $this->keyRepository === NULL) {
      return FALSE;
    }
    $key = $this->keyRepository->getKey($keyId);
    return $key !== NULL && (string) $key->getKeyValue() !== '';
  }

}
