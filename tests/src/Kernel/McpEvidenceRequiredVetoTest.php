<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\mcp_sentinel\Service\McpEvidenceGuard;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the evidence-required action veto (d.o #3616539).
 *
 * The contract under test: when a policy profile marks an action class as
 * evidence-required, a governed mutation in that class executes only when its
 * evidence can commit durably to the keyed audit chain. Evidence that cannot
 * commit vetoes the mutation — never best-effort logging, and never a fall
 * back to unkeyed integrity. The veto itself leaves a (rollback-surviving)
 * refusal row, because a refusal that vanishes reads as "nothing happened".
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpEvidenceRequiredVetoTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * Machine name of the content type used throughout.
   */
  private const TYPE = 'page';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installSchema('node', ['node_access']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'mcp_sentinel',
    ]);

    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('audit_enabled', TRUE)
      ->save();

    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('allow_delete', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    NodeType::create(['type' => self::TYPE, 'name' => 'Page'])->save();
  }

  /**
   * Creates a governed mcp_api account and sets it as the current user.
   */
  private function setGovernedAccount(): AccountInterface {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * Marks an action class evidence-required on the default profile.
   *
   * @param string[] $classes
   *   Action classes, e.g. ['entity_write'].
   */
  private function requireEvidenceFor(array $classes): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('evidence_required_actions', $classes)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
  }

  /**
   * Configures a resolvable HMAC signing key for the audit chain.
   */
  private function configureSigningKey(): void {
    Key::create([
      'id' => 'evidence_test_key',
      'label' => 'Evidence test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'evidence-veto-test-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'evidence_test_key')
      ->save();
  }

  /**
   * Returns all chain rows for one operation, oldest first.
   *
   * @return array<int, array{operation: string, metadata: array}>
   *   Decoded rows.
   */
  private function chainRows(string $operation): array {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $result = $this->container->get('database')
      ->select('audit_chain_log', 'a')
      ->fields('a', ['operation', 'metadata'])
      ->condition('operation', $operation)
      ->orderBy('id')
      ->execute();
    $rows = [];
    foreach ($result as $record) {
      $rows[] = [
        'operation' => $record->operation,
        'metadata' => $logger->decodeMetadata((string) $record->metadata),
      ];
    }
    return $rows;
  }

  /**
   * An evidence-required save on an unkeyed chain is vetoed before mutation.
   *
   * "No fallback to unkeyed integrity or best-effort logging can satisfy the
   * high-assurance class": with no signing key configured, the chain would
   * accept the rows but could not sign them, so the governed mutation must
   * not execute at all.
   */
  public function testSaveVetoedWhenChainUnkeyed(): void {
    $this->requireEvidenceFor(['entity_write']);
    $this->setGovernedAccount();

    $node = Node::create(['type' => self::TYPE, 'title' => 'Vetoed draft']);
    try {
      $node->save();
      $this->fail('The evidence-required save must be vetoed on an unkeyed chain.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString('evidence_unkeyed', $e->getMessage());
    }

    // The mutation did not execute.
    $count = (int) \Drupal::entityQuery('node')->accessCheck(FALSE)->count()->execute();
    $this->assertSame(0, $count, 'No node was persisted by the vetoed save.');

    // The veto itself left a refusal row with the stable reason code.
    $vetoes = $this->chainRows('evidence_veto');
    $this->assertCount(1, $vetoes);
    $this->assertSame('evidence_unkeyed', $vetoes[0]['metadata']['reason']);
  }

  /**
   * A keyed evidence-required save writes a correlated precommit and receipt.
   *
   * The precommit is appended before the mutation inside the same
   * transaction, carrying principal, policy digest, decision, and target;
   * the entity_save receipt row completes it with the persisted identity and
   * the shared correlation id. Both rows exist or the save did not happen.
   */
  public function testKeyedSaveWritesCorrelatedPrecommitAndReceipt(): void {
    $this->requireEvidenceFor(['entity_write']);
    $this->configureSigningKey();
    $account = $this->setGovernedAccount();

    $this->container->get('request_stack')->getCurrentRequest()
      ->headers->set('X-Request-Id', 'req-kernel-1');
    $node = Node::create(['type' => self::TYPE, 'title' => 'Evidenced draft']);
    $node->save();

    $precommits = $this->chainRows('evidence_precommit');
    $this->assertCount(1, $precommits);
    $meta = $precommits[0]['metadata'];
    $this->assertSame('entity_write', $meta['action_class']);
    $this->assertSame('allow', $meta['decision']);
    $this->assertSame('default', $meta['profile']);
    $this->assertSame((string) $account->id(), (string) $meta['principal_uid']);
    $this->assertNotSame('', (string) $meta['correlation_id']);
    $this->assertStringStartsWith('sha256:', (string) $meta['policy_digest']);
    // Delegation binding: present and NULL on the role-fallback channel (an
    // OAuth request records its validated consumer client id here).
    $this->assertArrayHasKey('consumer_client_id', $meta);
    $this->assertNull($meta['consumer_client_id']);
    // The caller's own correlation header is recorded verbatim.
    $this->assertSame('req-kernel-1', $meta['request_id']);
    $this->assertSame($node->uuid(), $meta['target']['uuid']);
    $this->assertSame('node', $meta['target']['entity_type']);

    // The receipt is the entity_save row, completed with the correlation id.
    $saves = $this->chainRows('entity_save');
    $this->assertCount(1, $saves);
    $evidence = $saves[0]['metadata']['evidence'];
    $this->assertSame($meta['correlation_id'], $evidence['correlation_id']);

    // The chain verifies keyed end to end — the evidence is signed, not just
    // present.
    $verify = $this->container->get('mcp_sentinel.audit_logger')->verifyChain();
    $this->assertTrue($verify['ok']);
    $this->assertSame(0, $verify['unkeyed_rows']);
  }

  /**
   * The audit-disabled veto still leaves its refusal row.
   *
   * The refusal is written through the always path: recording an
   * evidence_audit_disabled veto through the ordinary log() gate would be
   * suppressed by the very flag it reports on, and a refusal that vanishes
   * reads as "nothing happened".
   */
  public function testAuditDisabledVetoLeavesRefusalRow(): void {
    $this->requireEvidenceFor(['entity_write']);
    $this->configureSigningKey();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('audit_enabled', FALSE)
      ->save();
    $this->setGovernedAccount();

    $node = Node::create(['type' => self::TYPE, 'title' => 'Unaudited draft']);
    try {
      $node->save();
      $this->fail('The evidence-required save must be vetoed while auditing is disabled.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString('evidence_audit_disabled', $e->getMessage());
    }

    $count = (int) \Drupal::entityQuery('node')->accessCheck(FALSE)->count()->execute();
    $this->assertSame(0, $count, 'No node was persisted by the vetoed save.');

    $vetoes = $this->chainRows('evidence_veto');
    $this->assertCount(1, $vetoes);
    $this->assertSame('evidence_audit_disabled', $vetoes[0]['metadata']['reason']);
  }

  /**
   * An evidence-store outage vetoes the mutation, not just the logging.
   *
   * With the chain's storage gone, the precommit append fails inside the save
   * transaction; the failure aborts the save. "Best-effort logging" would be
   * the opposite: a persisted node and a swallowed exception.
   */
  public function testStorageOutageVetoesSave(): void {
    $this->requireEvidenceFor(['entity_write']);
    $this->configureSigningKey();
    $this->setGovernedAccount();

    $this->container->get('database')->schema()->dropTable('audit_chain_log');

    $node = Node::create(['type' => self::TYPE, 'title' => 'Outage draft']);
    try {
      $node->save();
      $this->fail('The save must abort when the evidence store is unavailable.');
    }
    catch (EntityStorageException) {
      // Expected: the append failure propagated and aborted the save.
    }

    $count = (int) \Drupal::entityQuery('node')->accessCheck(FALSE)->count()->execute();
    $this->assertSame(0, $count, 'No node was persisted during the evidence-store outage.');
  }

  /**
   * A store that times out mid-append vetoes the save like an outage does.
   *
   * Distinct from the dropped-table outage: the chain is present and healthy
   * by every precondition the veto checks, and only the append itself hangs
   * long enough for the storage layer to give up. The resulting exception
   * aborts the save — a timed-out append is an append that did not happen.
   */
  public function testStoreTimeoutVetoesSave(): void {
    // Swapped in before any evidence service is instantiated, so the lazily
    // built audit logger and guard both receive it.
    $timingOut = new class() implements AuditChainLoggerInterface {

      /**
       * {@inheritdoc}
       */
      public function log(string $channel, string $operation, array $metadata = []): void {
        throw new \RuntimeException('Lock wait timeout exceeded appending to the audit chain.');
      }

      /**
       * {@inheritdoc}
       */
      public function verify(): array {
        return [
          'ok' => TRUE,
          'broken_at' => NULL,
          'reason' => NULL,
          'unkeyed_rows' => 0,
          'unkeyed_through' => NULL,
          'verified_from' => NULL,
          'sealed_through' => NULL,
          'seal_intact' => NULL,
        ];
      }

      /**
       * {@inheritdoc}
       */
      public function sealPrefix(int $throughId, string $reason): array {
        return ['sealed' => FALSE, 'message' => 'stub', 'seal' => NULL];
      }

      /**
       * {@inheritdoc}
       */
      public function getSeal(): ?array {
        return NULL;
      }

      /**
       * {@inheritdoc}
       */
      public function decodeMetadata(string $stored, string $encryptionProfile = ''): array {
        return [];
      }

      /**
       * {@inheritdoc}
       */
      public function reencrypt(string $fromProfile, string $toProfile, int $limit = 0): array {
        return ['updated' => 0, 'failed' => 0, 'remaining' => 0, 'refused' => NULL];
      }

      /**
       * {@inheritdoc}
       */
      public function prune(string $channel, int $retentionDays): int {
        return 0;
      }

    };
    // The real logger and guard may already be instantiated from setUp, so
    // replace the public services with instances built around the faulting
    // chain rather than relying on lazy construction order.
    $this->container->set('audit_chain.logger', $timingOut);
    $logger = new McpAuditLogger(
      $this->container->get('config.factory'),
      $this->container->get('request_stack'),
      $timingOut,
      NULL,
      $this->container->get('database'),
    );
    $this->container->set('mcp_sentinel.audit_logger', $logger);
    $this->container->set('mcp_sentinel.evidence_guard', new McpEvidenceGuard(
      $this->container->get('config.factory'),
      $timingOut,
      $this->container->get('key.repository'),
      $logger,
      $this->container->get('uuid'),
      $this->container->get('current_user'),
      $this->container->get('keyvalue'),
      $this->container->get('datetime.time'),
      $this->container->get('mcp_sentinel.oauth_context'),
      $this->container->get('request_stack'),
      $this->container->get('database'),
    ));

    $this->requireEvidenceFor(['entity_write']);
    $this->configureSigningKey();
    $this->setGovernedAccount();

    $node = Node::create(['type' => self::TYPE, 'title' => 'Timed-out draft']);
    try {
      $node->save();
      $this->fail('The save must abort when the evidence append times out.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString('timeout', $e->getMessage());
    }

    $count = (int) \Drupal::entityQuery('node')->accessCheck(FALSE)->count()->execute();
    $this->assertSame(0, $count, 'No node was persisted during the append timeout.');
  }

  /**
   * A save that fails after its precommit leaves no orphaned evidence.
   *
   * The atomic co-commit half of the contract, proven from the other side:
   * the precommit append succeeds, the mutation itself then fails, and the
   * rollback removes the precommit with it. Evidence rows describe actions
   * that happened — a precommit for a mutation that never executed would be
   * evidence of nothing.
   */
  public function testFailedSaveLeavesNoOrphanPrecommit(): void {
    $this->requireEvidenceFor(['entity_write']);
    $this->configureSigningKey();
    $this->setGovernedAccount();

    // Break the mutation, not the evidence store: the node field-data table
    // is gone, so presave (and the precommit) succeed and the entity insert
    // itself fails.
    $this->container->get('database')->schema()->dropTable('node_field_data');

    $node = Node::create(['type' => self::TYPE, 'title' => 'Doomed draft']);
    try {
      $node->save();
      $this->fail('The save must fail once its storage is broken.');
    }
    catch (EntityStorageException) {
      // Expected.
    }

    $this->assertCount(
      0,
      $this->chainRows('evidence_precommit'),
      'The rollback removed the precommit along with the failed mutation.',
    );
  }

  /**
   * An evidence-required delete on an unkeyed chain is vetoed before removal.
   */
  public function testDeleteVetoedWhenChainUnkeyed(): void {
    $this->setGovernedAccount();
    $node = Node::create(['type' => self::TYPE, 'title' => 'Keep me']);
    $node->save();

    $this->requireEvidenceFor(['entity_delete']);

    try {
      $node->delete();
      $this->fail('The evidence-required delete must be vetoed on an unkeyed chain.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString('evidence_unkeyed', $e->getMessage());
    }

    $this->assertNotNull(
      \Drupal::entityTypeManager()->getStorage('node')->loadUnchanged((int) $node->id()),
      'The node survived the vetoed delete.',
    );
    $vetoes = $this->chainRows('evidence_veto');
    $this->assertCount(1, $vetoes);
    $this->assertSame('entity_delete', $vetoes[0]['metadata']['action_class']);
  }

  /**
   * A keyed evidence-required delete writes a correlated precommit + receipt.
   */
  public function testKeyedDeleteWritesCorrelatedPrecommitAndReceipt(): void {
    $this->configureSigningKey();
    $this->setGovernedAccount();
    $node = Node::create(['type' => self::TYPE, 'title' => 'Remove me']);
    $node->save();

    $this->requireEvidenceFor(['entity_delete']);
    $node->delete();

    $precommits = $this->chainRows('evidence_precommit');
    $this->assertCount(1, $precommits);
    $meta = $precommits[0]['metadata'];
    $this->assertSame('entity_delete', $meta['action_class']);
    $this->assertSame('delete', $meta['operation']);

    $deletes = $this->chainRows('entity_delete');
    $this->assertCount(1, $deletes);
    $this->assertSame(
      $meta['correlation_id'],
      $deletes[0]['metadata']['evidence']['correlation_id'],
    );
  }

  /**
   * An out-of-transaction receipt failure becomes an explicit uncertain state.
   *
   * When the mutation is already durable and only its execution receipt
   * fails, the caller gets an explicit evidence_uncertain refusal (never an
   * unproven success), the failure lands in the reconciliation ledger exactly
   * once however often it is delivered, and reconciliation appends the late
   * receipt — marked reconciled — once the store recovers. A second
   * reconciliation run appends nothing.
   */
  public function testUncertainReceiptRecordedDeduplicatedAndReconciled(): void {
    $this->configureSigningKey();
    $this->setGovernedAccount();
    $node = Node::create(['type' => self::TYPE, 'title' => 'Receipt subject']);
    $node->save();

    /** @var \Drupal\mcp_sentinel\Service\McpEvidenceGuard $guard */
    $guard = $this->container->get('mcp_sentinel.evidence_guard');
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile */
    $profile = \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->load('default');
    $correlation = $guard->precommit($profile, 'entity_write', $node, 'update');

    $this->container->get('database')->schema()->dropTable('audit_chain_log');
    $metadata = ['entity_type' => 'node', 'id' => $node->id(), 'label' => $node->label()];

    // First delivery: explicit uncertainty, never silence.
    try {
      $guard->receipt($correlation, 'entity_save', $metadata);
      $this->fail('A failed out-of-transaction receipt must refuse explicitly.');
    }
    catch (\RuntimeException $e) {
      $this->assertStringContainsString('evidence_uncertain', $e->getMessage());
    }
    $this->assertSame(1, $guard->uncertainCount());

    // Duplicate delivery of the same receipt: still one ledger entry.
    try {
      $guard->receipt($correlation, 'entity_save', $metadata);
      $this->fail('The receipt delivered again must refuse explicitly too.');
    }
    catch (\RuntimeException) {
      // Expected.
    }
    $this->assertSame(1, $guard->uncertainCount());

    // Retry while the store is still down changes nothing.
    $result = $guard->reconcile();
    $this->assertSame(0, $result['reconciled']);
    $this->assertSame(1, $result['remaining']);

    // Recovery: the store returns, reconciliation appends the late receipt.
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $result = $guard->reconcile();
    $this->assertSame(1, $result['reconciled']);
    $this->assertSame(0, $result['remaining']);
    $this->assertSame(0, $guard->uncertainCount());

    $rows = $this->chainRows('entity_save');
    $this->assertCount(1, $rows);
    $this->assertSame($correlation, $rows[0]['metadata']['evidence']['correlation_id']);
    $this->assertTrue($rows[0]['metadata']['evidence']['reconciled']);

    // Reconciling an empty ledger appends nothing more.
    $result = $guard->reconcile();
    $this->assertSame(0, $result['reconciled']);
    $this->assertCount(1, $this->chainRows('entity_save'));
  }

  /**
   * The uncertain ledger is retried by cron and visible on the status report.
   *
   * An uncertain receipt that nobody surfaces decays into silent evidence
   * loss. Until it reconciles, the status report carries an error naming the
   * pending count; ordinary cron runs the retry; once reconciled the row
   * clears.
   */
  public function testCronReconcilesAndRequirementsSurfaceTheLedger(): void {
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_webhook_delivery']);
    $this->configureSigningKey();

    /** @var \Drupal\mcp_sentinel\Service\McpEvidenceGuard $guard */
    $guard = $this->container->get('mcp_sentinel.evidence_guard');
    $guard->recordUncertain(
      'test-correlation-1',
      'entity_save',
      [
        'entity_type' => 'node',
        'id' => '42',
        'evidence' => ['correlation_id' => 'test-correlation-1', 'precommit' => TRUE],
      ],
      new \RuntimeException('simulated store outage'),
    );

    require_once \Drupal::root() . '/core/includes/install.inc';
    require_once \Drupal::root() . '/' . \Drupal::service('extension.list.module')
      ->getPath('mcp_sentinel') . '/mcp_sentinel.install';

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_evidence_uncertain', $requirements);
    $this->assertSame(REQUIREMENT_ERROR, $requirements['mcp_sentinel_evidence_uncertain']['severity']);

    mcp_sentinel_cron();

    $this->assertSame(0, $guard->uncertainCount());
    $rows = $this->chainRows('entity_save');
    $this->assertCount(1, $rows);
    $this->assertTrue($rows[0]['metadata']['evidence']['reconciled']);
    $this->assertArrayNotHasKey(
      'mcp_sentinel_evidence_uncertain',
      mcp_sentinel_requirements('runtime'),
    );
  }

  /**
   * A profile with no evidence-required classes ignores the signing state.
   *
   * The upgrade-safety direction: absent configuration changes no behavior,
   * even on a chain that could not sign a row.
   */
  public function testSaveUnaffectedWhenClassNotRequired(): void {
    $this->setGovernedAccount();

    $node = Node::create(['type' => self::TYPE, 'title' => 'Ordinary draft']);
    $node->save();

    $this->assertNotEmpty($node->id());
    $this->assertCount(0, $this->chainRows('evidence_precommit'));
    $this->assertCount(0, $this->chainRows('evidence_veto'));
  }

}
