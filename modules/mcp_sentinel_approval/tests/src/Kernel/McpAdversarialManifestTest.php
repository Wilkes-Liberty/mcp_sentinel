<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Enum\McpDecisionReason;
use Drupal\mcp_sentinel\Service\McpEvidenceGuard;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\mcp_sentinel_approval\Service\McpApprovalExecutor;
use Drupal\mcp_sentinel_approval\Service\McpManifestBinder;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Adversarial sweep for the sealed action manifest (slice 6 of #3616538).
 *
 * Covers the matrix items that slices 1-5 did not prove: action-manifest
 * expiry, stale target revision, overlapping approve (idempotency_replay),
 * a still-pending second consume, the correlated postcondition receipt,
 * and a detectable postcondition discrepancy. Tampering, reviewer
 * conflict, break-glass, superuser refusal, promotion separation and
 * the safety floor are already covered elsewhere and are not repeated.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAdversarialManifestTest extends KernelTestBase {

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
    'mcp_sentinel_approval',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installEntitySchema('mcp_approval_request');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel_approval', ['mcp_sentinel_manifest_used']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installConfig([
      'filter',
      'node',
      'mcp_sentinel',
      'mcp_sentinel_approval',
    ]);

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent']);
    $role->grantPermission('delete any article content');
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    McpPolicyProfile::create([
      'id' => 'agent_delete',
      'label' => 'Agent delete profile',
      'roles' => ['mcp_agent'],
      'weight' => 10,
      'allow_write' => TRUE,
      'allow_delete' => TRUE,
    ])->save();

    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();

    Key::create([
      'id' => 'adversarial_test_key',
      'label' => 'Adversarial test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'adversarial-manifest-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'adversarial_test_key')
      ->save();
  }

  /**
   * An expired action manifest refuses with manifest_expired.
   *
   * Break-glass TTL tests do not cover this clock: this is the sealed
   * action's own expiry, checked at approve time.
   */
  public function testExpiredActionManifestRefuses(): void {
    $nid = $this->queueDelete('Expire me');
    $request = $this->loadSoleRequest();
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')
      ->open($request->getSealedManifest());
    $this->assertNotNull($manifest);

    $this->setApproverCurrentUser();
    $this->bindClock($manifest->expires() + 1);
    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);

    $this->assertFalse($result['executed']);
    $this->assertFalse($result['error']);
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'An expired manifest must not delete the target.',
    );
    $this->assertSame(
      McpDecisionReason::ManifestExpired->value,
      $this->lastApprovalReason(),
    );
  }

  /**
   * A changed live revision refuses with target_stale.
   */
  public function testStaleTargetRevisionRefuses(): void {
    $nid = $this->queueDelete('Stale me');
    $request = $this->loadSoleRequest();
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')
      ->open($request->getSealedManifest());
    $this->assertNotNull($manifest);
    $this->assertContains('target_revision', $manifest->preconditions());
    $sealedRevision = $manifest->target()['revision'];
    $this->assertNotNull($sealedRevision);

    $node = $this->container->get('entity_type.manager')->getStorage('node')->load($nid);
    $this->assertNotNull($node);
    $node->setNewRevision(TRUE);
    $node->setTitle('Changed after the seal');
    $node->save();
    $this->assertNotSame($sealedRevision, (string) $node->getRevisionId());

    $this->setApproverCurrentUser();
    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);

    $this->assertFalse($result['executed']);
    $this->assertFalse($result['error']);
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'A stale target revision must not be deleted.',
    );
    $this->assertSame(
      McpDecisionReason::TargetStale->value,
      $this->lastApprovalReason(),
    );
  }

  /**
   * Two overlapping approve attempts consume the idempotency key once.
   *
   * The second in-memory approve still sees pending (it loaded before
   * the first save) and the unique consume is idempotency_replay.
   */
  public function testConcurrentApproveSecondConsumeIsIdempotencyReplay(): void {
    $this->config('system.site')->set('name', 'Before concurrent')->save();
    $requestId = $this->queueConfigImport([
      'name' => 'After concurrent',
    ]);
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $first */
    $first = $storage->load($requestId);
    $this->assertNotNull($first);
    // Two load()s without a cache reset return the same instance, so the
    // second approve would see the first decision and throw instead of
    // hitting the consume unique key.
    $storage->resetCache([$requestId]);
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $overlapping */
    $overlapping = $storage->load($requestId);
    $this->assertNotNull($overlapping);
    $this->assertNotSame($first, $overlapping);
    $this->assertTrue($first->isPending());
    $this->assertTrue($overlapping->isPending());

    $this->setApproverCurrentUser();
    $executor = $this->container->get('mcp_sentinel_approval.executor');
    $won = $executor->approve($first);
    $this->assertTrue($won['executed'], $won['message']);
    $this->assertSame('After concurrent', $this->config('system.site')->get('name'));
    $this->assertTrue($overlapping->isPending(), 'The overlapping copy is still pending in memory.');

    $lost = $executor->approve($overlapping);
    $this->assertFalse($lost['executed']);
    $this->assertFalse($lost['error']);
    $this->assertSame('After concurrent', $this->config('system.site')->get('name'));
    $this->assertSame(1, $this->consumedKeyCount());
    $this->assertSame(
      McpDecisionReason::IdempotencyReplay->value,
      $this->lastApprovalReason(),
    );
  }

  /**
   * A still-pending second consume is idempotency_replay, not a re-decision.
   *
   * Distinct from testDoubleApproveThrowsAndDoesNotReExecute: the
   * request has not been decided; only the sealed key has been used.
   */
  public function testPendingReplaySecondConsumeIsIdempotencyReplay(): void {
    $nid = $this->queueDelete('Replay me');
    $request = $this->loadSoleRequest();
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')
      ->open($request->getSealedManifest());
    $this->assertNotNull($manifest);

    $consumed = $this->container->get('mcp_sentinel_approval.manifest_binder')
      ->consume($manifest, (int) $request->id());
    $this->assertTrue($consumed);
    $this->assertTrue($request->isPending());

    $this->setApproverCurrentUser();
    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);

    $this->assertFalse($result['executed']);
    $this->assertFalse($result['error']);
    $this->assertFalse($request->isPending());
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'A pending replay must not delete the target.',
    );
    $this->assertSame(1, $this->consumedKeyCount());
    $this->assertSame(
      McpDecisionReason::IdempotencyReplay->value,
      $this->lastApprovalReason(),
    );
  }

  /**
   * Execution emits a correlated receipt with postconditions.
   *
   * The receipt is the existing evidence guard's, extended with what
   * actually happened: target id/uuid/revision and outcome.
   */
  public function testApprovalEmitsCorrelatedReceiptWithPostconditions(): void {
    $nid = $this->queueDelete('Receipt me');
    $request = $this->loadSoleRequest();
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')
      ->open($request->getSealedManifest());
    $this->assertNotNull($manifest);

    $this->setApproverCurrentUser();
    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    $this->assertTrue($result['executed'], $result['message']);
    $this->assertNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
    );

    $meta = $this->lastApprovalMetadata();
    $this->assertTrue($meta['executed']);
    $this->assertSame($manifest->id(), $meta['manifest_id']);
    $this->assertArrayHasKey('evidence', $meta);
    $this->assertSame($manifest->id(), $meta['evidence']['correlation_id']);
    $postconditions = $meta['evidence']['postconditions'];
    $this->assertSame((string) $nid, $postconditions['target']['id']);
    $this->assertSame($manifest->target()['uuid'], $postconditions['target']['uuid']);
    $this->assertSame($manifest->target()['revision'], $postconditions['target']['revision']);
    $this->assertSame('deleted', $postconditions['outcome']);
    $this->assertFalse($postconditions['exists']);
  }

  /**
   * A postcondition discrepancy is recorded and refuses the caller.
   */
  public function testPostconditionDiscrepancyIsDetectableAndRefuses(): void {
    $this->setApproverCurrentUser();
    /** @var \Drupal\mcp_sentinel\Service\McpEvidenceGuard $guard */
    $guard = $this->container->get('mcp_sentinel.evidence_guard');

    $observed = [
      'target' => [
        'id' => '4',
        'uuid' => 'live-uuid',
        'revision' => '11',
      ],
      'outcome' => 'present',
      'exists' => TRUE,
    ];
    $expected = [
      'target' => [
        'id' => '4',
        'uuid' => 'sealed-uuid',
        'revision' => '11',
      ],
      'outcome' => 'deleted',
      'exists' => FALSE,
    ];

    try {
      $guard->receipt('corr-discrepancy', 'approval_decision', [
        'entity_type' => 'node',
        'id' => '4',
        'postconditions' => $observed,
      ], $expected);
      $this->fail('A postcondition discrepancy must refuse explicitly.');
    }
    catch (\RuntimeException $e) {
      $this->assertStringContainsString(
        McpEvidenceGuard::REASON_POSTCONDITION_DISCREPANCY,
        $e->getMessage(),
      );
    }

    $rows = $this->approvalDecisionRows();
    $this->assertNotEmpty($rows);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) end($rows)['metadata']);
    $this->assertTrue($meta['evidence']['discrepancy']);
    $this->assertSame($observed, $meta['evidence']['postconditions']);
    $this->assertSame(
      McpEvidenceGuard::REASON_POSTCONDITION_DISCREPANCY,
      $meta['reason'],
    );
  }

  /**
   * Sets a governed user with delete rights as the current user.
   */
  private function setGovernedCurrentUser(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Switches to a distinct approver who may decide the queued request.
   */
  private function setApproverCurrentUser(): void {
    $current = $this->container->get('current_user');
    $current->setAccount(new AnonymousUserSession());
    $approver = $this->createUser(
      ['approve mcp sentinel operations'],
      NULL,
      TRUE,
    );
    $current->setAccount($approver);
  }

  /**
   * Queues a gated bulk delete and returns the target node id.
   *
   * @param string $title
   *   Node title.
   *
   * @return int
   *   The node id.
   */
  private function queueDelete(string $title): int {
    $this->setGovernedCurrentUser();
    $node = Node::create(['type' => 'article', 'title' => $title]);
    $node->save();
    $nid = (int) $node->id();
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'delete');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', [(string) $nid]);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();
    return $nid;
  }

  /**
   * Creates a pending config_import request and returns its id.
   *
   * @param array<string, mixed> $data
   *   Config values to apply on approve.
   *
   * @return int
   *   The request id.
   */
  private function queueConfigImport(array $data): int {
    $this->setGovernedCurrentUser();
    $account = $this->container->get('current_user');
    $payload = ['data' => $data];
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')->tryMint(
      $account,
      'config_import',
      ['type' => 'config', 'id' => 'system.site'],
      $payload,
    );
    $this->assertNotNull($manifest);
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = $storage->create([
      'requested_by' => (int) $account->id(),
      'operation' => 'config_import',
      'entity_type' => 'config',
      'entity_id' => 'system.site',
      'payload' => (string) json_encode($payload),
      'status' => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest' => $manifest->toJson(),
    ]);
    $request->save();
    return (int) $request->id();
  }

  /**
   * The sole queued approval request.
   */
  private function loadSoleRequest(): McpApprovalRequestInterface {
    $requests = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request')
      ->loadMultiple();
    $this->assertCount(1, $requests);
    $request = reset($requests);
    $this->assertInstanceOf(McpApprovalRequestInterface::class, $request);
    return $request;
  }

  /**
   * Rebinds the binder and executor to a frozen clock.
   *
   * @param int $now
   *   Unix timestamp returned by getRequestTime().
   */
  private function bindClock(int $now): void {
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn($now);
    $binder = new McpManifestBinder(
      $this->container->get('mcp_sentinel.action_manifest_sealer'),
      $this->container->get('database'),
      $time,
      $this->container->get('current_user'),
      $this->container->get('entity_type.manager'),
    );
    $this->container->set('mcp_sentinel_approval.manifest_binder', $binder);
    $this->container->set('mcp_sentinel_approval.executor', new McpApprovalExecutor(
      $this->container->get('entity_type.manager'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('current_user'),
      $time,
      $this->container->get('config.factory'),
      $this->container->get('module_installer'),
      $this->container->get('mcp_sentinel_approval.break_glass'),
      $this->container->get('module_handler'),
      $binder,
      $this->container->get('mcp_sentinel.evidence_guard'),
    ));
  }

  /**
   * How many idempotency keys have been consumed.
   */
  private function consumedKeyCount(): int {
    return (int) $this->container->get('database')
      ->select('mcp_sentinel_manifest_used', 'u')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Reason on the latest approval_decision row.
   */
  private function lastApprovalReason(): ?string {
    $meta = $this->lastApprovalMetadata();
    return isset($meta['reason']) ? (string) $meta['reason'] : NULL;
  }

  /**
   * Metadata of the latest approval_decision row.
   *
   * @return array<string, mixed>
   *   Decoded metadata.
   */
  private function lastApprovalMetadata(): array {
    $rows = $this->approvalDecisionRows();
    $this->assertNotEmpty($rows, 'An approval_decision row must be written.');
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) end($rows)['metadata']);
  }

  /**
   * Approval decision audit rows, oldest first.
   *
   * @return array<int, array<string, mixed>>
   *   Raw rows.
   */
  private function approvalDecisionRows(): array {
    return $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('operation', 'approval_decision')
      ->orderBy('id')
      ->execute()
      ->fetchAll(\PDO::FETCH_ASSOC);
  }

}
