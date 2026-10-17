<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Plugin\QueueWorker\McpWebhookWorker;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Freeze-first mass stop and held side effects (DEV-985).
 *
 * Each deny-path test has a weaken counterpart that fails if the new
 * behaviour still runs when the flag is on.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpKillSwitchFreezeHoldTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;

  /**
   * Synthetic issuer. Not a live IdP.
   */
  private const ISS = 'https://idp.example/realms/agents';

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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'mcp_sentinel', 'key']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_webhook_delivery']);
  }

  /**
   * A person-wide stop refuses every in-scope agent before confirm.
   */
  public function testPersonWideStopRefusesImmediately(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-person');
    $result = $this->killSwitch()->kill([$human], 'person-wide', $this->paladinA());
    $this->assertTrue($result->needsConfirm);
    $this->assertSame(McpKillBlockStatus::KillPending, $result->status);
    $this->assertGreaterThan(0, $result->blockUntil);
    $this->sealSubject('subject-person', 'agent-a');
    $this->expectGenericDeny();
    $this->sealSubject('subject-person', 'agent-b');
    $this->expectGenericDeny();
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_FREEZE));
    $freeze = $this->lastAuditMetadata(McpKillSwitch::AUDIT_FREEZE);
    $this->assertSame($this->paladinA()->storageId(), $freeze['actor']);
    $this->assertArrayHasKey('scope', $freeze);
    $this->assertArrayHasKey('timestamp', $freeze);
    $this->assertSame($result->batchId, $freeze['correlation_id']);
  }

  /**
   * Guard bypass: a person-wide stop does not refuse when freeze is off.
   *
   * This is the red mutation for testPersonWideStopRefusesImmediately.
   */
  public function testPersonWideStopDoesNotRefuseWhenFreezeWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_MASS_FREEZE);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-person-w');
    $this->killSwitch()->kill([$human], 'person-wide', $this->paladinA());
    $this->sealSubject('subject-person-w', 'agent-a');
    $this->assertSame(
      'subject-person-w',
      $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
    );
  }

  /**
   * A tenant-wide stop refuses every in-scope agent before confirm.
   */
  public function testTenantWideStopRefusesImmediately(): void {
    $tenant = McpKillSelector::tenant('tenant-a');
    $result = $this->killSwitch()->kill([$tenant], 'tenant-wide', $this->paladinA());
    $this->assertTrue($result->needsConfirm);
    $this->sealSubject('subject-tenant', 'agent-a');
    $this->expectGenericDeny();
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_FREEZE));
    $this->assertStringContainsString('tenant:tenant-a', $this->lastAuditMetadata(McpKillSwitch::AUDIT_FREEZE)['scope']);
  }

  /**
   * Guard bypass: a tenant-wide stop does not refuse when freeze is off.
   */
  public function testTenantWideStopDoesNotRefuseWhenFreezeWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_MASS_FREEZE);
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('tenant-a')],
      'tenant-wide',
      $this->paladinA(),
    );
    $this->sealSubject('subject-tenant-w', 'agent-a');
    $this->assertSame(
      'subject-tenant-w',
      $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
    );
  }

  /**
   * An unconfirmed window expiry keeps the freeze and fires escalation.
   */
  public function testUnconfirmedFreezeStaysAndEscalates(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-esc');
    $result = $this->killSwitch()->kill([$human], 'escalate', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $result->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $this->sealSubject('subject-esc', 'agent-a');
    $this->expectGenericDeny();
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_ESCALATE));
    $this->assertSame(0, $this->countAudit(McpKillSwitch::AUDIT_EXPIRE));
    $row = $this->lastAuditMetadata(McpKillSwitch::AUDIT_ESCALATE);
    $this->assertSame($result->batchId, $row['correlation_id']);
    $this->assertArrayHasKey('timestamp', $row);
    $this->assertArrayHasKey('scope', $row);
    $this->killSwitch()->expireDue();
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_ESCALATE));
  }

  /**
   * Guard bypass: the window expiry lifts the freeze when the old path is on.
   */
  public function testUnconfirmedFreezeLiftsWhenTimeoutWeakenOn(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_LIFT_ON_CONFIRM_TIMEOUT);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-esc-w');
    $result = $this->killSwitch()->kill([$human], 'escalate', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $result->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * A second operator confirms, extends (7d cap), and lifts. Self-confirm fails.
   */
  public function testSecondOperatorConfirmExtendLift(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-cel');
    $kill = $this->killSwitch()->kill([$human], 'cel', $this->paladinA());
    try {
      $this->killSwitch()->confirm($kill->batchId, $this->paladinA());
      $this->fail('The requesting operator must not confirm their own stop.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));

    $confirmed = $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Killed, $confirmed->status);
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_CONFIRM));
    $confirm = $this->lastAuditMetadata(McpKillSwitch::AUDIT_CONFIRM);
    $this->assertSame($this->paladinB()->storageId(), $confirm['actor']);
    $this->assertArrayHasKey('timestamp', $confirm);

    try {
      $this->killSwitch()->extend($kill->batchId, $this->paladinB(), McpKillTtl::MAX + 1);
      $this->fail('An extend above 7 days must be refused.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::INVALID_TTL, $e->reasonCode);
    }
    $extended = $this->killSwitch()->extend($kill->batchId, $this->paladinB(), McpKillTtl::MAX);
    $this->assertSame(McpKillTtl::MAX, $extended->ttl);
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_EXTEND));

    $this->sealSubject('subject-cel', 'agent-a');
    $this->expectGenericDeny();
    $unkill = $this->killSwitch()->requestUnkill([$human], 'restore', $this->paladinA());
    $this->killSwitch()->confirmUnkill($unkill->batchId, $this->paladinB());
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
    $this->assertSame(
      'subject-cel',
      $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
    );
  }

  /**
   * An unconfirmed freeze can be lifted by a distinct second operator.
   */
  public function testSecondOperatorLiftsUnconfirmedFreeze(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-lift');
    $kill = $this->killSwitch()->kill([$human], 'lift', $this->paladinA());
    try {
      $this->killSwitch()->lift($kill->batchId, $this->paladinA());
      $this->fail('The requesting operator must not lift their own freeze.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
    $lifted = $this->killSwitch()->lift($kill->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Expired, $lifted->status);
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_LIFT));
    $lift = $this->lastAuditMetadata(McpKillSwitch::AUDIT_LIFT);
    $this->assertSame($this->paladinB()->storageId(), $lift['actor']);
    $this->assertArrayHasKey('scope', $lift);
    $this->assertArrayHasKey('timestamp', $lift);
  }

  /**
   * Break-glass keep, extend, and lift each write one break-glass audit row.
   */
  public function testBreakGlassKeepExtendLift(): void {
    $keep = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|subject-bg-keep')],
      'bg-keep',
      $this->paladinA(),
    );
    $this->killSwitch()->breakGlass(
      $keep->batchId,
      McpKillBreakGlassAction::Keep,
      $this->paladinB(),
    );
    $this->assertSame(McpKillBlockStatus::Killed, McpKillBlockStatus::from(
      (string) $this->killSwitch()->status(McpKillSelector::humanKey(self::ISS . '|subject-bg-keep'))['status'],
    ));
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_BREAK_GLASS));
    $this->assertSame(0, $this->countAudit(McpKillSwitch::AUDIT_CONFIRM));

    $extend = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|subject-bg-ext')],
      'bg-ext',
      $this->paladinA(),
    );
    $this->killSwitch()->breakGlass(
      $extend->batchId,
      McpKillBreakGlassAction::Extend,
      $this->paladinB(),
      McpKillTtl::MAX,
    );
    $this->assertSame(2, $this->countAudit(McpKillSwitch::AUDIT_BREAK_GLASS));
    $this->assertSame(0, $this->countAudit(McpKillSwitch::AUDIT_EXTEND));

    $lift = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|subject-bg-lift')],
      'bg-lift',
      $this->paladinA(),
    );
    $this->killSwitch()->breakGlass(
      $lift->batchId,
      McpKillBreakGlassAction::Lift,
      $this->paladinB(),
    );
    $this->assertFalse($this->killSwitch()->isKilled('', self::ISS . '|subject-bg-lift'));
    $this->assertSame(3, $this->countAudit(McpKillSwitch::AUDIT_BREAK_GLASS));
    $this->assertSame(0, $this->countAudit(McpKillSwitch::AUDIT_LIFT));
    $bg = $this->lastAuditMetadata(McpKillSwitch::AUDIT_BREAK_GLASS);
    $this->assertSame(McpKillBreakGlassAction::Lift->value, $bg['break_glass_action']);
    $this->assertArrayHasKey('timestamp', $bg);
    $this->assertArrayHasKey('scope', $bg);
  }

  /**
   * A single-agent stop holds in-scope deliveries and lets others through.
   */
  public function testSingleAgentStopHoldsQueuedDeliveries(): void {
    $this->assertHoldForSelector(
      $this->principalSelector('subject-hold-p', 'agent-hold-p'),
      'subject-hold-p',
      'agent-hold-p',
    );
  }

  /**
   * A person-wide stop holds in-scope deliveries and lets others through.
   */
  public function testPersonWideStopHoldsQueuedDeliveries(): void {
    $this->assertHoldForSelector(
      McpKillSelector::humanKey(self::ISS . '|subject-hold-h'),
      'subject-hold-h',
      'agent-hold-h',
    );
  }

  /**
   * A tenant-wide stop holds in-scope deliveries and lets others through.
   */
  public function testTenantWideStopHoldsQueuedDeliveries(): void {
    $this->assertHoldForSelector(
      McpKillSelector::tenant('tenant-a'),
      'subject-hold-t',
      'agent-hold-t',
    );
  }

  /**
   * Guard bypass: in-scope deliveries still send when hold is off.
   */
  public function testQueuedDeliveriesSendWhenHoldWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_QUEUE_HOLD);
    $this->enableEndpoint();
    $this->sealSubject('subject-hold-w', 'agent-hold-w');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'in']);
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-hold-w', 'agent-hold-w')],
      'hold-off',
      $this->paladinA(),
    );
    $row = $this->latestDelivery();
    $this->assertSame('pending', $row['status']);
    $history = [];
    $this->worker($history)->processItem($this->queueItem((int) $row['id'], $row));
    $this->assertSame('sent', $this->loadDelivery((int) $row['id'])['status']);
    $this->assertCount(1, $history);
  }

  /**
   * Release delivers the original id, payload, and body signature.
   */
  public function testReleaseDeliversUnchangedAndDiscardNeverDelivers(): void {
    $this->createSigningKey();
    $this->enableEndpoint('mcp_wh_secret');
    $this->sealSubject('subject-rel', 'agent-rel');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'held-release']);
    $in = $this->latestDelivery();
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-rel', 'agent-rel')],
      'hold',
      $this->paladinA(),
    );
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery((int) $in['id'])['status']);
    $this->assertSame(1, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
    $hold = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_HOLD);
    $this->assertSame($this->paladinA()->storageId(), $hold['actor']);
    $this->assertArrayHasKey('item_ids', $hold);
    $this->assertArrayHasKey('timestamp', $hold);

    $history = [];
    $released = $this->queue()->releaseHeld([(int) $in['id']], $this->paladinB());
    $this->assertSame([(int) $in['id']], $released);
    $this->assertSame(1, $this->countAudit(McpWebhookQueueManager::AUDIT_RELEASE));
    $this->worker($history)->processItem($this->queueItem((int) $in['id'], $in));
    $this->assertCount(1, $history);
    $request = $history[0]['request'];
    $this->assertSame((string) $in['id'], $request->getHeaderLine('X-MCP-Delivery'));
    $this->assertSame((string) $in['payload'], (string) $request->getBody());
    $this->assertSame(
      'sha256=' . hash_hmac('sha256', (string) $in['payload'], 'topsecret'),
      $request->getHeaderLine('X-MCP-Signature'),
    );

    $this->sealSubject('subject-disc', 'agent-disc');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'held-discard']);
    $discardRow = $this->latestDelivery();
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-disc', 'agent-disc')],
      'discard',
      $this->paladinA(),
    );
    $this->queue()->discardHeld([(int) $discardRow['id']], $this->paladinB());
    $this->assertSame(
      McpWebhookQueueManager::STATUS_DISCARDED,
      $this->loadDelivery((int) $discardRow['id'])['status'],
    );
    $this->assertSame(1, $this->countAudit(McpWebhookQueueManager::AUDIT_DISCARD));
    $history = [];
    $this->worker($history)->processItem($this->queueItem((int) $discardRow['id'], $discardRow));
    $this->assertCount(0, $history);
    $this->assertSame(
      McpWebhookQueueManager::STATUS_DISCARDED,
      $this->loadDelivery((int) $discardRow['id'])['status'],
    );
  }

  /**
   * Lifting a freeze does not release held items. Cron does not re-queue them.
   */
  public function testLiftDoesNotReleaseAndCronSkipsHeld(): void {
    $this->enableEndpoint();
    $human = McpKillSelector::humanKey(self::ISS . '|subject-norelease');
    $this->sealSubject('subject-norelease', 'agent-a');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'stay']);
    $row = $this->latestDelivery();
    $kill = $this->killSwitch()->kill([$human], 'hold', $this->paladinA());
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery((int) $row['id'])['status']);
    $this->killSwitch()->lift($kill->batchId, $this->paladinB());
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery((int) $row['id'])['status']);
    $this->assertSame(0, $this->countAudit(McpWebhookQueueManager::AUDIT_RELEASE));

    $this->container->get('database')->update('mcp_sentinel_webhook_delivery')
      ->fields(['next_attempt' => 1])
      ->condition('id', (int) $row['id'])
      ->execute();
    $queue = $this->container->get('queue')->get(McpWebhookQueueManager::QUEUE_NAME);
    $before = $queue->numberOfItems();
    $this->assertSame(0, $this->queue()->requeueDuePendingRows());
    $this->assertSame($before, $queue->numberOfItems());
  }

  /**
   * Guard bypass: lift releases held items when that weaken flag is on.
   */
  public function testLiftReleasesHeldWhenAutoReleaseWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_AUTO_RELEASE_ON_LIFT);
    $this->enableEndpoint();
    $human = McpKillSelector::humanKey(self::ISS . '|subject-autorelease');
    $this->sealSubject('subject-autorelease', 'agent-a');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'auto']);
    $row = $this->latestDelivery();
    $kill = $this->killSwitch()->kill([$human], 'hold', $this->paladinA());
    $this->killSwitch()->lift($kill->batchId, $this->paladinB());
    $this->assertSame('pending', $this->loadDelivery((int) $row['id'])['status']);
  }

  /**
   * Guard bypass: cron re-queues held rows when that weaken flag is on.
   */
  public function testCronRequeuesHeldWhenWeakenOn(): void {
    $this->queue()->weakenForTest(McpWebhookQueueManager::WEAKEN_REQUEUE_HELD);
    $this->enableEndpoint();
    $id = (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => McpWebhookQueueManager::STATUS_HELD,
        'attempts' => 0,
        'created' => 1,
        'next_attempt' => 1,
        'principal_key' => '',
        'human_key' => '',
        'tenant' => '',
      ])->execute();
    $this->assertSame(1, $this->queue()->requeueDuePendingRows());
    $this->assertNotNull(
      $this->loadDelivery($id)['item_id'],
    );
  }

  /**
   * Holds in-scope items and delivers the out-of-scope control row.
   */
  private function assertHoldForSelector(
    McpKillSelector $selector,
    string $sub,
    string $azp,
  ): void {
    $this->enableEndpoint();
    $this->sealSubject($sub, $azp);
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'in-scope']);
    $in = $this->latestDelivery();
    $this->assertNotSame('', $in['principal_key']);
    $this->principalContextHolder()->resetForTest();
    $this->sealSubject('other-out', 'agent-out', 'tenant-out');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'out-scope']);
    $out = $this->latestDelivery();
    $this->assertNotSame($in['id'], $out['id']);

    $this->killSwitch()->kill([$selector], 'hold', $this->paladinA());
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery((int) $in['id'])['status']);
    $this->assertSame('pending', $this->loadDelivery((int) $out['id'])['status']);

    $history = [];
    $worker = $this->worker($history);
    $worker->processItem($this->queueItem((int) $in['id'], $in));
    $worker->processItem($this->queueItem((int) $out['id'], $out));
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery((int) $in['id'])['status']);
    $this->assertSame('sent', $this->loadDelivery((int) $out['id'])['status']);
    $this->assertCount(1, $history);
  }

  /**
   * Configures one HTTPS endpoint.
   */
  private function enableEndpoint(string $secretKey = ''): void {
    $this->config('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'ep1',
          'label' => 'Test',
          'url' => 'https://example.com/hook',
          'secret_key' => $secretKey,
          'events' => [],
          'enabled' => TRUE,
          'allow_internal' => FALSE,
        ],
      ])->save();
  }

  /**
   * Signing key used for the unchanged-signature assertion.
   */
  private function createSigningKey(): void {
    Key::create([
      'id' => 'mcp_wh_secret',
      'label' => 'WH secret',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'topsecret'],
    ])->save();
  }

  /**
   * Queue item payload for a stored row.
   *
   * @param array<string, mixed> $row
   *   Delivery row.
   *
   * @return array<string, mixed>
   *   Worker item.
   */
  private function queueItem(int $id, array $row): array {
    return [
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => (string) ($this->config('mcp_sentinel.settings')->get('webhook_endpoints')[0]['secret_key'] ?? ''),
      ],
      'event_name' => (string) $row['event_name'],
      'payload' => (string) $row['payload'],
      'principal_key' => (string) ($row['principal_key'] ?? ''),
      'human_key' => (string) ($row['human_key'] ?? ''),
      'tenant' => (string) ($row['tenant'] ?? ''),
    ];
  }

  /**
   * Worker with a mocked HTTP client.
   *
   * @param array $history
   *   Captured requests.
   *
   * @param-out array|\ArrayAccess<int, array> $history
   */
  private function worker(array &$history): McpWebhookWorker {
    $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'ok')]));
    $stack->push(Middleware::history($history));
    $this->container->set('http_client', new Client(['handler' => $stack]));
    $worker = $this->container->get('plugin.manager.queue_worker')
      ->createInstance('mcp_sentinel_webhook_delivery');
    $this->assertInstanceOf(McpWebhookWorker::class, $worker);
    return $worker;
  }

  /**
   * Most recently inserted delivery row.
   *
   * @return array<string, mixed>
   *   Row.
   */
  private function latestDelivery(): array {
    $row = $this->container->get('database')
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    return $row;
  }

  /**
   * Loads a delivery row.
   *
   * @return array<string, mixed>
   *   Row.
   */
  private function loadDelivery(int $id): array {
    $row = $this->container->get('database')
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')
      ->condition('id', $id)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    return $row;
  }

  /**
   * Seals a Paladin-shaped principal on the current request.
   */
  private function sealSubject(string $sub, string $azp, string $tenant = 'tenant-a'): void {
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => self::ISS,
      'sub' => $sub,
      'azp' => $azp,
      'tenant' => $tenant,
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $holder = $this->principalContextHolder();
    $holder->resetForTest();
    $stack = $this->container->get('request_stack');
    $current = $stack->getCurrentRequest();
    if ($current !== NULL && $current->hasSession()) {
      $request->setSession($current->getSession());
    }
    $stack->push($request);
    $ctx = $this->container->get('mcp_sentinel.principal_context_factory')
      ->fromRequest($request);
    $holder->seal($ctx, $request);
  }

  /**
   * Principal-key selector.
   */
  private function principalSelector(string $sub, string $azp): McpKillSelector {
    return McpKillSelector::principalKey(self::ISS . '|' . $sub . '|' . $azp);
  }

  /**
   * First operator.
   */
  private function paladinA(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|operator-a');
  }

  /**
   * Named second person.
   */
  private function paladinB(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|operator-b');
  }

  /**
   * Kill-switch service.
   */
  private function killSwitch(): McpKillSwitch {
    return $this->container->get('mcp_sentinel.kill_switch');
  }

  /**
   * Webhook queue manager.
   */
  private function queue(): McpWebhookQueueManager {
    return $this->container->get('mcp_sentinel.webhook_queue_manager');
  }

  /**
   * Dispatcher.
   */
  private function dispatcher(): McpPrincipalContextDispatcher {
    return $this->container->get('mcp_sentinel.principal_context_dispatcher');
  }

  /**
   * Latest metadata for an audit operation.
   *
   * @return array<string, mixed>
   *   Decoded metadata.
   */
  private function lastAuditMetadata(string $operation): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', $operation)
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
  }

  /**
   * Number of audit rows for an operation.
   */
  private function countAudit(string $operation): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Current sealed principal is refused with the generic deny.
   */
  private function expectGenericDeny(): void {
    try {
      $this->dispatcher()->admit(['note' => 'ok'], 'probe');
      $this->fail('The frozen principal must still be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
  }

}
