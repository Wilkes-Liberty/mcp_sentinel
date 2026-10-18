<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Event\McpKillUnavailableConfirmerEvent;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Plugin\QueueWorker\McpWebhookWorker;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
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
 * Mutation checks (test…WhenWeakened) turn one guard off and assert
 * the old fail-open path. They are not operator acceptance tests.
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
    'mcp_sentinel_kill_hook_probe',
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
    $this->setSetting(
      'mcp_sentinel.kill_switch.break_glass_operator',
      self::ISS . '|breakglass-op',
    );
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
   * Mutation check: a person-wide stop does not refuse when freeze is off.
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
   * Mutation check: a tenant-wide stop does not refuse when freeze is off.
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
   * Mutation check: the window expiry lifts the freeze when that flag is on.
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
   * A second operator confirms, extends (7d cap), and lifts.
   *
   * Self-confirm is refused.
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
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_REFUSE));
    $same = $this->lastAuditMetadata(McpKillSwitch::AUDIT_REFUSE);
    $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $same['reason_code']);

    $second = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|subject-cel-lift')],
      'cel-lift',
      $this->paladinA(),
    );
    $lifted = $this->killSwitch()->lift($second->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Expired, $lifted->status);
    $this->assertFalse($this->killSwitch()->isKilled('', self::ISS . '|subject-cel-lift'));
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_LIFT));
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
   * Mutation check: the requester can lift when distinct-operator is off.
   */
  public function testRequesterLiftsWhenDistinctOperatorWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_DISTINCT_OPERATOR);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-lift-w');
    $kill = $this->killSwitch()->kill([$human], 'lift', $this->paladinA());
    $this->killSwitch()->lift($kill->batchId, $this->paladinA());
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Mutation check: an extend above 7 days is accepted when the cap is off.
   */
  public function testExtendAboveSevenDaysWhenTtlCapWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_TTL_CAP);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-ttl-w');
    $kill = $this->killSwitch()->kill([$human], 'ttl', $this->paladinA());
    $extended = $this->killSwitch()->extend(
      $kill->batchId,
      $this->paladinB(),
      McpKillTtl::MAX + 1,
    );
    $this->assertSame(McpKillTtl::MAX + 1, $extended->ttl);
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
      $this->breakGlassOp(),
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
      $this->breakGlassOp(),
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
      $this->breakGlassOp(),
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
   * Mutation check: in-scope deliveries still send when hold is off.
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

    $unkill = $this->killSwitch()->requestUnkill(
      [$this->principalSelector('subject-rel', 'agent-rel')],
      'restore',
      $this->paladinA(),
    );
    $this->killSwitch()->confirmUnkill($unkill->batchId, $this->paladinB());
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
   * Mutation check: lift releases held items when that flag is on.
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
   * Mutation check: cron re-queues held rows when that flag is on.
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
   * Release under an active stop is refused.
   */
  public function testReleaseUnderActiveStopIsRefused(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-rel-stop', 'agent-rel-stop');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'held']);
    $in = $this->latestDelivery();
    $this->assertNotSame('', $in['principal_key']);
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-rel-stop', 'agent-rel-stop')],
      'hold',
      $this->paladinA(),
    );
    $this->assertSame(
      McpWebhookQueueManager::STATUS_HELD,
      $this->loadDelivery((int) $in['id'])['status'],
    );
    try {
      $this->queue()->releaseHeld([(int) $in['id']], $this->paladinB());
      $this->fail('Release must be refused while the scope is still stopped.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SCOPE_STOPPED, $e->reasonCode);
    }
    $this->assertSame(
      McpWebhookQueueManager::STATUS_HELD,
      $this->loadDelivery((int) $in['id'])['status'],
    );
    $this->assertSame(0, $this->countAudit(McpWebhookQueueManager::AUDIT_RELEASE));
    $this->assertSame(1, $this->countAudit(McpWebhookQueueManager::AUDIT_REFUSE));
    $refuse = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_REFUSE);
    $this->assertSame(McpKillSwitchException::SCOPE_STOPPED, $refuse['reason_code']);
    $this->assertSame($this->paladinB()->storageId(), $refuse['actor']);
  }

  /**
   * Mutation check: release under an active stop succeeds when that flag is on.
   */
  public function testReleaseUnderActiveStopWhenWeakened(): void {
    $this->queue()->weakenForTest(McpWebhookQueueManager::WEAKEN_SKIP_RELEASE_UNDER_STOP);
    $this->enableEndpoint();
    $this->sealSubject('subject-rel-w', 'agent-rel-w');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'held']);
    $in = $this->latestDelivery();
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-rel-w', 'agent-rel-w')],
      'hold',
      $this->paladinA(),
    );
    $released = $this->queue()->releaseHeld([(int) $in['id']], $this->paladinB());
    $this->assertSame([(int) $in['id']], $released);
    $this->assertSame('pending', $this->loadDelivery((int) $in['id'])['status']);
  }

  /**
   * Worker registry check holds the row before claim.
   */
  public function testWorkerHoldsBeforeClaimWithoutSending(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-pre', 'agent-pre');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'pre']);
    $row = $this->latestDelivery();
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-pre', 'agent-pre')],
      'hold',
      $this->paladinA(),
    );
    $this->container->get('database')->update('mcp_sentinel_webhook_delivery')
      ->fields(['status' => 'pending'])
      ->condition('id', (int) $row['id'])
      ->execute();
    $history = [];
    $this->worker($history)->processItem($this->queueItem((int) $row['id'], $row));
    $held = $this->loadDelivery((int) $row['id']);
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $held['status']);
    $this->assertNull($held['last_attempt']);
    $this->assertCount(0, $history);
  }

  /**
   * Mutation check: skipping the pre-claim check claims the row first.
   */
  public function testWorkerClaimsWhenPreClaimCheckWeakened(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-pre-w', 'agent-pre-w');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'pre']);
    $row = $this->latestDelivery();
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-pre-w', 'agent-pre-w')],
      'hold',
      $this->paladinA(),
    );
    $this->container->get('database')->update('mcp_sentinel_webhook_delivery')
      ->fields(['status' => 'pending', 'last_attempt' => NULL])
      ->condition('id', (int) $row['id'])
      ->execute();
    $history = [];
    $worker = $this->worker($history);
    $worker->weakenForTest(McpWebhookWorker::WEAKEN_SKIP_PRE_CLAIM_CHECK);
    $worker->processItem($this->queueItem((int) $row['id'], $row));
    $held = $this->loadDelivery((int) $row['id']);
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $held['status']);
    $this->assertNotNull($held['last_attempt']);
    $this->assertCount(0, $history);
  }

  /**
   * A kill between check and claim is caught by the post-claim re-check.
   */
  public function testPostClaimRecheckHoldsAfterKillRace(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-race', 'agent-race');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'race']);
    $row = $this->latestDelivery();
    $history = [];
    $worker = $this->worker($history);
    $worker->killBetweenCheckAndClaimForTest(function (): void {
      $this->insertActiveKill($this->principalSelector('subject-race', 'agent-race'));
    });
    $worker->processItem($this->queueItem((int) $row['id'], $row));
    $held = $this->loadDelivery((int) $row['id']);
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $held['status']);
    $this->assertNotNull($held['last_attempt']);
    $this->assertCount(0, $history);
  }

  /**
   * Mutation check: skipping the post-claim re-check delivers the race.
   */
  public function testPostClaimRecheckWhenWeakened(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-race-w', 'agent-race-w');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'race']);
    $row = $this->latestDelivery();
    $history = [];
    $worker = $this->worker($history);
    $worker->weakenForTest(McpWebhookWorker::WEAKEN_SKIP_POST_CLAIM_RECHECK);
    $worker->killBetweenCheckAndClaimForTest(function (): void {
      $this->insertActiveKill($this->principalSelector('subject-race-w', 'agent-race-w'));
    });
    $worker->processItem($this->queueItem((int) $row['id'], $row));
    $this->assertSame('sent', $this->loadDelivery((int) $row['id'])['status']);
    $this->assertCount(1, $history);
  }

  /**
   * A 500 after claim+kill keeps the row held; lift does not deliver it.
   */
  public function testRetryAfterClaimAndKillStaysHeld(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-500', 'agent-500');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'retry']);
    $row = $this->latestDelivery();
    $history = [];
    $worker = $this->worker500($history);
    $worker->afterClaimForTest(function (): void {
      $this->killSwitch()->kill(
        [$this->principalSelector('subject-500', 'agent-500')],
        'during-post',
        $this->paladinA(),
      );
    });
    $worker->processItem($this->queueItem((int) $row['id'], $row));
    $held = $this->loadDelivery((int) $row['id']);
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $held['status']);
    $this->assertSame(500, (int) $held['last_response_code']);
    $unkill = $this->killSwitch()->requestUnkill(
      [$this->principalSelector('subject-500', 'agent-500')],
      'restore',
      $this->paladinA(),
    );
    $this->killSwitch()->confirmUnkill($unkill->batchId, $this->paladinB());
    $this->assertFalse(
      $this->killSwitch()->isKilled($this->principalSelector('subject-500', 'agent-500')->key),
    );
    $this->assertSame(
      McpWebhookQueueManager::STATUS_HELD,
      $this->loadDelivery((int) $row['id'])['status'],
    );
    $history = [];
    $this->worker($history)->processItem($this->queueItem((int) $row['id'], $row));
    $this->assertCount(0, $history);
    $this->assertSame(
      McpWebhookQueueManager::STATUS_HELD,
      $this->loadDelivery((int) $row['id'])['status'],
    );
    $this->assertGreaterThanOrEqual(2, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
    $hold = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_HOLD);
    $this->assertSame('system', $hold['actor']);
    $this->assertStringContainsString((string) $row['id'], (string) $hold['item_ids']);
  }

  /**
   * Mutation check: a 500 retry overwrites held when the status guard is off.
   */
  public function testRetryOverwritesHeldWhenStatusGuardWeakened(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-500-w', 'agent-500-w');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'retry']);
    $row = $this->latestDelivery();
    $history = [];
    $worker = $this->worker500($history);
    $worker->weakenForTest(McpWebhookWorker::WEAKEN_SKIP_RETRY_STATUS_GUARD);
    $worker->afterClaimForTest(function (): void {
      $this->killSwitch()->kill(
        [$this->principalSelector('subject-500-w', 'agent-500-w')],
        'during-post',
        $this->paladinA(),
      );
    });
    $worker->processItem($this->queueItem((int) $row['id'], $row));
    $this->assertSame('pending', $this->loadDelivery((int) $row['id'])['status']);
  }

  /**
   * An item enqueued after the kill is held by the worker with one audit row.
   */
  public function testWorkerHoldAfterKillWritesOneAudit(): void {
    $this->enableEndpoint();
    $selector = $this->principalSelector('subject-after', 'agent-after');
    $kill = $this->killSwitch()->kill([$selector], 'after', $this->paladinA());
    $this->assertSame(0, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
    $this->sealSubject('subject-after', 'agent-after');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'after']);
    $row = $this->latestDelivery();
    $this->assertSame('pending', $row['status']);
    $history = [];
    $this->worker($history)->processItem($this->queueItem((int) $row['id'], $row));
    $this->assertSame(
      McpWebhookQueueManager::STATUS_HELD,
      $this->loadDelivery((int) $row['id'])['status'],
    );
    $this->assertSame(1, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
    $hold = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_HOLD);
    $this->assertSame('system', $hold['actor']);
    $this->assertSame($kill->batchId, $hold['batch_id']);
    $this->assertArrayHasKey('scope', $hold);
    $this->assertCount(0, $history);
  }

  /**
   * Mutation check: worker hold writes no audit when that flag is on.
   */
  public function testWorkerHoldAuditWhenWeakened(): void {
    $this->queue()->weakenForTest(McpWebhookQueueManager::WEAKEN_SKIP_AUDIT);
    $this->enableEndpoint();
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-after-w', 'agent-after-w')],
      'after',
      $this->paladinA(),
    );
    $this->sealSubject('subject-after-w', 'agent-after-w');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'after']);
    $row = $this->latestDelivery();
    $history = [];
    $this->worker($history)->processItem($this->queueItem((int) $row['id'], $row));
    $this->assertSame(
      McpWebhookQueueManager::STATUS_HELD,
      $this->loadDelivery((int) $row['id'])['status'],
    );
    $this->assertSame(0, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
  }

  /**
   * Extending with a shorter TTL leaves a long freeze unchanged.
   */
  public function testExtendDoesNotShortenLongFreeze(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-ext-max');
    $kill = $this->killSwitch()->kill([$human], 'long', $this->paladinA(), McpKillTtl::MAX);
    $before = (int) $this->killSwitch()->status($human)['block_until'];
    $extended = $this->killSwitch()->extend($kill->batchId, $this->paladinB(), 1);
    $this->assertSame($before, $extended->blockUntil);
    $this->assertSame($before, (int) $this->killSwitch()->status($human)['block_until']);
  }

  /**
   * Mutation check: extend shortens when max() is off.
   */
  public function testExtendShortensWhenMaxWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_EXTEND_MAX);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-ext-w');
    $kill = $this->killSwitch()->kill([$human], 'long', $this->paladinA(), McpKillTtl::MAX);
    $before = (int) $this->killSwitch()->status($human)['block_until'];
    $extended = $this->killSwitch()->extend($kill->batchId, $this->paladinB(), 1);
    $this->assertLessThan($before, $extended->blockUntil);
  }

  /**
   * An unconfirmed freeze does not expire at block_until.
   */
  public function testUnconfirmedFreezeDoesNotExpireAtTtl(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-stays');
    $kill = $this->killSwitch()->kill([$human], 'stay', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 1])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->assertSame(0, $this->killSwitch()->expireDue());
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $this->assertSame(0, $this->countAudit(McpKillSwitch::AUDIT_EXPIRE));
    $this->assertSame(
      McpKillBlockStatus::KillPending->value,
      $this->killSwitch()->status($human)['status'],
    );
    $this->sealSubject('subject-stays', 'agent-a');
    $this->expectGenericDeny();
  }

  /**
   * Mutation check: unconfirmed freezes expire at TTL when that flag is on.
   */
  public function testUnconfirmedFreezeExpiresWhenWeakenOn(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_EXPIRE_UNCONFIRMED);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-exp-w');
    $kill = $this->killSwitch()->kill([$human], 'expire', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 1])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Un-kill on a kill_pending row is refused and points at kill-lift.
   */
  public function testUnkillOnPendingFreezeIsRefused(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-use-lift');
    $this->killSwitch()->kill([$human], 'pending', $this->paladinA());
    try {
      $this->killSwitch()->requestUnkill([$human], 'nope', $this->paladinA());
      $this->fail('Un-kill must be refused on an unconfirmed freeze.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::INVALID_ACTION, $e->reasonCode);
      $this->assertStringContainsString('kill-lift', $e->getMessage());
    }
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $this->assertSame(
      McpKillBlockStatus::KillPending->value,
      $this->killSwitch()->status($human)['status'],
    );
  }

  /**
   * Escalation fires the hook and event once per batch, not once per row.
   */
  public function testEscalationFiresOncePerBatch(): void {
    $GLOBALS['mcp_sentinel_kill_hook_probe'] = [];
    $events = [];
    $this->container->get('event_dispatcher')->addListener(
      McpKillUnavailableConfirmerEvent::NAME,
      function (McpKillUnavailableConfirmerEvent $event) use (&$events): void {
        $events[] = $event;
      },
    );
    $one = McpKillSelector::humanKey(self::ISS . '|esc-a');
    $two = McpKillSelector::humanKey(self::ISS . '|esc-b');
    $kill = $this->killSwitch()->kill([$one, $two], 'escalate-batch', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertCount(1, $GLOBALS['mcp_sentinel_kill_hook_probe']);
    $this->assertCount(1, $events);
    $this->assertSame($kill->batchId, $events[0]->batchId);
    $this->assertSame($kill->batchId, $GLOBALS['mcp_sentinel_kill_hook_probe'][0]['batch_id']);
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_ESCALATE));
  }

  /**
   * The unavailable-confirmer hook must be named {module}_{hook}.
   *
   * The hook already starts with mcp_sentinel_, so the prefix is
   * repeated. The short name is not a Drupal hook implementation
   * and never dispatches the event.
   */
  public function testEscalationHookUsesRepeatedModulePrefix(): void {
    $this->assertTrue(
      function_exists('mcp_sentinel_mcp_sentinel_kill_unavailable_confirmer'),
      'hook_mcp_sentinel_kill_unavailable_confirmer must be {module}_{hook}.',
    );
    $this->assertFalse(
      function_exists('mcp_sentinel_kill_unavailable_confirmer'),
      'The unprefixed name is not a Drupal hook implementation.',
    );
    $this->assertTrue(
      $this->container->get('module_handler')
        ->hasImplementations('mcp_sentinel_kill_unavailable_confirmer', 'mcp_sentinel'),
      'mcp_sentinel must implement hook_mcp_sentinel_kill_unavailable_confirmer.',
    );
  }

  /**
   * Mutation check: skipping notify leaves hook and event silent.
   */
  public function testEscalationSkippedWhenWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_ESCALATION);
    $GLOBALS['mcp_sentinel_kill_hook_probe'] = [];
    $events = [];
    $this->container->get('event_dispatcher')->addListener(
      McpKillUnavailableConfirmerEvent::NAME,
      function (McpKillUnavailableConfirmerEvent $event) use (&$events): void {
        $events[] = $event;
      },
    );
    $human = McpKillSelector::humanKey(self::ISS . '|esc-skip');
    $kill = $this->killSwitch()->kill([$human], 'escalate', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->killSwitch()->expireDue();
    $this->assertCount(0, $GLOBALS['mcp_sentinel_kill_hook_probe']);
    $this->assertCount(0, $events);
  }

  /**
   * Break-glass refuses the requester and any unpinned identity.
   */
  public function testBreakGlassRefusesRequesterAndUnpinnedIdentity(): void {
    $requesterKill = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|bg-req')],
      'bg-req',
      $this->breakGlassOp(),
    );
    try {
      $this->killSwitch()->breakGlass(
        $requesterKill->batchId,
        McpKillBreakGlassAction::Keep,
        $this->breakGlassOp(),
      );
      $this->fail('The requester must not use break-glass on their own stop.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }

    $other = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|bg-other')],
      'bg-other',
      $this->paladinA(),
    );
    try {
      $this->killSwitch()->breakGlass(
        $other->batchId,
        McpKillBreakGlassAction::Keep,
        $this->paladinB(),
      );
      $this->fail('An unpinned identity must not use break-glass.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::BREAK_GLASS_DENIED, $e->reasonCode);
    }
  }

  /**
   * Mutation check: any distinct operator can break-glass when the pin is off.
   */
  public function testBreakGlassIdentityWhenWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_BREAK_GLASS_IDENTITY);
    $kill = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|bg-w')],
      'bg-w',
      $this->paladinA(),
    );
    $this->killSwitch()->breakGlass(
      $kill->batchId,
      McpKillBreakGlassAction::Keep,
      $this->paladinB(),
    );
    $this->assertSame(
      McpKillBlockStatus::Killed->value,
      $this->killSwitch()->status(McpKillSelector::humanKey(self::ISS . '|bg-w'))['status'],
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
   * @param int $id
   *   Delivery id.
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
   * Worker whose first POST returns HTTP 500.
   *
   * @param array $history
   *   Captured requests.
   *
   * @param-out array|\ArrayAccess<int, array> $history
   */
  private function worker500(array &$history): McpWebhookWorker {
    $stack = HandlerStack::create(new MockHandler([new Response(500, [], 'err')]));
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
   * Writes a blocking kill-block without holding the queue (claim-race seam).
   */
  private function insertActiveKill(McpKillSelector $selector): void {
    $now = $this->container->get('datetime.time')->getRequestTime();
    $this->container->get('database')->insert(McpKillSwitch::TABLE)
      ->fields([
        'selector_hash' => $selector->hash(),
        'selector_type' => $selector->type->value,
        'selector_key' => $selector->key,
        'status' => McpKillBlockStatus::Killed->value,
        'batch_id' => 'race-batch',
        'block_until' => $now + McpKillTtl::DEFAULT,
        'ttl' => McpKillTtl::DEFAULT,
        'reason' => 'race',
        'requested_by' => $this->paladinA()->storageId(),
        'requested_at' => $now,
        'changed' => $now,
      ])->execute();
  }

  /**
   * Confirming an overdue freeze refreshes block_until so it stays in force.
   */
  public function testConfirmRefreshesElapsedBlockUntil(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-confirm-ttl');
    $kill = $this->killSwitch()->kill([$human], 'confirm-ttl', $this->paladinA());
    $now = $this->container->get('datetime.time')->getRequestTime();
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => $now - 10])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $confirmed = $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Killed, $confirmed->status);
    $this->assertGreaterThan($now, $confirmed->blockUntil);
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * An unconfirmed freeze whose TTL has elapsed still escalates.
   */
  public function testOverdueUnconfirmedFreezeStillEscalates(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-overdue-esc');
    $tenant = McpKillSelector::tenant('tenant-overdue-esc');
    $kill = $this->killSwitch()->kill([$human, $tenant], 'overdue-esc', $this->paladinA());
    $now = $this->container->get('datetime.time')->getRequestTime();
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields([
        'confirm_until' => $now - 1,
        'block_until' => $now - 1,
      ])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $row = $this->killSwitch()->status($human);
    $this->assertSame(McpKillBlockStatus::KillPending->value, $row['status']);
    $this->assertGreaterThan(0, (int) $row['escalated_at']);
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_ESCALATE));
    $esc = $this->lastAuditMetadata(McpKillSwitch::AUDIT_ESCALATE);
    $this->assertSame('system', $esc['actor']);
    $this->assertNotSame($esc['scope'], $esc['target_selector']);
  }

  /**
   * Cron prune leaves held rows in place.
   */
  public function testPruneSkipsHeldRows(): void {
    $this->container->get('config.factory')->getEditable('mcp_sentinel.settings')
      ->set('webhook_delivery_retention_days', 1)
      ->save();
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
        'principal_key' => 'p',
        'human_key' => 'h',
        'tenant' => 't',
      ])->execute();
    $this->assertSame(0, $this->queue()->pruneOldDeliveries());
    $this->assertSame(
      McpWebhookQueueManager::STATUS_HELD,
      $this->loadDelivery($id)['status'],
    );
  }

  /**
   * Pre-upgrade keyless rows stay stopped while any stop is active.
   */
  public function testPreUpgradeKeylessRowStaysStopped(): void {
    $this->enableEndpoint();
    $id = (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => 'pending',
        'attempts' => 0,
        'created' => 1,
        'principal_key' => '',
        'human_key' => '',
        'tenant' => '',
      ])->execute();
    $this->container->get('state')->set(
      McpWebhookQueueManager::STATE_PRE_UPGRADE_MAX_ID,
      $id,
    );
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('other-tenant')],
      'keyless',
      $this->paladinA(),
    );
    $history = [];
    $this->worker($history)->processItem($this->queueItem($id, $this->loadDelivery($id)));
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery($id)['status']);
    $this->assertCount(0, $history);
    try {
      $this->queue()->releaseHeld([$id], $this->paladinB());
      $this->fail('A keyless pre-upgrade row must stay held while any stop is active.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SCOPE_STOPPED, $e->reasonCode);
    }
  }

  /**
   * Keys longer than the column are not truncated and are not enqueued.
   */
  public function testOversizedPrincipalKeyIsNotEnqueued(): void {
    $this->enableEndpoint();
    $job = $this->container->get('mcp_sentinel.principal_context_job');
    $this->assertInstanceOf(McpPrincipalContextJob::class, $job);
    $handle = $job->beginCarrying(
      str_repeat('p', McpWebhookQueueManager::KEY_MAX_LENGTH + 1),
      'h',
      't',
    );
    $before = (int) $this->container->get('database')
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->countQuery()
      ->execute()
      ->fetchField();
    try {
      $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'oversize']);
    }
    finally {
      $job->release($handle);
    }
    $after = (int) $this->container->get('database')
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame($before, $after);
  }

  /**
   * Break-glass accepts only the pinned Paladin iss|sub.
   */
  public function testBreakGlassPinIsPaladinIssSubOnly(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-bg-pin');
    $kill = $this->killSwitch()->kill([$human], 'bg-pin', $this->paladinA());
    try {
      $this->killSwitch()->breakGlass(
        $kill->batchId,
        McpKillBreakGlassAction::Keep,
        $this->paladinB(),
      );
      $this->fail('An unpinned Paladin identity must not use break-glass.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::BREAK_GLASS_DENIED, $e->reasonCode);
    }
    $this->assertSame(1, $this->countAudit(McpKillSwitch::AUDIT_REFUSE));
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_TRUST_UID);
    try {
      $this->killSwitch()->breakGlass(
        $kill->batchId,
        McpKillBreakGlassAction::Keep,
        McpOperatorIdentity::fromDrupalUid('2'),
      );
      $this->fail('A Drupal uid must not match the Paladin break-glass pin.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::BREAK_GLASS_DENIED, $e->reasonCode);
    }
    $this->setSetting('mcp_sentinel.kill_switch.break_glass_operator', '');
    try {
      $this->killSwitch()->breakGlass(
        $kill->batchId,
        McpKillBreakGlassAction::Keep,
        $this->breakGlassOp(),
      );
      $this->fail('Break-glass with an empty pin must be refused.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::BREAK_GLASS_DENIED, $e->reasonCode);
    }
    $this->setSetting(
      'mcp_sentinel.kill_switch.break_glass_operator',
      self::ISS . '|breakglass-op',
    );
    $kept = $this->killSwitch()->breakGlass(
      $kill->batchId,
      McpKillBreakGlassAction::Keep,
      $this->breakGlassOp(),
    );
    $this->assertSame(McpKillBlockStatus::Killed, $kept->status);
  }

  /**
   * Extend or lift of a confirmed-then-unkilled batch is NOT_FROZEN and audited.
   */
  public function testNotFrozenRefusalIsAudited(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-not-frozen');
    $kill = $this->killSwitch()->kill([$human], 'nf', $this->paladinA());
    $this->killSwitch()->lift($kill->batchId, $this->paladinB());
    try {
      $this->killSwitch()->extend($kill->batchId, $this->paladinB());
      $this->fail('A lifted batch must not accept extend.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::NOT_FROZEN, $e->reasonCode);
    }
    $refuse = $this->lastAuditMetadata(McpKillSwitch::AUDIT_REFUSE);
    $this->assertSame(McpKillSwitchException::NOT_FROZEN, $refuse['reason_code']);
    $this->assertSame($kill->batchId, $refuse['batch_id']);
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
   * Second bound operator.
   */
  private function paladinB(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|operator-b');
  }

  /**
   * Break-glass operator pinned in settings.php.
   */
  private function breakGlassOp(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|breakglass-op');
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
