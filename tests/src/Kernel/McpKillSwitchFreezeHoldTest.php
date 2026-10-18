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
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillSwitchResult;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\User;
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
 * Mutation checks (test…WhenWeakened) turn one PHPUnit-only guard
 * off and assert the product path that the guard was blocking.
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

    try {
      $this->killSwitch()->lift($kill->batchId, $this->paladinB());
      $this->fail('A confirmed freeze must not accept lift; use unkill.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::NOT_FROZEN, $e->reasonCode);
    }

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
    $this->assertSame(1, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
    $hold = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_HOLD);
    $this->assertSame('system', $hold['actor']);
    $this->assertStringContainsString((string) $row['id'], (string) $hold['item_ids']);
  }

  /**
   * Mutation check: a 500 retry overwrites held when the status guard is off.
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
    $this->assertEqualsCanonicalizing(
      ['human_key:' . $one->key, 'human_key:' . $two->key],
      $events[0]->targets,
    );
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
   * Confirm uses the batch-max window, not the last locked row.
   */
  public function testConfirmUsesBatchMaxBlockUntil(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-confirm-max');
    $tenant = McpKillSelector::tenant('tenant-confirm-max');
    $kill = $this->killSwitch()->kill([$human, $tenant], 'confirm-max', $this->paladinA());
    $now = $this->container->get('datetime.time')->getRequestTime();
    $hashes = $this->container->get('database')
      ->select(McpKillSwitch::TABLE, 'k')
      ->fields('k', ['selector_hash'])
      ->condition('batch_id', $kill->batchId)
      ->orderBy('selector_hash')
      ->execute()
      ->fetchCol();
    $this->assertCount(2, $hashes);
    $longTtl = 86400;
    $shortTtl = 3600;
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields([
        'ttl' => $longTtl,
        'block_until' => $now + $longTtl,
      ])
      ->condition('selector_hash', $hashes[0])
      ->execute();
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields([
        'ttl' => $shortTtl,
        'block_until' => $now + $shortTtl,
      ])
      ->condition('selector_hash', $hashes[1])
      ->execute();
    $confirmed = $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Killed, $confirmed->status);
    $this->assertSame($now + $longTtl, $confirmed->blockUntil);
    $this->assertSame($longTtl, $confirmed->ttl);
    foreach ($hashes as $hash) {
      $row = $this->container->get('database')
        ->select(McpKillSwitch::TABLE, 'k')
        ->fields('k', ['block_until'])
        ->condition('selector_hash', $hash)
        ->execute()
        ->fetchAssoc();
      $this->assertIsArray($row);
      $this->assertSame($now + $longTtl, (int) $row['block_until']);
    }
  }

  /**
   * Re-issuing a stop onto a pending selector keeps the longer TTL.
   */
  public function testReissueKeepsLongerStoredTtl(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-reissue-ttl');
    $tenantA = McpKillSelector::tenant('tenant-reissue-a');
    $first = $this->killSwitch()->kill(
      [$human, $tenantA],
      'reissue-long',
      $this->paladinA(),
      604800,
    );
    $this->assertTrue($first->needsConfirm);
    $tenantB = McpKillSelector::tenant('tenant-reissue-b');
    $second = $this->killSwitch()->kill(
      [$human, $tenantB],
      'reissue-short',
      $this->paladinA(),
      3600,
    );
    $this->assertTrue($second->needsConfirm);
    $row = $this->killSwitch()->status($human);
    $this->assertIsArray($row);
    $this->assertSame(604800, (int) $row['ttl']);
    $this->assertGreaterThanOrEqual($first->blockUntil, (int) $row['block_until']);
    $this->assertSame(604800, $second->ttl);
    $this->assertSame(3600, $second->requestedTtl);
    $this->assertSame((int) $row['block_until'], $second->blockUntil);
    $audit = $this->lastAuditMetadata(McpKillSwitch::AUDIT_FREEZE);
    $this->assertSame('604800', $audit['ttl']);
    $this->assertSame((string) $row['block_until'], $audit['block_until']);
    $this->assertSame('3600', $audit['requested_ttl']);
  }

  /**
   * Re-killing after a lift uses the requested window, not the dead row.
   */
  public function testKillAfterLiftUsesRequestedWindow(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-after-lift-ttl');
    $first = $this->killSwitch()->kill(
      [$human],
      'after-lift-long',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->assertTrue($first->needsConfirm);
    $this->killSwitch()->lift($first->batchId, $this->paladinB());
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
    $second = $this->killSwitch()->kill(
      [$human],
      'after-lift-short',
      $this->paladinA(),
      3600,
    );
    $this->assertStoredKillWindow($human, $second, 3600, McpKillSwitch::AUDIT_FREEZE);
  }

  /**
   * Re-killing after un-kill confirm uses the requested window.
   */
  public function testKillAfterUnkillConfirmUsesRequestedWindow(): void {
    $selector = $this->principalSelector('subject-after-unkill-ttl', 'agent-after-unkill-ttl');
    $first = $this->killSwitch()->kill(
      [$selector],
      'after-unkill-long',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->assertFalse($first->needsConfirm);
    $unkill = $this->killSwitch()->requestUnkill(
      [$selector],
      'restore',
      $this->paladinA(),
    );
    $this->killSwitch()->confirmUnkill($unkill->batchId, $this->paladinB());
    $this->assertFalse($this->killSwitch()->isKilled($selector->key));
    $second = $this->killSwitch()->kill(
      [$selector],
      'after-unkill-short',
      $this->paladinA(),
      3600,
    );
    $this->assertStoredKillWindow($selector, $second, 3600, McpKillSwitch::AUDIT_KILL);
  }

  /**
   * Re-killing after TTL expiry uses the requested window.
   */
  public function testKillAfterTtlExpiryUsesRequestedWindow(): void {
    $selector = $this->principalSelector('subject-after-exp-ttl', 'agent-after-exp-ttl');
    $this->killSwitch()->kill(
      [$selector],
      'after-exp-long',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 1])
      ->condition('selector_hash', $selector->hash())
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertFalse($this->killSwitch()->isKilled($selector->key));
    $second = $this->killSwitch()->kill(
      [$selector],
      'after-exp-short',
      $this->paladinA(),
      3600,
    );
    $this->assertStoredKillWindow($selector, $second, 3600, McpKillSwitch::AUDIT_KILL);
  }

  /**
   * An unknown status is dead for inheritance and blocking for admit.
   */
  public function testKillAfterUnknownStatusUsesRequestedWindow(): void {
    $selector = $this->principalSelector('subject-after-unknown-ttl', 'agent-after-unknown-ttl');
    $this->killSwitch()->kill(
      [$selector],
      'after-unknown-long',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['status' => 'not_a_status'])
      ->condition('selector_hash', $selector->hash())
      ->execute();
    $this->assertTrue($this->killSwitch()->isKilled($selector->key));
    $second = $this->killSwitch()->kill(
      [$selector],
      'after-unknown-short',
      $this->paladinA(),
      3600,
    );
    $this->assertStoredKillWindow($selector, $second, 3600, McpKillSwitch::AUDIT_KILL);
  }

  /**
   * A time-expired killed row does not keep the old confirmer.
   */
  public function testKillAfterExpiredKilledRowClearsConfirmer(): void {
    $selector = $this->principalSelector('subject-after-dead-cf', 'agent-after-dead-cf');
    $this->killSwitch()->kill(
      [$selector],
      'after-dead-cf-long',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields([
        'block_until' => 1,
        'confirmed_by' => 'paladin:' . self::ISS . '|old-confirmer',
        'confirmed_at' => 99,
      ])
      ->condition('selector_hash', $selector->hash())
      ->execute();
    $second = $this->killSwitch()->kill(
      [$selector],
      'after-dead-cf-short',
      $this->paladinA(),
      3600,
    );
    $this->assertStoredKillWindow($selector, $second, 3600, McpKillSwitch::AUDIT_KILL);
    $row = $this->killSwitch()->status($selector);
    $this->assertIsArray($row);
    $this->assertSame('', (string) $row['confirmed_by']);
    $this->assertSame(0, (int) $row['confirmed_at']);
  }

  /**
   * Mutation check: a dead killed row keeps the confirmer when that flag is on.
   */
  public function testDeadConfirmerKeptWhenWeakenOn(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_KEEP_DEAD_CONFIRMER);
    $selector = $this->principalSelector('subject-keep-cf-w', 'agent-keep-cf-w');
    $this->killSwitch()->kill(
      [$selector],
      'keep-cf-long',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields([
        'block_until' => 1,
        'confirmed_by' => 'paladin:' . self::ISS . '|old-confirmer',
        'confirmed_at' => 99,
      ])
      ->condition('selector_hash', $selector->hash())
      ->execute();
    $this->killSwitch()->kill(
      [$selector],
      'keep-cf-short',
      $this->paladinA(),
      3600,
    );
    $row = $this->killSwitch()->status($selector);
    $this->assertIsArray($row);
    $this->assertSame('paladin:' . self::ISS . '|old-confirmer', (string) $row['confirmed_by']);
    $this->assertSame(99, (int) $row['confirmed_at']);
  }

  /**
   * Mutation check: a dead row donates its window when that flag is on.
   */
  public function testDeadRowInheritsWhenWeakenOn(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_INHERIT_DEAD_WINDOW);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-inherit-w');
    $first = $this->killSwitch()->kill(
      [$human],
      'inherit-long',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->killSwitch()->lift($first->batchId, $this->paladinB());
    $second = $this->killSwitch()->kill(
      [$human],
      'inherit-short',
      $this->paladinA(),
      3600,
    );
    $row = $this->killSwitch()->status($human);
    $this->assertIsArray($row);
    $this->assertSame(McpKillTtl::MAX, (int) $row['ttl']);
    $this->assertSame(McpKillTtl::MAX, $second->ttl);
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
    $this->assertSame(2, $this->countAudit(McpKillSwitch::AUDIT_REFUSE));
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
    $this->assertSame(3, $this->countAudit(McpKillSwitch::AUDIT_REFUSE));
    $alice = $this->createUser([McpKillSwitch::PERMISSION], 'alice');
    $this->assertInstanceOf(User::class, $alice);
    $this->container->get('mcp_sentinel.operator_binding')
      ->bindIdentityForTest($this->paladinB(), (int) $alice->id());
    $this->setSetting('mcp_sentinel.kill_switch.break_glass_operator', 'alice');
    try {
      $this->killSwitch()->breakGlass(
        $kill->batchId,
        McpKillBreakGlassAction::Keep,
        $this->paladinB(),
      );
      $this->fail('A Drupal username pin must not grant break-glass.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::BREAK_GLASS_DENIED, $e->reasonCode);
    }
    $this->assertSame(4, $this->countAudit(McpKillSwitch::AUDIT_REFUSE));
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
   * A lifted batch refuses extend with an audited NOT_FROZEN.
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
   * A service-level confirm of a non-pending batch writes one refuse row.
   */
  public function testConfirmNotPendingRefusalIsAudited(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-np');
    $kill = $this->killSwitch()->kill([$human], 'np', $this->paladinA());
    $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $before = $this->countAudit(McpKillSwitch::AUDIT_REFUSE);
    try {
      $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
      $this->fail('A confirmed batch must refuse a second confirm.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::NOT_PENDING, $e->reasonCode);
    }
    $this->assertSame($before + 1, $this->countAudit(McpKillSwitch::AUDIT_REFUSE));
    $refuse = $this->lastAuditMetadata(McpKillSwitch::AUDIT_REFUSE);
    $this->assertSame(McpKillSwitchException::NOT_PENDING, $refuse['reason_code']);
    $this->assertSame($this->paladinB()->storageId(), $refuse['actor']);
    $this->assertSame($kill->batchId, $refuse['batch_id']);
  }

  /**
   * A missing 10038 state key treats every keyless row as stopped.
   */
  public function testKeylessRowStopsWhenStateKeyAbsent(): void {
    $this->enableEndpoint();
    $this->container->get('state')->delete(
      McpWebhookQueueManager::STATE_PRE_UPGRADE_MAX_ID,
    );
    $id = $this->insertDelivery([
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]);
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('other-absent')],
      'keyless-absent',
      $this->paladinA(),
    );
    $history = [];
    $this->worker($history)->processItem($this->queueItem($id, $this->loadDelivery($id)));
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery($id)['status']);
    $this->assertCount(0, $history);
    try {
      $this->queue()->releaseHeld([$id], $this->paladinB());
      $this->fail('A keyless row must stay held when the state key is absent.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SCOPE_STOPPED, $e->reasonCode);
    }
  }

  /**
   * A keyless row is held after claim when the state key is absent.
   */
  public function testKeylessRowStopsAfterClaimWhenStateAbsent(): void {
    $this->enableEndpoint();
    $this->container->get('state')->delete(
      McpWebhookQueueManager::STATE_PRE_UPGRADE_MAX_ID,
    );
    $id = $this->insertDelivery([
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]);
    $history = [];
    $worker = $this->worker($history);
    $worker->killBetweenCheckAndClaimForTest(function (): void {
      $this->killSwitch()->kill(
        [McpKillSelector::tenant('other-claim')],
        'keyless-claim',
        $this->paladinA(),
      );
    });
    $worker->processItem($this->queueItem($id, $this->loadDelivery($id)));
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery($id)['status']);
    $this->assertCount(0, $history);
  }

  /**
   * A keyless retry stays held when the state key is absent.
   */
  public function testKeylessRetryStopsWhenStateAbsent(): void {
    $this->enableEndpoint();
    $this->container->get('state')->delete(
      McpWebhookQueueManager::STATE_PRE_UPGRADE_MAX_ID,
    );
    $id = $this->insertDelivery([
      'status' => 'in_progress',
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]);
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('other-retry')],
      'keyless-retry',
      $this->paladinA(),
    );
    $this->assertTrue($this->queue()->holdAfterAttempt($id, 1, 500, 'err', 99));
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery($id)['status']);
  }

  /**
   * A keyless row above the recorded max id stays stopped.
   */
  public function testKeylessRowAboveMaxIdStaysStopped(): void {
    $this->enableEndpoint();
    $below = $this->insertDelivery([
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]);
    $this->container->get('state')->set(
      McpWebhookQueueManager::STATE_PRE_UPGRADE_MAX_ID,
      $below,
    );
    $above = $this->insertDelivery([
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]);
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('other-above')],
      'keyless-above',
      $this->paladinA(),
    );
    $this->assertTrue(
      $this->queue()->shouldHoldRow($this->loadDelivery($above)),
      'A keyless row queued after 10038 must stay held while any stop is active.',
    );
    $this->assertTrue($this->queue()->shouldHoldRow($this->loadDelivery($below)));
  }

  /**
   * A fresh-install keyless row stays held while any stop is active.
   */
  public function testFreshInstallKeylessRowStaysStopped(): void {
    $this->enableEndpoint();
    $this->container->get('state')->set(
      McpWebhookQueueManager::STATE_PRE_UPGRADE_MAX_ID,
      0,
    );
    $id = $this->insertDelivery([
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]);
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('other-fresh')],
      'keyless-fresh',
      $this->paladinA(),
    );
    $this->assertTrue(
      $this->queue()->shouldHoldRow($this->loadDelivery($id)),
      'A fresh-install keyless row must stay held while any stop is active.',
    );
  }

  /**
   * A keyless row with an unreadable id fails closed while any stop is active.
   */
  public function testKeylessRowWithUnreadableIdIsStopped(): void {
    $this->enableEndpoint();
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('other-bad-id')],
      'keyless-bad-id',
      $this->paladinA(),
    );
    $this->assertTrue($this->queue()->shouldHoldRow([
      'id' => 0,
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]));
  }

  /**
   * An unreadable stored block_until fails closed.
   */
  public function testUnreadableBlockUntilFailsClosed(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-str-block');
    $kill = $this->killSwitch()->kill([$human], 'str-block', $this->paladinA());
    $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 'not-a-number'])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->assertTrue($this->killSwitch()->hasActiveStop());
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $listed = $this->killSwitch()->listActiveBlocks();
    $hashes = array_column($listed, 'selector_hash');
    $this->assertContains($human->hash(), $hashes);
  }

  /**
   * An unreadable stored block_until fails closed in isKilled.
   */
  public function testUnreadableBlockUntilIsKilledFailsClosed(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-str-killed');
    $kill = $this->killSwitch()->kill([$human], 'str-killed', $this->paladinA());
    $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 'not-a-number'])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * An unreadable stored block_until stays listed as an active block.
   */
  public function testUnreadableBlockUntilListActiveBlocksFailsClosed(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-str-list');
    $kill = $this->killSwitch()->kill([$human], 'str-list', $this->paladinA());
    $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 'not-a-number'])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $listed = $this->killSwitch()->listActiveBlocks();
    $hashes = array_column($listed, 'selector_hash');
    $this->assertContains($human->hash(), $hashes);
  }

  /**
   * A failed escalation audit rolls back the claim and uses escalate_failed.
   */
  public function testEscalateClaimFailureRollsBackAndUsesDistinctReason(): void {
    $this->killSwitch()->afterEscalateClaimForTest(function (): void {
      throw new \RuntimeException('audit boom');
    });
    $human = McpKillSelector::humanKey(self::ISS . '|esc-claim-fail');
    $kill = $this->killSwitch()->kill([$human], 'esc-claim', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->killSwitch()->expireDue();
    $row = $this->killSwitch()->status($human);
    $this->assertIsArray($row);
    $this->assertSame(0, (int) $row['escalated_at']);
    $failed = $this->lastAuditMetadata(McpKillSwitch::AUDIT_ESCALATE);
    $this->assertSame('escalate_failed', $failed['reason']);
  }

  /**
   * A failed un-kill expiry rolls the batch back and uses unkill_expire_failed.
   */
  public function testUnkillExpireFailureRollsBackAndUsesDistinctReason(): void {
    $this->killSwitch()->afterUnkillExpireForTest(function (): void {
      throw new \RuntimeException('unkill boom');
    });
    $human = McpKillSelector::principalKey(self::ISS . '|subject-unkill-fail|agent-a');
    $this->killSwitch()->kill([$human], 'unkill-fail', $this->paladinA());
    $unkill = $this->killSwitch()->requestUnkill([$human], 'restore', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['unkill_confirm_until' => 1])
      ->condition('unkill_batch_id', $unkill->batchId)
      ->execute();
    $this->killSwitch()->expireDue();
    $row = $this->killSwitch()->status($human);
    $this->assertIsArray($row);
    $this->assertSame(McpKillBlockStatus::UnkillPending->value, $row['status']);
    $failed = $this->lastAuditMetadata(McpKillSwitch::AUDIT_ESCALATE);
    $this->assertSame('unkill_expire_failed', $failed['reason']);
    $this->assertSame($unkill->batchId, $failed['batch_id']);
  }

  /**
   * A keyless row stays stopped under a confirmed (killed) stop.
   */
  public function testKeylessRowStaysStoppedUnderKilledStop(): void {
    $this->enableEndpoint();
    $id = $this->insertDelivery([
      'principal_key' => '',
      'human_key' => '',
      'tenant' => '',
    ]);
    $this->insertActiveKill(McpKillSelector::tenant('other-killed-keyless'));
    $this->assertTrue(
      $this->queue()->shouldHoldRow($this->loadDelivery($id)),
      'A keyless row must stay held while a confirmed stop is active.',
    );
    $this->queue()->markHeld($id);
    try {
      $this->queue()->releaseHeld([$id], $this->paladinB());
      $this->fail('A keyless row must not release while a confirmed stop is active.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SCOPE_STOPPED, $e->reasonCode);
    }
  }

  /**
   * A 770-byte stored key is held while any stop is active.
   */
  public function testOversizedStoredKeyIsHeldUnderStop(): void {
    $this->enableEndpoint();
    $stored = str_repeat('k', McpWebhookQueueManager::KEY_MAX_LENGTH);
    $id = $this->insertDelivery([
      'principal_key' => $stored,
      'human_key' => 'h',
      'tenant' => 't',
    ]);
    $this->killSwitch()->kill(
      [McpKillSelector::tenant('other-oversize')],
      'oversize-stored',
      $this->paladinA(),
    );
    $this->assertTrue($this->queue()->shouldHoldRow($this->loadDelivery($id)));
    $history = [];
    $this->worker($history)->processItem($this->queueItem($id, $this->loadDelivery($id)));
    $this->assertSame(McpWebhookQueueManager::STATUS_HELD, $this->loadDelivery($id)['status']);
    $this->assertCount(0, $history);
  }

  /**
   * An enqueue drop for an oversized key writes one refuse row.
   */
  public function testOversizedEnqueueWritesRefuseAudit(): void {
    $this->enableEndpoint();
    $job = $this->container->get('mcp_sentinel.principal_context_job');
    $handle = $job->beginCarrying(
      str_repeat('p', McpWebhookQueueManager::KEY_MAX_LENGTH),
      'h',
      't',
    );
    $before = $this->countAudit(McpWebhookQueueManager::AUDIT_REFUSE);
    try {
      $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'oversize']);
    }
    finally {
      $job->release($handle);
    }
    $this->assertSame($before + 1, $this->countAudit(McpWebhookQueueManager::AUDIT_REFUSE));
    $refuse = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_REFUSE);
    $this->assertSame(
      McpWebhookQueueManager::REASON_OVERSIZED_KEY,
      $refuse['reason_code'],
    );
    $this->assertSame('ep1', $refuse['endpoint_id']);
    $this->assertSame('mcp.entity.presave', $refuse['event']);
    $this->assertArrayNotHasKey('principal_key', $refuse);
  }

  /**
   * A concurrent discard between select and update is not audited.
   */
  public function testHoldMatchingReselectsAfterConcurrentDiscard(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-reselect-a', 'agent-reselect-a');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'a']);
    $keep = (int) $this->latestDelivery()['id'];
    $this->sealSubject('subject-reselect-b', 'agent-reselect-b');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'b']);
    $drop = (int) $this->latestDelivery()['id'];
    $this->queue()->afterHoldSelectForTest(function (array $ids) use ($drop): void {
      $this->assertContains($drop, $ids);
      $this->container->get('database')
        ->update('mcp_sentinel_webhook_delivery')
        ->fields(['status' => McpWebhookQueueManager::STATUS_DISCARDED])
        ->condition('id', $drop)
        ->execute();
    });
    $before = $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD);
    $held = $this->queue()->holdMatching(
      [
        $this->principalSelector('subject-reselect-a', 'agent-reselect-a'),
        $this->principalSelector('subject-reselect-b', 'agent-reselect-b'),
      ],
      $this->paladinA(),
      'reselect-batch',
    );
    $this->assertSame([$keep], $held);
    $this->assertSame($before + 1, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
    $hold = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_HOLD);
    $this->assertSame((string) $keep, $hold['item_ids']);
    $this->assertStringNotContainsString((string) $drop, (string) $hold['item_ids']);
  }

  /**
   * An empty re-select after holdFromStatus still writes AUDIT_HOLD.
   */
  public function testHoldFromStatusEmptyReselectAuditsDelivery(): void {
    $this->enableEndpoint();
    $this->sealSubject('subject-empty-reselect', 'agent-empty-reselect');
    $this->queue()->enqueueForEvent('mcp.entity.presave', ['event' => 'empty-reselect']);
    $id = (int) $this->latestDelivery()['id'];
    $this->queue()->afterHoldUpdateForTest(function (int $deliveryId) use ($id): void {
      $this->assertSame($id, $deliveryId);
      $this->container->get('database')
        ->delete('mcp_sentinel_webhook_delivery')
        ->condition('id', $deliveryId)
        ->execute();
    });
    $before = $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD);
    $this->queue()->markHeld($id);
    $this->assertSame($before + 1, $this->countAudit(McpWebhookQueueManager::AUDIT_HOLD));
    $hold = $this->lastAuditMetadata(McpWebhookQueueManager::AUDIT_HOLD);
    $this->assertSame('delivery:' . (string) $id, $hold['scope']);
    $this->assertSame((string) $id, $hold['item_ids']);
  }

  /**
   * Escalation writes the audit row even when the hook throws.
   */
  public function testEscalationAuditSurvivesThrowingHook(): void {
    $GLOBALS['mcp_sentinel_kill_hook_probe'] = [];
    $GLOBALS['mcp_sentinel_kill_hook_probe_throw'] = TRUE;
    $events = [];
    $this->container->get('event_dispatcher')->addListener(
      McpKillUnavailableConfirmerEvent::NAME,
      function (McpKillUnavailableConfirmerEvent $event) use (&$events): void {
        $events[] = $event;
      },
    );
    $one = McpKillSelector::humanKey(self::ISS . '|esc-throw-a');
    $two = McpKillSelector::humanKey(self::ISS . '|esc-throw-b');
    $kill = $this->killSwitch()->kill([$one, $two], 'esc-throw', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $kill->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertSame(2, $this->countAudit(McpKillSwitch::AUDIT_ESCALATE));
    $failed = $this->lastAuditMetadata(McpKillSwitch::AUDIT_ESCALATE);
    $this->assertSame('notify_failed', $failed['reason']);
    $this->assertSame('system', $failed['actor']);
    $this->assertSame($kill->batchId, $failed['batch_id']);
    $this->assertCount(1, $GLOBALS['mcp_sentinel_kill_hook_probe']);
    $this->assertEqualsCanonicalizing(
      ['human_key:' . $one->key, 'human_key:' . $two->key],
      $GLOBALS['mcp_sentinel_kill_hook_probe'][0]['targets'],
    );
    $this->killSwitch()->expireDue();
    $this->assertSame(2, $this->countAudit(McpKillSwitch::AUDIT_ESCALATE));
    $this->assertCount(1, $GLOBALS['mcp_sentinel_kill_hook_probe']);
    unset($GLOBALS['mcp_sentinel_kill_hook_probe_throw']);
  }

  /**
   * Mutation check: a person-wide stop does not refuse when freeze is off.
   */
  public function testPersonWideStopDoesNotRefuseWhenFreezeWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_MASS_FREEZE);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-person-w');
    $this->killSwitch()->kill([$human], 'person-wide', $this->paladinA());
    $this->sealSubject('subject-person-w', 'agent-a');
    try {
      $this->assertSame(
        'subject-person-w',
        $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
      );
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->fail('A weakened mass freeze must not refuse the in-scope admit: ' . $e->getMessage());
    }
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
    try {
      $this->assertSame(
        'subject-tenant-w',
        $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
      );
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->fail('A weakened tenant freeze must not refuse the in-scope admit: ' . $e->getMessage());
    }
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
   * Mutation check: the requester can lift when distinct-operator is off.
   */
  public function testRequesterLiftsWhenDistinctOperatorWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_DISTINCT_OPERATOR);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-lift-w');
    $kill = $this->killSwitch()->kill([$human], 'lift', $this->paladinA());
    try {
      $this->killSwitch()->lift($kill->batchId, $this->paladinA());
    }
    catch (McpKillSwitchException $e) {
      $this->fail('A weakened distinct-operator check must allow the requester to lift: ' . $e->getMessage());
    }
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Mutation check: an extend above 7 days is accepted when the cap is off.
   */
  public function testExtendAboveSevenDaysWhenTtlCapWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_TTL_CAP);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-ttl-w');
    $kill = $this->killSwitch()->kill([$human], 'ttl', $this->paladinA());
    try {
      $extended = $this->killSwitch()->extend(
        $kill->batchId,
        $this->paladinB(),
        McpKillTtl::MAX + 1,
      );
    }
    catch (McpKillSwitchException $e) {
      $this->fail('A weakened TTL cap must accept an extend above 7 days: ' . $e->getMessage());
    }
    $this->assertSame(McpKillTtl::MAX + 1, $extended->ttl);
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
    try {
      $released = $this->queue()->releaseHeld([(int) $in['id']], $this->paladinB());
    }
    catch (McpKillSwitchException $e) {
      $this->fail('A weakened release-under-stop check must release the held row: ' . $e->getMessage());
    }
    $this->assertSame([(int) $in['id']], $released);
    $this->assertSame('pending', $this->loadDelivery((int) $in['id'])['status']);
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
   * Mutation check: kill-switch writes no audit when that flag is on.
   */
  public function testKillWritesNoAuditWhenSkipAuditWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_AUDIT);
    $selector = $this->principalSelector('subject-audit-w', 'agent-audit-w');
    $this->killSwitch()->kill([$selector], 'audit-w', $this->paladinA());
    $this->assertTrue($this->killSwitch()->isKilled($selector->key));
    $this->assertSame(0, $this->countAudit(McpKillSwitch::AUDIT_KILL));
    $this->assertSame(0, $this->countAudit(McpKillSwitch::AUDIT_FREEZE));
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
   * Mutation check: any distinct operator can break-glass when the pin is off.
   */
  public function testBreakGlassIdentityWhenWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_BREAK_GLASS_IDENTITY);
    $kill = $this->killSwitch()->kill(
      [McpKillSelector::humanKey(self::ISS . '|bg-w')],
      'bg-w',
      $this->paladinA(),
    );
    try {
      $this->killSwitch()->breakGlass(
        $kill->batchId,
        McpKillBreakGlassAction::Keep,
        $this->paladinB(),
      );
    }
    catch (McpKillSwitchException $e) {
      $this->fail('A weakened break-glass pin must accept a distinct operator: ' . $e->getMessage());
    }
    $this->assertSame(
      McpKillBlockStatus::Killed->value,
      $this->killSwitch()->status(McpKillSelector::humanKey(self::ISS . '|bg-w'))['status'],
    );
  }

  /**
   * Holds the in-scope delivery and lets the out-of-scope one send.
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
   * Inserts a webhook delivery row.
   *
   * @param array<string, mixed> $overrides
   *   Column overrides.
   *
   * @return int
   *   New row id.
   */
  private function insertDelivery(array $overrides = []): int {
    return (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields($overrides + [
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => 'pending',
        'attempts' => 0,
        'created' => 1,
        'principal_key' => 'p',
        'human_key' => 'h',
        'tenant' => 't',
      ])->execute();
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
   * Result, stored row, and kill audit all carry the enforced window.
   */
  private function assertStoredKillWindow(
    McpKillSelector $selector,
    McpKillSwitchResult $result,
    int $ttl,
    string $auditOp,
  ): void {
    $now = $this->container->get('datetime.time')->getRequestTime();
    $until = $now + $ttl;
    $this->assertSame($ttl, $result->ttl);
    $this->assertSame($until, $result->blockUntil);
    $this->assertSame($ttl, $result->requestedTtl);
    $this->assertSame($until, $result->requestedBlockUntil);
    $row = $this->killSwitch()->status($selector);
    $this->assertIsArray($row);
    $this->assertSame($ttl, (int) $row['ttl']);
    $this->assertSame($until, (int) $row['block_until']);
    $audit = $this->lastAuditMetadata($auditOp);
    $this->assertSame((string) $ttl, $audit['ttl']);
    $this->assertSame((string) $until, $audit['block_until']);
    $this->assertSame((string) $ttl, $audit['requested_ttl']);
    $this->assertSame((string) $until, $audit['requested_block_until']);
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
