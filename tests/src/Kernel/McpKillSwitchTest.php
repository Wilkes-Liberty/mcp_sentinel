<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Config\ConfigException;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBinding;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Agent kill switch core (DEV-846).
 *
 * Deny-path tests fail when the principal-context guard is disabled
 * via disableForTest() and pass when it is on.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpKillSwitchTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedRequestTrait;
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
   * First operator account id.
   */
  private string $operatorA = '';

  /**
   * Named second person (secondary account holder) account id.
   */
  private string $operatorB = '';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('node', ['node_access']);
    $this->installConfig(['system', 'user', 'node', 'mcp_sentinel']);
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();

    $first = $this->createUser([McpKillSwitch::PERMISSION]);
    $second = $this->createUser([McpKillSwitch::PERMISSION]);
    $this->assertInstanceOf(User::class, $first);
    $this->assertInstanceOf(User::class, $second);
    $this->operatorA = (string) $first->id();
    $this->operatorB = (string) $second->id();
    $this->assertNotSame($this->operatorA, $this->operatorB);
  }

  /**
   * A killed principal is refused at admit with a generic deny.
   */
  public function testKilledPrincipalRefusedAtAdmitWithGenericDeny(): void {
    $this->sealSubject('subject-a', 'agent-a');
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-a', 'agent-a')],
      'compromise',
      $this->paladinA(),
    );
    try {
      $this->dispatcher()->admit(['note' => 'ok'], 'mcp_kill_probe');
      $this->fail('A killed principal must be refused at admit().');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
      $this->assertStringNotContainsString('killed', $e->getMessage());
    }
    $meta = $this->lastAuditMetadata('denied_access');
    $this->assertSame(McpKillSwitch::DENY_REASON, $meta['reason']);
  }

  /**
   * A kill mid-write rolls the governed entity save back.
   */
  public function testKillMidWriteRollsBack(): void {
    $this->sealSubject('subject-a', 'agent-a');
    $node = Node::create([
      'type' => 'page',
      'title' => 'before-kill',
      'status' => 0,
    ]);
    $node->save();
    $id = (int) $node->id();
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-a', 'agent-a')],
      'mid-write',
      $this->paladinA(),
    );
    $node->setTitle('after-kill');
    try {
      $node->save();
      $this->fail('A kill mid-write must refuse before commit.');
    }
    catch (EntityStorageException $e) {
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
    }
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$id]);
    $stored = $storage->load($id);
    $this->assertInstanceOf(Node::class, $stored);
    $this->assertSame('before-kill', $stored->label());
    $this->assertSame(
      McpKillSwitch::DENY_REASON,
      $this->lastAuditMetadata('denied_access')['reason'],
    );
  }

  /**
   * A job carrying a killed principal is refused at admit.
   */
  public function testJobScopeWithKilledPrincipalRefused(): void {
    $selector = $this->principalSelector('subject-job', 'agent-job');
    $this->killSwitch()->kill([$selector], 'queued work', $this->paladinA());
    $job = new McpPrincipalContextJob($this->principalContextHolder());
    $handle = $job->beginCarrying($selector->key, self::ISS . '|subject-job', 'tenant-a');
    try {
      $this->dispatcher()->admit(['note' => 'ok'], 'mcp_kill_job_probe');
      $this->fail('A job carrying a killed principal must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
    }
    $job->end($handle);
    $meta = $this->lastAuditMetadata('denied_access');
    $this->assertSame(McpKillSwitch::DENY_REASON, $meta['reason']);
    $this->assertSame('unverified', $meta['principal_key']);
    $this->assertSame('unverified', $meta['human_key']);
  }

  /**
   * Default TTL is 24 h; a request above 7 d is refused. Re-kill extends.
   */
  public function testTtlDefaultAndCapAndExtension(): void {
    $selector = $this->principalSelector('subject-ttl', 'agent-ttl');
    $first = $this->killSwitch()->kill([$selector], 'ttl-default', $this->paladinA());
    $this->assertSame(McpKillTtl::DEFAULT, $first->ttl);
    $now = (int) $this->container->get('datetime.time')->getRequestTime();
    $this->assertGreaterThanOrEqual($now + McpKillTtl::DEFAULT - 1, $first->blockUntil);

    try {
      $this->killSwitch()->kill(
        [$this->principalSelector('subject-cap', 'agent-cap')],
        'ttl-cap',
        $this->paladinA(),
        McpKillTtl::MAX + 86400,
      );
      $this->fail('A TTL above 7 d must be a validation error.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::INVALID_TTL, $e->reasonCode);
    }

    $extended = $this->killSwitch()->kill(
      [$selector],
      'ttl-extend',
      $this->paladinA(),
      McpKillTtl::MAX,
    );
    $this->assertSame(McpKillTtl::MAX, $extended->ttl);
    $this->assertGreaterThanOrEqual($first->blockUntil, $extended->blockUntil);
  }

  /**
   * Expiry restores access and writes an expire audit row.
   */
  public function testExpiryRestoresAccess(): void {
    $selector = $this->principalSelector('subject-exp', 'agent-exp');
    $this->sealSubject('subject-exp', 'agent-exp');
    $this->killSwitch()->kill([$selector], 'short', $this->paladinA(), 60);
    $this->expectGenericDeny();

    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 1])
      ->condition('selector_hash', $selector->hash())
      ->execute();
    $this->assertFalse($this->killSwitch()->isKilled($selector->key));
    $this->assertSame('subject-exp', $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject());
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertSame('ttl', $this->lastAuditMetadata(McpKillSwitch::AUDIT_EXPIRE)['reason']);
  }

  /**
   * Guard bypass: a mass kill applies immediately when mass-pending is off.
   *
   * This is the red mutation for testMassKillStaysPendingWithoutSecondOperator.
   */
  public function testMassKillAppliesWhenMassPendingIsWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_SKIP_MASS_PENDING);
    $one = $this->principalSelector('subject-m1w', 'agent-m1w');
    $two = $this->principalSelector('subject-m2w', 'agent-m2w');
    $result = $this->killSwitch()->kill([$one, $two], 'mass', $this->paladinA());
    $this->assertFalse($result->needsConfirm);
    $this->assertSame(McpKillBlockStatus::Killed, $result->status);
    $this->assertTrue($this->killSwitch()->isKilled($one->key));
  }

  /**
   * A mass kill stays pending without a second operator.
   */
  public function testMassKillStaysPendingWithoutSecondOperator(): void {
    $one = $this->principalSelector('subject-m1', 'agent-m1');
    $two = $this->principalSelector('subject-m2', 'agent-m2');
    $result = $this->killSwitch()->kill([$one, $two], 'mass', $this->paladinA());
    $this->assertTrue($result->needsConfirm);
    $this->assertSame(McpKillBlockStatus::KillPending, $result->status);
    $this->assertFalse($this->killSwitch()->isKilled($one->key));
    $this->sealSubject('subject-m1', 'agent-m1');
    $this->assertSame('subject-m1', $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject());
  }

  /**
   * Same-account confirm is refused.
   */
  public function testSameAccountConfirmRefused(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-mass');
    $result = $this->killSwitch()->kill([$human], 'all agents of this person', $this->paladinA());
    $this->assertTrue($result->needsConfirm);
    try {
      $this->killSwitch()->confirm($result->batchId, $this->paladinA());
      $this->fail('The same operator account must not confirm.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Un-kill needs two distinct operators.
   */
  public function testUnkillNeedsTwoOperators(): void {
    $selector = $this->principalSelector('subject-u', 'agent-u');
    $this->killSwitch()->kill([$selector], 'kill', $this->paladinA());
    $pending = $this->killSwitch()->requestUnkill(
      [$selector],
      'restore',
      $this->paladinA(),
    );
    $this->assertTrue($pending->needsConfirm);
    $this->assertTrue($this->killSwitch()->isKilled($selector->key));
    try {
      $this->killSwitch()->confirmUnkill($pending->batchId, $this->paladinA());
      $this->fail('Un-kill must not complete with one operator.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
    $done = $this->killSwitch()->confirmUnkill($pending->batchId, $this->paladinB());
    $this->assertFalse($done->needsConfirm);
    $this->assertFalse($this->killSwitch()->isKilled($selector->key));
  }

  /**
   * An audit row is written for each kill-switch transition.
   */
  public function testAuditRowForEachTransition(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-audit');
    $kill = $this->killSwitch()->kill([$human], 'audit-kill', $this->paladinA());
    $this->assertSame($this->paladinA()->storageId(), $this->lastAuditMetadata(McpKillSwitch::AUDIT_KILL)['actor']);
    $this->assertSame('', $this->lastAuditMetadata(McpKillSwitch::AUDIT_KILL)['second_confirmer']);

    $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $confirm = $this->lastAuditMetadata(McpKillSwitch::AUDIT_CONFIRM);
    $this->assertSame($this->paladinB()->storageId(), $confirm['actor']);
    $this->assertSame($this->paladinB()->storageId(), $confirm['second_confirmer']);
    $this->assertArrayNotHasKey('token', $confirm);
    $this->assertArrayNotHasKey('access_token', $confirm);

    $unkill = $this->killSwitch()->requestUnkill([$human], 'audit-unkill', $this->paladinA());
    $this->assertSame(
      $this->paladinA()->storageId(),
      $this->lastAuditMetadata(McpKillSwitch::AUDIT_UNKILL_REQUEST)['actor'],
    );

    $this->killSwitch()->confirmUnkill($unkill->batchId, $this->paladinB());
    $this->assertSame(
      $this->paladinB()->storageId(),
      $this->lastAuditMetadata(McpKillSwitch::AUDIT_UNKILL)['second_confirmer'],
    );
  }

  /**
   * A pending mass kill that times out does not apply and does not weaken.
   */
  public function testUnavailableConfirmerDoesNotWeakenTwoPersonRule(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-unavailable');
    $result = $this->killSwitch()->kill([$human], 'pending', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $result->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
    $expire = $this->lastAuditMetadata(McpKillSwitch::AUDIT_EXPIRE);
    $this->assertSame('confirm_window', $expire['reason']);
  }

  /**
   * Guard bypass: a killed principal is admitted when the guard is off.
   *
   * This is the red run. It must fail if the kill check ignores the guard
   * and still refuses.
   */
  public function testGuardDisableSkipsKillCheck(): void {
    $this->sealSubject('subject-a', 'agent-a');
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-a', 'agent-a')],
      'red-run',
      $this->paladinA(),
    );
    $this->container->get('mcp_sentinel.principal_context_guard')->disableForTest();
    $seen = $this->dispatcher()->admit(['note' => 'ok'], 'probe');
    $this->assertSame('subject-a', $seen->subject());
  }

  /**
   * Restricted permission is required.
   */
  public function testPermissionIsRequired(): void {
    $other = $this->createUser([]);
    $this->assertInstanceOf(User::class, $other);
    try {
      $this->killSwitch()->assertOperatorAccess($other);
      $this->fail('The restricted permission must be required.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::PERMISSION_DENIED, $e->reasonCode);
    }
  }

  /**
   * Re-killing an already-killed key stays killed and still blocks.
   */
  public function testRepeatKillOnKilledKeyStaysKilled(): void {
    $selector = $this->principalSelector('subject-repeat', 'agent-repeat');
    $this->sealSubject('subject-repeat', 'agent-repeat');
    $first = $this->killSwitch()->kill([$selector], 'first', $this->paladinA());
    $this->assertSame(McpKillBlockStatus::Killed, $first->status);
    $again = $this->killSwitch()->kill([$selector], 'again', $this->paladinA(), McpKillTtl::MAX);
    $this->assertSame(McpKillBlockStatus::Killed, $again->status);
    $row = $this->killSwitch()->status($selector);
    $this->assertIsArray($row);
    $this->assertSame(McpKillBlockStatus::Killed->value, $row['status']);
    $this->expectGenericDeny();
  }

  /**
   * Re-requesting a mass kill on a killed key leaves it killed.
   */
  public function testReRequestMassKillOnKilledKeyStaysKilled(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-mass-keep');
    $this->sealSubject('subject-mass-keep', 'agent-mass-keep');
    $pending = $this->killSwitch()->kill([$human], 'mass', $this->paladinA());
    $this->killSwitch()->confirm($pending->batchId, $this->paladinB());
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $again = $this->killSwitch()->kill([$human], 'mass-again', $this->paladinA());
    $this->assertSame(McpKillBlockStatus::Killed, $again->status);
    $this->assertFalse($again->needsConfirm);
    $this->assertSame('', $again->batchId);
    $row = $this->killSwitch()->status($human);
    $this->assertIsArray($row);
    $this->assertSame(McpKillBlockStatus::Killed->value, $row['status']);
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $this->expectGenericDeny();
  }

  /**
   * A mass kill that includes a killed key leaves that key killed.
   */
  public function testMassKillTouchingKilledKeyLeavesItKilled(): void {
    $killed = $this->principalSelector('subject-keep', 'agent-keep');
    $other = $this->principalSelector('subject-other', 'agent-other');
    $this->sealSubject('subject-keep', 'agent-keep');
    $this->killSwitch()->kill([$killed], 'already', $this->paladinA());
    $mass = $this->killSwitch()->kill(
      [$killed, $other],
      'mass-includes-killed',
      $this->paladinA(),
    );
    $this->assertTrue($mass->needsConfirm);
    $row = $this->killSwitch()->status($killed);
    $this->assertIsArray($row);
    $this->assertSame(McpKillBlockStatus::Killed->value, $row['status']);
    $this->assertTrue($this->killSwitch()->isKilled($killed->key));
    $this->expectGenericDeny();
  }

  /**
   * A mass re-kill cancels an in-flight un-kill and stays blocking.
   *
   * The new request is not blocking by itself. It must not leave the
   * un-kill confirmable, and it must not open a phantom confirm batch.
   */
  public function testNewKillCancelsInFlightUnkill(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-cancel-unkill');
    $this->sealSubject('subject-cancel-unkill', 'agent-cancel-unkill');
    $killed = $this->killSwitch()->kill([$human], 'already', $this->paladinA());
    $this->killSwitch()->confirm($killed->batchId, $this->paladinB());
    $pending = $this->killSwitch()->requestUnkill(
      [$human],
      'restore',
      $this->paladinA(),
    );
    $again = $this->killSwitch()->kill([$human], 'stay-dead', $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Killed, $again->status);
    $this->assertFalse($again->needsConfirm);
    $this->assertSame('', $again->batchId);
    $row = $this->killSwitch()->status($human);
    $this->assertIsArray($row);
    $this->assertSame(McpKillBlockStatus::Killed->value, $row['status']);
    $this->assertSame('', $row['unkill_batch_id']);
    try {
      $this->killSwitch()->confirmUnkill($pending->batchId, $this->paladinB());
      $this->fail('A cancelled un-kill must not complete.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNKNOWN_BATCH, $e->reasonCode);
    }
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $this->expectGenericDeny();
  }

  /**
   * A killed principal's config save is reverted, matching denied-name.
   */
  public function testKilledConfigSaveReverts(): void {
    $this->installEntitySchema('consumer');
    $this->installEntitySchema('oauth2_token');
    $this->enableRoleFallbackGovernance();
    if (Role::load('mcp_api') === NULL) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    $account = User::create(['name' => 'killed-config-agent', 'status' => 1]);
    $account->addRole('mcp_api');
    $account->save();
    $this->container->get('current_user')->setAccount($account);
    $this->sealSubject('subject-cfg', 'agent-cfg');
    $this->killSwitch()->kill(
      [$this->principalSelector('subject-cfg', 'agent-cfg')],
      'config-kill',
      $this->paladinA(),
    );
    $original = $this->config('system.site')->get('name');
    try {
      $this->config('system.site')->set('name', 'killed-write')->save();
      $this->fail('A killed principal must not persist a config write.');
    }
    catch (ConfigException $e) {
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
    }
    $this->container->get('config.factory')->reset('system.site');
    $this->assertSame($original, $this->config('system.site')->get('name'));
  }

  /**
   * The same shell posing as two Drupal account ids is refused.
   */
  public function testSameShellPosingAsTwoAccountIdsIsRefused(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-accounts');
    $asUidA = McpOperatorIdentity::fromDrupalUid($this->operatorA);
    $asUidB = McpOperatorIdentity::fromDrupalUid($this->operatorB);
    try {
      $result = $this->killSwitch()->kill([$human], 'uid-pose', $asUidA);
      $this->killSwitch()->confirm($result->batchId, $asUidB);
      $this->fail(
        'The same shell posing as two Drupal account ids must be refused.',
      );
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Two distinct Paladin operators can confirm a mass kill.
   */
  public function testTwoDistinctVerifiedOperatorsSucceed(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-two-ops');
    $kill = $this->killSwitch()->kill([$human], 'mass', $this->paladinA());
    $done = $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Killed, $done->status);
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * A Drush assertion ignores Drupal uid: one shell is one operator.
   */
  public function testDrushAssertionIgnoresDrupalUid(): void {
    $factory = $this->container->get('mcp_sentinel.operator_identity');
    $firstAccount = User::load((int) $this->operatorA);
    $secondAccount = User::load((int) $this->operatorB);
    $this->assertInstanceOf(User::class, $firstAccount);
    $this->assertInstanceOf(User::class, $secondAccount);
    $this->container->get('current_user')->setAccount($firstAccount);
    $previousUser = getenv('USER');
    putenv('USER=operator-one');
    $asA = $factory->fromDrushAssertion();
    $this->container->get('current_user')->setAccount($secondAccount);
    putenv('USER=operator-two');
    $asB = $factory->fromDrushAssertion();
    if ($previousUser === FALSE) {
      putenv('USER');
    }
    else {
      putenv('USER=' . $previousUser);
    }
    $this->assertTrue($asA->equals($asB));
    $human = McpKillSelector::humanKey(self::ISS . '|subject-shell');
    $kill = $this->killSwitch()->kill([$human], 'shell', $asA);
    try {
      $this->killSwitch()->confirm($kill->batchId, $asB);
      $this->fail('The same shell must not confirm by switching Drupal accounts.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * Mixed-channel confirm without a binding is refused.
   */
  public function testUnboundMixedChannelConfirmIsRefused(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-unbound');
    $kill = $this->killSwitch()->kill([$human], 'unbound', $this->paladinA());
    try {
      $this->killSwitch()->confirm($kill->batchId, $this->drushFingerprint('shell-a'));
      $this->fail('Mixed-channel confirm without a binding must be refused.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNBOUND_OPERATOR, $e->reasonCode);
    }
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * The same bound person cannot confirm on the other channel.
   */
  public function testBoundSamePersonCannotConfirmAcrossChannels(): void {
    $paladin = $this->paladinA();
    $drush = $this->drushFingerprint('shell-a');
    $this->bindings()->bind($paladin, $drush);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-same-bound');
    $kill = $this->killSwitch()->kill([$human], 'cross', $paladin);
    try {
      $this->killSwitch()->confirm($kill->batchId, $drush);
      $this->fail('The same bound operator must not confirm on the other channel.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Distinct bound people can confirm across Paladin and Drush.
   */
  public function testBoundDistinctPeopleCanConfirmAcrossChannels(): void {
    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $this->bindings()->bind($this->paladinB(), $this->drushFingerprint('shell-b'));
    $human = McpKillSelector::humanKey(self::ISS . '|subject-cross-bound');
    $kill = $this->killSwitch()->kill([$human], 'cross', $this->paladinA());
    $done = $this->killSwitch()->confirm($kill->batchId, $this->drushFingerprint('shell-b'));
    $this->assertSame(McpKillBlockStatus::Killed, $done->status);
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Identities already bound to different records cannot be merged.
   */
  public function testBindingConflictWhenIdentitiesBelongToDifferentRecords(): void {
    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $this->bindings()->bind($this->paladinB(), $this->drushFingerprint('shell-b'));
    try {
      $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-b'));
      $this->fail('Identities bound to different records must conflict.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $e->reasonCode);
    }
  }

  /**
   * Two Drush OS accounts do not need a Paladin binding.
   */
  public function testSameKindDrushConfirmDoesNotRequireBinding(): void {
    $first = $this->drushFingerprint('shell-a');
    $second = $this->drushFingerprint('shell-b');
    $human = McpKillSelector::humanKey(self::ISS . '|subject-two-shells');
    $kill = $this->killSwitch()->kill([$human], 'shells', $first);
    $done = $this->killSwitch()->confirm($kill->batchId, $second);
    $this->assertSame(McpKillBlockStatus::Killed, $done->status);
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Mixed-channel un-kill confirm without a binding is refused.
   */
  public function testUnboundMixedChannelUnkillConfirmIsRefused(): void {
    $selector = $this->principalSelector('subject-unbound-u', 'agent-unbound-u');
    $this->killSwitch()->kill([$selector], 'kill', $this->paladinA());
    $pending = $this->killSwitch()->requestUnkill(
      [$selector],
      'restore',
      $this->paladinA(),
    );
    try {
      $this->killSwitch()->confirmUnkill(
        $pending->batchId,
        $this->drushFingerprint('shell-b'),
      );
      $this->fail('Mixed-channel un-kill confirm without a binding must be refused.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNBOUND_OPERATOR, $e->reasonCode);
    }
    $this->assertTrue($this->killSwitch()->isKilled($selector->key));
  }

  /**
   * Operator selectors use principal-key vector error codes.
   */
  public function testSelectorUsesPrincipalKeyVectorCodes(): void {
    try {
      McpKillSelector::principalKey(self::ISS . '|sub|act|extra');
      $this->fail('An extra pipe must use the vector invalid_separator code.');
    }
    catch (McpPrincipalKeyException $e) {
      $this->assertSame(McpPrincipalKeyException::INVALID_SEPARATOR, $e->reasonCode);
    }
    try {
      McpKillSelector::humanKey("iss|\x80");
      $this->fail('Invalid UTF-8 must use the vector invalid_utf8 code.');
    }
    catch (McpPrincipalKeyException $e) {
      $this->assertSame(McpPrincipalKeyException::INVALID_UTF8, $e->reasonCode);
    }
  }

  /**
   * Configured max TTL above 7 d is refused rather than applied.
   */
  public function testConfiguredMaxTtlAbove7DaysIsRefused(): void {
    $this->config('mcp_sentinel.settings')
      ->set('kill_switch_max_ttl', McpKillTtl::MAX + 1)
      ->save();
    try {
      $this->killSwitch()->kill(
        [$this->principalSelector('subject-cfg-ttl', 'agent-cfg-ttl')],
        'too-long',
        $this->paladinA(),
      );
      $this->fail('A configured max TTL above 7 d must be a validation error.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::INVALID_TTL, $e->reasonCode);
    }
  }

  /**
   * Seals a Paladin-shaped principal on the current request.
   */
  private function sealSubject(string $sub, string $azp): void {
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => self::ISS,
      'sub' => $sub,
      'azp' => $azp,
      'tenant' => 'tenant-a',
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
   * Principal-key selector for a synthetic subject and actor.
   */
  private function principalSelector(string $sub, string $azp): McpKillSelector {
    return McpKillSelector::principalKey(self::ISS . '|' . $sub . '|' . $azp);
  }

  /**
   * First verified Paladin operator.
   */
  private function paladinA(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|operator-a');
  }

  /**
   * Fabricated Drush assertion for a distinct OS account.
   */
  private function drushFingerprint(string $seed): McpOperatorIdentity {
    return McpOperatorIdentity::drushAssertion(hash('sha256', $seed));
  }

  /**
   * Operator-binding store.
   */
  private function bindings(): McpOperatorBinding {
    return $this->container->get('mcp_sentinel.operator_binding');
  }

  /**
   * Named second person (secondary account holder), Paladin identity.
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
   * Current sealed principal is refused with the generic deny.
   */
  private function expectGenericDeny(): void {
    try {
      $this->dispatcher()->admit(['note' => 'ok'], 'probe');
      $this->fail('The killed principal must still be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
  }

}
