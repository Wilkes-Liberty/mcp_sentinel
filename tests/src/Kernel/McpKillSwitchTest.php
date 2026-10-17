<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Config\ConfigException;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBinding;
use Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory;
use Drupal\mcp_sentinel\Service\McpPaladinIntrospection;
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
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request as GuzzleRequest;
use GuzzleHttp\Psr7\Response;
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
   * Pinned operator-bind audience. Not a live client.
   */
  private const AUDIENCE = 'mcp-sentinel-operator-bind';

  /**
   * Pinned operator audience or role. Not a live client.
   */
  private const OPERATOR_AUDIENCE = 'mcp-sentinel-operator';

  /**
   * PHPUnit weaken flags reapplied after Paladin service rebuilds.
   *
   * @var list<string>
   */
  private array $introspectionWeaken = [];

  /**
   * PHPUnit weaken flags reapplied after binding service rebuilds.
   *
   * @var list<string>
   */
  private array $bindingWeaken = [];

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
    foreach ($this->introspectionWeaken as $flag) {
      $this->container->get('mcp_sentinel.paladin_introspection')->weakenForTest($flag);
    }
    foreach ($this->bindingWeaken as $flag) {
      $this->bindings()->weakenForTest($flag);
    }
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
    $this->pinPaladinSettings([
      McpOperatorIdentityFactory::SETTING_ALLOW_OS_ASSERTION => TRUE,
    ]);
    $this->rebuildPaladinServices();
    $factory = $this->container->get('mcp_sentinel.operator_identity');
    $factory->setProcessIdentityForTest(1001, 'alice');
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
   * Without a token, forDrushCommand() is UNVERIFIED on default settings.
   */
  public function testForDrushCommandWithoutTokenIsUnverified(): void {
    $factory = $this->container->get('mcp_sentinel.operator_identity');
    try {
      $factory->forDrushCommand('');
      $this->fail('Default settings must not form a Drush OS identity.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * euid 0 is refused even when the OS-assertion flag is on.
   */
  public function testOsAssertionRefusesEuidZero(): void {
    $this->pinPaladinSettings([
      McpOperatorIdentityFactory::SETTING_ALLOW_OS_ASSERTION => TRUE,
    ]);
    $this->rebuildPaladinServices();
    $factory = $this->container->get('mcp_sentinel.operator_identity');
    $factory->setProcessIdentityForTest(0, 'root');
    try {
      $factory->fromDrushAssertion();
      $this->fail('euid 0 must not be an operator identity.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * Guard bypass: euid 0 binds when the root check is off.
   */
  public function testOsAssertionAcceptsEuidZeroWhenWeakened(): void {
    $this->pinPaladinSettings([
      McpOperatorIdentityFactory::SETTING_ALLOW_OS_ASSERTION => TRUE,
    ]);
    $this->rebuildPaladinServices();
    $factory = $this->container->get('mcp_sentinel.operator_identity');
    $factory->weakenForTest(McpOperatorIdentityFactory::WEAKEN_SKIP_EUID_ZERO);
    $factory->setProcessIdentityForTest(0, 'alice');
    $identity = $factory->fromDrushAssertion();
    $this->assertTrue($identity->isVerified());
  }

  /**
   * Two Paladin identities mapped to one Drupal uid cannot confirm.
   */
  public function testTwoIssSubMappedToOneDrupalUidAreSameOperator(): void {
    $this->bindings()->bindToAccount($this->paladinA(), (int) $this->operatorA);
    $this->bindings()->bindToAccount($this->paladinB(), (int) $this->operatorA);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-same-uid');
    $kill = $this->killSwitch()->kill([$human], 'same-uid', $this->paladinA());
    try {
      $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
      $this->fail('Two tokens mapped to one Drupal uid must be SAME_OPERATOR.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * Guard bypass: the same mapped uid confirms when the uid check is off.
   */
  public function testSameMappedUidConfirmsWhenUidCheckIsWeakened(): void {
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_UID_MATCH);
    $this->bindings()->bindToAccount($this->paladinA(), (int) $this->operatorA);
    $this->bindings()->bindToAccount($this->paladinB(), (int) $this->operatorA);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-weak-uid');
    $kill = $this->killSwitch()->kill([$human], 'weak-uid', $this->paladinA());
    $done = $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Killed, $done->status);
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
   * Guard bypass: mixed-channel and squat checks are skipped when weakened.
   *
   * This is the red mutation for unbound, same-person, and squat tests.
   */
  public function testMixedChannelChecksFailWhenWeakened(): void {
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_MIXED_CHANNEL);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-weak-mix');
    $kill = $this->killSwitch()->kill([$human], 'unbound', $this->paladinA());
    $done = $this->killSwitch()->confirm($kill->batchId, $this->drushFingerprint('shell-a'));
    $this->assertSame(McpKillBlockStatus::Killed, $done->status);

    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $this->bindings()->bind($this->paladinB(), $this->drushFingerprint('shell-b'));
    $merged = $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-b'));
    $this->assertNotSame('', $merged);
  }

  /**
   * Bind derives iss|sub from an active Paladin introspection, not input.
   */
  public function testBindFromTokenUsesIntrospectedIssSub(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson()),
    ]);
    $operatorId = $this->bindings()->bindFromToken('not-a-human-key', (int) $this->operatorA);
    $this->assertNotSame('', $operatorId);
    $this->assertSame(
      $operatorId,
      $this->bindings()->recordId('paladin', self::ISS . '|operator-a'),
    );
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND);
    $this->assertSame($this->paladinA()->storageId(), $audit['actor']);
    $this->assertArrayNotHasKey('token', $audit);
    $this->assertArrayNotHasKey('access_token', $audit);
    $this->assertSame((int) $this->operatorA, $this->bindings()->uidFor($this->paladinA()));
  }

  /**
   * An inactive Paladin token cannot bind.
   */
  public function testBindFromInactiveTokenIsRefused(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'active' => FALSE,
      ])),
    ]);
    try {
      $this->bindings()->bindFromToken('inactive-token', (int) $this->operatorA);
      $this->fail('An inactive Paladin token must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $audit['reason_code']);
    $this->assertArrayNotHasKey('token', $audit);
  }

  /**
   * Paladin unreachable fails closed.
   */
  public function testBindWhenPaladinIsDownFailsClosed(): void {
    $this->stubPaladinIntrospection([
      new ConnectException('down', new GuzzleRequest('POST', 'https://idp.example/introspect')),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('Paladin down must fail closed.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $audit['reason_code']);
  }

  /**
   * Paladin unconfigured fails closed.
   */
  public function testBindWhenPaladinIsUnconfiguredFailsClosed(): void {
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('Unconfigured Paladin must fail closed.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $audit['reason_code']);
  }

  /**
   * An HTTP introspection URL is refused.
   */
  public function testBindWhenPaladinUrlIsHttpFailsClosed(): void {
    $this->pinPaladinSettings([
      'mcp_sentinel.paladin.introspection_url' => 'http://idp.example/introspect',
    ]);
    $this->rebuildPaladinServices();
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('An HTTP Paladin URL must fail closed.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $audit['reason_code']);
  }

  /**
   * Missing client authentication is refused.
   */
  public function testBindWhenClientAuthIsMissingFailsClosed(): void {
    $this->pinPaladinSettings([
      'mcp_sentinel.paladin.client_id' => '',
      'mcp_sentinel.paladin.client_secret' => '',
    ]);
    $this->rebuildPaladinServices();
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('Missing Paladin client auth must fail closed.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $audit['reason_code']);
  }

  /**
   * A token whose iss does not match the pinned issuer is refused.
   */
  public function testBindRefusesWrongIssuer(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'iss' => 'https://other.example/realms/agents',
      ])),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('A token from another issuer must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $audit['reason_code']);
  }

  /**
   * A token for another audience or client is refused.
   */
  public function testBindRefusesWrongAudience(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'aud' => 'some-other-client',
        'azp' => 'some-other-client',
        'client_id' => 'some-other-client',
      ])),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('A token for another client must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $audit['reason_code']);
  }

  /**
   * A token with an act claim cannot bind (agent tokens).
   */
  public function testBindRefusesActClaim(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'act' => ['sub' => 'agent-1'],
      ])),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('An agent token with an act claim must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * A token without the pinned operator audience or role is refused.
   */
  public function testBindRefusesMissingOperatorAudience(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'aud' => self::AUDIENCE,
        'azp' => self::AUDIENCE,
        'client_id' => self::AUDIENCE,
      ])),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('A token without the operator audience must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * Guard bypass: an act claim binds when the act check is off.
   */
  public function testActClaimBindsWhenActCheckIsWeakened(): void {
    $this->introspectionWeaken = [McpPaladinIntrospection::WEAKEN_SKIP_ACT_CLAIM];
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'act' => ['sub' => 'agent-1'],
      ])),
    ]);
    $operatorId = $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
    $this->assertNotSame('', $operatorId);
  }

  /**
   * An expired token is refused even when active is true.
   */
  public function testBindRefusesExpiredToken(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'exp' => 1,
      ])),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('An expired Paladin token must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $audit['reason_code']);
    $this->assertArrayNotHasKey('token', $audit);
  }

  /**
   * An active response with no exp is refused.
   */
  public function testBindRefusesActiveResponseWithoutExp(): void {
    $payload = json_decode($this->activeIntrospectionJson(), TRUE);
    $this->assertIsArray($payload);
    unset($payload['exp']);
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], json_encode($payload, JSON_THROW_ON_ERROR)),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('An introspection response with no exp must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $audit['reason_code']);
    $this->assertArrayNotHasKey('token', $audit);
  }

  /**
   * A 3xx introspection response is refused and is not followed.
   */
  public function testBindRefusesRedirectingIntrospection(): void {
    $this->stubPaladinIntrospection([
      new Response(302, ['Location' => 'https://evil.example/introspect']),
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson()),
    ]);
    try {
      $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
      $this->fail('A redirecting Paladin introspection URL must fail closed.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::PALADIN_UNAVAILABLE, $audit['reason_code']);
    $this->assertArrayNotHasKey('token', $audit);
  }

  /**
   * Guard bypass: missing or elapsed exp binds when the exp check is off.
   *
   * This is the red mutation for testBindRefusesExpiredToken and
   * testBindRefusesActiveResponseWithoutExp.
   */
  public function testMissingExpBindsWhenExpCheckIsWeakened(): void {
    $this->introspectionWeaken = [McpPaladinIntrospection::WEAKEN_SKIP_EXP];
    $payload = json_decode($this->activeIntrospectionJson(), TRUE);
    $this->assertIsArray($payload);
    unset($payload['exp']);
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], json_encode($payload, JSON_THROW_ON_ERROR)),
    ]);
    $operatorId = $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
    $this->assertNotSame('', $operatorId);
    $this->assertSame(
      $operatorId,
      $this->bindings()->recordId('paladin', self::ISS . '|operator-a'),
    );
  }

  /**
   * Guard bypass: a 302 followed by 200 binds when redirects are allowed.
   *
   * This is the red mutation for testBindRefusesRedirectingIntrospection.
   */
  public function testRedirectingIntrospectionBindsWhenRedirectCheckIsWeakened(): void {
    $this->introspectionWeaken = [McpPaladinIntrospection::WEAKEN_SKIP_REDIRECT];
    $this->stubPaladinIntrospection([
      new Response(302, ['Location' => 'https://evil.example/introspect']),
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson()),
    ]);
    $operatorId = $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
    $this->assertNotSame('', $operatorId);
    $this->assertSame(
      $operatorId,
      $this->bindings()->recordId('paladin', self::ISS . '|operator-a'),
    );
  }

  /**
   * Guard bypass: a wrong issuer binds when issuer/audience checks are off.
   *
   * This is the red mutation for testBindRefusesWrongIssuer and
   * testBindRefusesWrongAudience.
   */
  public function testWrongIssuerBindsWhenIssuerCheckIsWeakened(): void {
    $this->introspectionWeaken = [McpPaladinIntrospection::WEAKEN_SKIP_ISSUER_AUDIENCE];
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'iss' => 'https://other.example/realms/agents',
        'sub' => 'operator-a',
      ])),
    ]);
    $operatorId = $this->bindings()->bindFromToken('any-token', (int) $this->operatorA);
    $this->assertNotSame('', $operatorId);
    $this->assertSame(
      $operatorId,
      $this->bindings()->recordId('paladin', 'https://other.example/realms/agents|operator-a'),
    );
  }

  /**
   * A unique-constraint race on bind is an audited conflict, not a raw error.
   */
  public function testConcurrentBindUniqueConstraintIsAuditedConflict(): void {
    $paladin = $this->paladinA();
    $drush = $this->drushFingerprint('shell-race');
    $this->bindings()->beforeUpsertForTest(function () use ($paladin): void {
      $this->container->get('database')->insert(McpOperatorBinding::TABLE)
        ->fields([
          'identity_hash' => hash('sha256', 'paladin' . "\0" . $paladin->id),
          'identity_kind' => 'paladin',
          'identity_id' => $paladin->id,
          'operator_id' => '00000000-0000-4000-8000-000000000099',
          'uid' => 0,
          'unbind_batch_id' => '',
          'unbind_requested_by' => '',
          'unbind_requested_at' => 0,
          'unbind_confirm_until' => 0,
        ])
        ->execute();
    });
    try {
      $this->bindings()->bind($paladin, $drush);
      $this->fail('A unique-constraint race must be a binding conflict.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $audit['reason_code']);
  }

  /**
   * Binding a second identity onto an already-bound record is refused.
   */
  public function testBindJoinExistingRecordIsRefused(): void {
    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    try {
      $this->bindings()->bind($this->paladinB(), $this->drushFingerprint('shell-a'));
      $this->fail('A second identity must not join an already-bound record.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $audit['reason_code']);
    $this->assertArrayNotHasKey('token', $audit);
  }

  /**
   * Guard bypass: a second identity joins when join refusal is off.
   */
  public function testBindJoinExistingRecordWhenJoinCheckIsWeakened(): void {
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_JOIN_REFUSAL);
    $existing = $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $joined = $this->bindings()->bind($this->paladinB(), $this->drushFingerprint('shell-a'));
    $this->assertTrue($this->bindings()->sameRecord($existing, $joined));
  }

  /**
   * Guard bypass: the same operator can confirm unbind when weakened.
   *
   * This is the red mutation for testUnbindNeedsTwoOperators.
   */
  public function testUnbindCompletesWhenSameOperatorIsWeakened(): void {
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_SAME_OPERATOR);
    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $batch = $this->bindings()->requestUnbind($this->paladinA());
    $this->bindings()->confirmUnbind($batch, $this->paladinA());
    $this->assertNull($this->bindings()->recordId('paladin', self::ISS . '|operator-a'));
  }

  /**
   * A squatted identity cannot be rebound to a different operator.
   */
  public function testBindRefusalIsAudited(): void {
    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $this->bindings()->bind($this->paladinB(), $this->drushFingerprint('shell-b'));
    try {
      $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-b'));
      $this->fail('Identities bound to different records must conflict.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $audit['reason_code']);
  }

  /**
   * Unbind stays pending without a second operator.
   */
  public function testUnbindNeedsTwoOperators(): void {
    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $batch = $this->bindings()->requestUnbind($this->paladinA());
    $this->assertNotSame('', $batch);
    try {
      $this->bindings()->confirmUnbind($batch, $this->paladinA());
      $this->fail('Unbind must not complete with one operator.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
    $this->assertNotNull($this->bindings()->recordId('paladin', self::ISS . '|operator-a'));
    $refused = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_UNBIND_REFUSED);
    $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $refused['reason_code']);
    $this->assertArrayNotHasKey('token', $refused);
    $this->bindings()->confirmUnbind($batch, $this->paladinB());
    $this->assertNull($this->bindings()->recordId('paladin', self::ISS . '|operator-a'));
    $this->assertNull($this->bindings()->recordId('drush', $this->drushFingerprint('shell-a')->id));
  }

  /**
   * Unbind request and confirm write audit rows without tokens.
   */
  public function testUnbindWritesAuditRows(): void {
    $this->bindings()->bind($this->paladinA(), $this->drushFingerprint('shell-a'));
    $batch = $this->bindings()->requestUnbind($this->paladinA());
    $request = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_UNBIND_REQUEST);
    $this->assertSame($this->paladinA()->storageId(), $request['actor']);
    $this->assertSame($batch, $request['batch_id']);
    $this->assertArrayNotHasKey('token', $request);
    $this->bindings()->confirmUnbind($batch, $this->paladinB());
    $done = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_UNBIND);
    $this->assertSame($this->paladinB()->storageId(), $done['second_confirmer']);
    $this->assertArrayNotHasKey('token', $done);
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
   * Configure Paladin introspection against a mock HTTP client.
   *
   * @param array<int, \Psr\Http\Message\ResponseInterface|\Throwable> $responses
   *   Mocked introspection responses or transport errors.
   */
  private function stubPaladinIntrospection(array $responses): void {
    $this->pinPaladinSettings();
    $stack = HandlerStack::create(new MockHandler($responses));
    $client = new Client(['handler' => $stack]);
    $this->container->set('http_client', $client);
    $this->rebuildPaladinServices($client);
  }

  /**
   * Pins Paladin introspection in settings.php (not config).
   *
   * @param array<string, mixed> $override
   *   Settings keys to replace. Empty string clears a required pin.
   */
  private function pinPaladinSettings(array $override = []): void {
    $values = Settings::getAll();
    $values['mcp_sentinel.paladin.introspection_url'] = 'https://idp.example/introspect';
    $values['mcp_sentinel.paladin.issuer'] = self::ISS;
    $values['mcp_sentinel.paladin.audience'] = self::AUDIENCE;
    $values['mcp_sentinel.paladin.operator_audience'] = self::OPERATOR_AUDIENCE;
    $values['mcp_sentinel.paladin.client_id'] = 'introspect-client';
    $values['mcp_sentinel.paladin.client_secret'] = 'introspect-secret';
    foreach ($override as $key => $value) {
      $values[$key] = $value;
    }
    $this->container->set('settings', new Settings($values));
  }

  /**
   * Rebuilds introspection and binding against the current container.
   */
  private function rebuildPaladinServices(?ClientInterface $client = NULL): void {
    $introspection = new McpPaladinIntrospection(
      $client ?? $this->container->get('http_client'),
      $this->container->get('settings'),
      $this->container->get('datetime.time'),
    );
    foreach ($this->introspectionWeaken as $flag) {
      $introspection->weakenForTest($flag);
    }
    $factory = new McpOperatorIdentityFactory(
      $this->container->get('mcp_sentinel.principal_context_holder'),
      $this->container->get('private_key'),
      $this->container->get('settings'),
      $introspection,
    );
    $binding = new McpOperatorBinding(
      $this->container->get('database'),
      $this->container->get('uuid'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('datetime.time'),
      $this->container->get('config.factory'),
      $introspection,
      $factory,
    );
    foreach ($this->bindingWeaken as $flag) {
      $binding->weakenForTest($flag);
    }
    $this->container->set('mcp_sentinel.paladin_introspection', $introspection);
    $this->container->set('mcp_sentinel.operator_identity', $factory);
    $this->container->set('mcp_sentinel.operator_binding', $binding);
  }

  /**
   * Active RFC 7662 payload matching the pinned issuer and audience.
   *
   * @param array<string, mixed> $override
   *   Claim overrides.
   */
  private function activeIntrospectionJson(array $override = []): string {
    $payload = $override + [
      'active' => TRUE,
      'iss' => self::ISS,
      'sub' => 'operator-a',
      'aud' => [self::AUDIENCE, self::OPERATOR_AUDIENCE],
      'exp' => $this->container->get('datetime.time')->getRequestTime() + 3600,
    ];
    return json_encode($payload, JSON_THROW_ON_ERROR);
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
