<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Config\ConfigException;
use Drupal\Core\Database\IntegrityConstraintViolationException;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Service\McpOperatorBindingUidSchema;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBinding;
use Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory;
use Drupal\mcp_sentinel\Service\McpPaladinIntrospection;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Service\McpPrincipalKey;
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
   * Settings.php snapshot from setUp. Restored by isolateOperatorSettings().
   *
   * @var array<string, mixed>
   */
  private array $settingsSnapshot = [];

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
    $this->settingsSnapshot = Settings::getAll();
    (new McpOperatorBindingUidSchema($this->container->get('database')))->ensure();
    foreach ($this->introspectionWeaken as $flag) {
      $this->container->get('mcp_sentinel.paladin_introspection')->weakenForTest($flag);
    }
    foreach ($this->bindingWeaken as $flag) {
      $this->bindings()->weakenForTest($flag);
    }
  }

  /**
   * A pre-upgrade principal-key stop still kills a delegated token.
   *
   * Stored rows used iss|sub|<act.sub>. After the act: prefix,
   * dual-match keeps that stop fail-closed. Over-inclusive: the
   * same row also stops azp=<act.sub>.
   */
  public function testLegacyPrincipalKeyKillStopsDelegatedToken(): void {
    $legacy = $this->principalSelector('subject-legacy', 'agent-7');
    $this->killSwitch()->kill([$legacy], 'pre-upgrade', $this->paladinA());
    $this->sealSubject('subject-legacy', 'other-client', 'agent-7');
    try {
      $this->dispatcher()->admit(['note' => 'ok'], 'mcp_kill_probe');
      $this->fail('A legacy principal-key stop must still refuse the delegated token.');
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
    $this->sealSubject('subject-legacy', 'agent-7');
    $this->expectGenericDeny();
  }

  /**
   * A kill row for iss|sub|act:X stops a delegated token.
   */
  public function testActPrefixedKillStopsDelegatedToken(): void {
    $prefixed = $this->principalSelector(
      'subject-act',
      McpPrincipalKey::ACT_PREFIX . 'agent-7',
    );
    $this->killSwitch()->kill([$prefixed], 'delegated', $this->paladinA());
    $this->sealSubject('subject-act', 'other-client', 'agent-7');
    $this->expectGenericDeny();
    $this->sealSubject('subject-act', 'other-client', 'agent-8');
    $this->assertSame(
      'subject-act',
      $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
    );
  }

  /**
   * A new act:X stop also refuses a non-delegated azp=X token.
   *
   * Dual-match is permanent, not limited to leftover legacy
   * rows. Identity stays separated: the sealed key is still
   * iss|sub|X.
   */
  public function testNewActPrefixedStopRefusesNonDelegatedAzpToken(): void {
    $prefixed = $this->principalSelector(
      'subject-new-azp',
      McpPrincipalKey::ACT_PREFIX . 'agent-7',
    );
    $this->killSwitch()->kill([$prefixed], 'new-act-stop', $this->paladinA());
    $this->sealSubject('subject-new-azp', 'agent-7');
    $this->expectGenericDeny();
    $this->sealSubject('subject-new-azp', 'agent-8');
    $this->assertSame(
      'subject-new-azp',
      $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
    );
  }

  /**
   * A new iss|sub|X stop also refuses a delegated act.sub=X token.
   *
   * Dual-match is permanent, not limited to leftover legacy
   * rows. Identity stays separated: the sealed key is still
   * iss|sub|act:X.
   */
  public function testNewUnprefixedStopRefusesDelegatedActSubToken(): void {
    $unprefixed = $this->principalSelector('subject-new-act', 'agent-7');
    $this->killSwitch()->kill([$unprefixed], 'new-azp-stop', $this->paladinA());
    $this->sealSubject('subject-new-act', 'other-client', 'agent-7');
    $this->expectGenericDeny();
    $this->sealSubject('subject-new-act', 'other-client', 'agent-8');
    $this->assertSame(
      'subject-new-act',
      $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject(),
    );
  }

  /**
   * Status and unkill match the stored spelling; enforcement matches both.
   *
   * A legacy iss|sub|X stop still refuses act.sub=X. Status and
   * unkill of the act: twin find no row. The operator must use
   * the stored spelling.
   */
  public function testStatusAndUnkillMatchStoredSpellingOnly(): void {
    $legacy = $this->principalSelector('subject-status-spell', 'agent-7');
    $prefixed = $this->principalSelector(
      'subject-status-spell',
      McpPrincipalKey::ACT_PREFIX . 'agent-7',
    );
    $this->killSwitch()->kill([$legacy], 'stored-spelling', $this->paladinA());
    $this->sealSubject('subject-status-spell', 'other-client', 'agent-7');
    $this->expectGenericDeny();
    $this->assertNull($this->killSwitch()->status($prefixed));
    $stored = $this->killSwitch()->status($legacy);
    $this->assertIsArray($stored);
    $this->assertSame($legacy->key, $stored['selector_key']);
    try {
      $this->killSwitch()->requestUnkill(
        [$prefixed],
        'twin-spelling',
        $this->paladinA(),
      );
      $this->fail('Unkill of the twin spelling must not find the stored row.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::NOT_PENDING, $e->reasonCode);
    }
    $pending = $this->killSwitch()->requestUnkill(
      [$legacy],
      'stored-spelling',
      $this->paladinA(),
    );
    $this->assertTrue($pending->needsConfirm);
    $this->assertSame(McpKillBlockStatus::UnkillPending, $pending->status);
  }

  /**
   * A composed key over 770 is refused at dispatch and audited.
   *
   * A 256/256/253 delegated token is 771 characters. Admit
   * must fail closed with part_too_long on the denied_access
   * row. Removing assertSafeComposedKey() makes this fail.
   */
  public function testComposedOverlongDelegatedTokenIsDeniedAndAudited(): void {
    $iss = str_repeat('a', 256);
    $sub = str_repeat('a', 256);
    $actSub = str_repeat('a', 253);
    $claims = [
      'iss' => $iss,
      'sub' => $sub,
      'azp' => 'agent-client',
      'act' => ['sub' => $actSub],
      'tenant' => 'tenant-a',
    ];
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $claims);
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
    try {
      $this->dispatcher()->admit(['note' => 'ok'], 'mcp_kill_probe');
      $this->fail('A 771-character delegated key must fail closed.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertStringContainsString(
        McpPrincipalKeyException::PART_TOO_LONG,
        $e->getMessage(),
      );
    }
    // The sealed subject is 256 characters. audit_chain maps metadata.id
    // onto entity_id varchar(255) and does not truncate it. MySQL 8
    // strict mode refuses that insert; SQLite does not. A missing row
    // here is the d.o phpunit failure on aa64970 (jobs 13226584 and
    // 13226437). The column value must stay inside 255 bytes so the
    // denial is recorded on every driver.
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata', 'entity_id'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $this->assertLessThanOrEqual(255, strlen((string) $row['entity_id']));
    $this->assertSame(
      'sha256:' . hash('sha256', $sub),
      $row['entity_id'],
    );
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $this->assertStringContainsString(
      McpPrincipalKeyException::PART_TOO_LONG,
      (string) ($meta['explain'] ?? '') . ' ' . (string) ($meta['reason'] ?? ''),
    );
    $this->assertSame($sub, $meta['sub'] ?? NULL);
  }

  /**
   * A new act: stop holds a job that still carries the pre-upgrade key.
   */
  public function testActPrefixedKillHoldsLegacyCarriedJob(): void {
    $prefixed = $this->principalSelector(
      'subject-carry',
      McpPrincipalKey::ACT_PREFIX . 'agent-7',
    );
    $this->killSwitch()->kill([$prefixed], 'queued work', $this->paladinA());
    $legacyKey = self::ISS . '|subject-carry|agent-7';
    $this->assertTrue(
      $this->killSwitch()->wouldHoldKeys(
        $legacyKey,
        self::ISS . '|subject-carry',
        'tenant-a',
      ),
    );
    $job = new McpPrincipalContextJob($this->principalContextHolder());
    $handle = $job->beginCarrying(
      $legacyKey,
      self::ISS . '|subject-carry',
      'tenant-a',
    );
    try {
      $this->dispatcher()->admit(['note' => 'ok'], 'mcp_kill_job_probe');
      $this->fail('A carried pre-upgrade key must be refused by an act: stop.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $job->end($handle);
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
   * A mass kill freezes immediately without a second operator (DEV-985).
   */
  public function testMassKillStaysPendingWithoutSecondOperator(): void {
    $one = $this->principalSelector('subject-m1', 'agent-m1');
    $two = $this->principalSelector('subject-m2', 'agent-m2');
    $result = $this->killSwitch()->kill([$one, $two], 'mass', $this->paladinA());
    $this->assertTrue($result->needsConfirm);
    $this->assertSame(McpKillBlockStatus::KillPending, $result->status);
    $this->assertTrue($this->killSwitch()->isKilled($one->key));
    $this->sealSubject('subject-m1', 'agent-m1');
    $this->expectGenericDeny();
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
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
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
    $this->assertSame($this->paladinA()->storageId(), $this->lastAuditMetadata(McpKillSwitch::AUDIT_FREEZE)['actor']);
    $this->assertSame('', $this->lastAuditMetadata(McpKillSwitch::AUDIT_FREEZE)['second_confirmer']);

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
   * An unconfirmed mass freeze stays frozen and escalates (DEV-985).
   */
  public function testUnavailableConfirmerDoesNotWeakenTwoPersonRule(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-unavailable');
    $result = $this->killSwitch()->kill([$human], 'pending', $this->paladinA());
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['confirm_until' => 1])
      ->condition('batch_id', $result->batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertTrue($this->killSwitch()->isKilled('', $human->key));
    $escalate = $this->lastAuditMetadata(McpKillSwitch::AUDIT_ESCALATE);
    $this->assertSame('confirm_window', $escalate['reason']);
    $this->assertSame($result->batchId, $escalate['batch_id']);
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
   * The new request must not leave the un-kill confirmable, and it
   * must not open a phantom confirm batch.
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
    try {
      $this->killSwitch()->kill([$human], 'uid-pose', $asUidA);
      $this->fail(
        'kill() must throw UNVERIFIED_OPERATOR for a Drupal uid identity.',
      );
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
    $this->assertFalse($this->killSwitch()->isKilled('', $human->key));
  }

  /**
   * Mutation check: a Drupal uid identity applies when that flag is on.
   */
  public function testUidOperatorAppliesWhenTrustUidWeakened(): void {
    $this->killSwitch()->weakenForTest(McpKillSwitch::WEAKEN_TRUST_UID);
    $selector = $this->principalSelector('subject-uid-w', 'agent-uid-w');
    $result = $this->killSwitch()->kill(
      [$selector],
      'uid-w',
      McpOperatorIdentity::fromDrupalUid($this->operatorA),
    );
    $this->assertFalse($result->needsConfirm);
    $this->assertSame(McpKillBlockStatus::Killed, $result->status);
    $this->assertTrue($this->killSwitch()->isKilled($selector->key));
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
   * Without a token, fromPaladinToken() is missing_token.
   */
  public function testFromPaladinTokenWithoutTokenIsMissingToken(): void {
    $this->isolateOperatorSettings();
    $factory = $this->container->get('mcp_sentinel.operator_identity');
    try {
      $factory->fromPaladinToken('');
      $this->fail('A Paladin token is required.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::MISSING_TOKEN, $e->reasonCode);
    }
  }

  /**
   * Guard bypass: fromPaladinToken() forms an identity when skip_token is on.
   */
  public function testFromPaladinTokenWithoutTokenSucceedsWhenWeakened(): void {
    $this->isolateOperatorSettings();
    $factory = $this->container->get('mcp_sentinel.operator_identity');
    $factory->weakenForTest(McpOperatorIdentityFactory::WEAKEN_SKIP_TOKEN);
    $identity = $factory->fromPaladinToken('');
    $this->assertTrue($identity->isVerified());
    $this->assertSame('https://idp.example/realms/agents|weakened-skip-token', $identity->id);
  }

  /**
   * A uid may be bound to only one Paladin iss|sub.
   */
  public function testBindSecondIdentityOnSameUidConflicts(): void {
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
    try {
      $this->bindings()->bindIdentityForTest($this->paladinB(), (int) $this->operatorA);
      $this->fail('A second iss|sub must not bind to the same Drupal uid.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $audit['reason_code']);
  }

  /**
   * Confirm deletes the 10037 kept marker for that batch.
   */
  public function testConfirmClearsUpgradeKeptMarker(): void {
    $batchId = '00000000-0000-4000-8000-000000000081';
    $human = self::ISS . '|kept-confirm';
    $this->insertDrushPendingFreeze($batchId, $human);
    $this->assertSame(1, $this->killSwitch()->keepDrushRequestedPendingAndRevertUnkill());
    $this->assertArrayHasKey($this->upgradeKeptKey($batchId, $human), $this->upgradeKeptMarkers());

    $this->killSwitch()->confirm($batchId, $this->paladinB());
    $this->assertSame([], $this->upgradeKeptMarkers());
    $this->assertFalse($this->container->get('state')->get(McpKillSwitch::STATE_UPGRADE_KEPT, FALSE));
  }

  /**
   * Lift deletes the 10037 kept marker for that batch.
   */
  public function testLiftClearsUpgradeKeptMarker(): void {
    $batchId = '00000000-0000-4000-8000-000000000082';
    $human = self::ISS . '|kept-lift';
    $this->insertDrushPendingFreeze($batchId, $human);
    $this->assertSame(1, $this->killSwitch()->keepDrushRequestedPendingAndRevertUnkill());
    $this->assertArrayHasKey($this->upgradeKeptKey($batchId, $human), $this->upgradeKeptMarkers());

    $this->killSwitch()->lift($batchId, $this->paladinB());
    $this->assertSame([], $this->upgradeKeptMarkers());
    $this->assertFalse($this->container->get('state')->get(McpKillSwitch::STATE_UPGRADE_KEPT, FALSE));
  }

  /**
   * Break-glass lift deletes the 10037 kept marker for that batch.
   */
  public function testBreakGlassLiftClearsUpgradeKeptMarker(): void {
    $batchId = '00000000-0000-4000-8000-000000000083';
    $human = self::ISS . '|kept-break-glass';
    $this->insertDrushPendingFreeze($batchId, $human);
    $this->assertSame(1, $this->killSwitch()->keepDrushRequestedPendingAndRevertUnkill());
    $this->assertArrayHasKey($this->upgradeKeptKey($batchId, $human), $this->upgradeKeptMarkers());

    $this->setSetting(
      'mcp_sentinel.kill_switch.break_glass_operator',
      self::ISS . '|operator-b',
    );
    $this->killSwitch()->breakGlass(
      $batchId,
      McpKillBreakGlassAction::Lift,
      $this->paladinB(),
    );
    $this->assertSame([], $this->upgradeKeptMarkers());
    $this->assertFalse($this->container->get('state')->get(McpKillSwitch::STATE_UPGRADE_KEPT, FALSE));
  }

  /**
   * A 10037 re-run prunes stale markers without re-auditing a keep.
   */
  public function testUpdate10037RerunPrunesStaleKeptMarker(): void {
    $pendingBatch = '00000000-0000-4000-8000-000000000084';
    $staleBatch = '00000000-0000-4000-8000-000000000085';
    $pendingHuman = self::ISS . '|kept-pending';
    $staleHuman = self::ISS . '|kept-stale';
    $this->insertDrushPendingFreeze($pendingBatch, $pendingHuman);
    $this->insertDrushPendingFreeze($staleBatch, $staleHuman);
    $this->assertSame(2, $this->killSwitch()->keepDrushRequestedPendingAndRevertUnkill());
    $this->assertSame(2, $this->upgradeKeptAuditCount());
    $this->assertArrayHasKey(
      $this->upgradeKeptKey($pendingBatch, $pendingHuman),
      $this->upgradeKeptMarkers(),
    );
    $this->assertArrayHasKey(
      $this->upgradeKeptKey($staleBatch, $staleHuman),
      $this->upgradeKeptMarkers(),
    );

    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['status' => McpKillBlockStatus::Expired->value])
      ->condition('batch_id', $staleBatch)
      ->execute();

    $this->assertSame(0, $this->killSwitch()->keepDrushRequestedPendingAndRevertUnkill());
    $kept = $this->upgradeKeptMarkers();
    $this->assertArrayHasKey($this->upgradeKeptKey($pendingBatch, $pendingHuman), $kept);
    $this->assertArrayNotHasKey($this->upgradeKeptKey($staleBatch, $staleHuman), $kept);
    $this->assertSame(2, $this->upgradeKeptAuditCount());
  }

  /**
   * TTL expiry of a leftover marker on a killed batch deletes it.
   */
  public function testExpireDueClearsUpgradeKeptMarker(): void {
    $batchId = '00000000-0000-4000-8000-000000000086';
    $human = self::ISS . '|kept-expire';
    $this->insertDrushPendingFreeze($batchId, $human);
    $this->assertSame(1, $this->killSwitch()->keepDrushRequestedPendingAndRevertUnkill());
    $this->assertArrayHasKey($this->upgradeKeptKey($batchId, $human), $this->upgradeKeptMarkers());

    // Leftover from a batch confirmed before marker cleanup shipped.
    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields([
        'status' => McpKillBlockStatus::Killed->value,
        'block_until' => 1,
      ])
      ->condition('batch_id', $batchId)
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertSame([], $this->upgradeKeptMarkers());
  }

  /**
   * Guard bypass: two identities on one uid confirm when uid checks are off.
   */
  public function testSameMappedUidConfirmsWhenUidCheckIsWeakened(): void {
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_UID_UNIQUE);
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_UID_MATCH);
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
    $this->bindings()->bindIdentityForTest($this->paladinB(), (int) $this->operatorA);
    $human = McpKillSelector::humanKey(self::ISS . '|subject-weak-uid');
    $kill = $this->killSwitch()->kill([$human], 'weak-uid', $this->paladinA());
    $done = $this->killSwitch()->confirm($kill->batchId, $this->paladinB());
    $this->assertSame(McpKillBlockStatus::Killed, $done->status);
  }

  /**
   * Two identities forced onto one uid cannot confirm.
   */
  public function testSameMappedUidCannotConfirm(): void {
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_UID_UNIQUE);
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
    $this->bindings()->bindIdentityForTest($this->paladinB(), (int) $this->operatorA);
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
   * Identities already bound to different uids cannot share one uid.
   */
  public function testBindingConflictWhenIdentitiesBelongToDifferentRecords(): void {
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
    $this->bindings()->bindIdentityForTest($this->paladinB(), (int) $this->operatorB);
    try {
      $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorB);
      $this->fail('An identity already bound to another uid must conflict.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $e->reasonCode);
    }
  }

  /**
   * The unique uid index rejects a second row with the same uid > 0.
   */
  public function testUidUniqueIndexRejectsDuplicate(): void {
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
    $this->assertTrue((new McpOperatorBindingUidSchema($this->container->get('database')))->exists());
    try {
      $this->container->get('database')->insert(McpOperatorBinding::TABLE)
        ->fields([
          'identity_hash' => hash('sha256', 'paladin' . "\0" . $this->paladinB()->id),
          'identity_kind' => 'paladin',
          'identity_id' => $this->paladinB()->id,
          'operator_id' => '00000000-0000-4000-8000-000000000099',
          'uid' => (int) $this->operatorA,
          'unbind_batch_id' => '',
          'unbind_requested_by' => '',
          'unbind_requested_at' => 0,
          'unbind_confirm_until' => 0,
        ])
        ->execute();
      $this->fail('The unique uid index must reject a second row for the same uid.');
    }
    catch (\Exception $e) {
      $this->assertTrue(
        $e instanceof IntegrityConstraintViolationException
        || str_contains($e->getMessage(), 'UNIQUE')
        || str_contains($e->getMessage(), 'unique'),
        $e->getMessage(),
      );
    }
  }

  /**
   * Bind succeeds when the optional mail claim matches a verified email.
   */
  public function testBindFromTokenMailMatch(): void {
    $account = $this->operatorUser((int) $this->operatorA);
    $account->setEmail('alice@example.test');
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'email' => 'alice@example.test',
        'email_verified' => TRUE,
      ])),
    ], [
      McpOperatorBinding::SETTING_MAIL_CLAIM => 'email',
    ]);
    $operatorId = $this->bindToken('any-token', $account);
    $this->assertNotSame('', $operatorId);
  }

  /**
   * Bind refuses when the optional mail claim does not match.
   */
  public function testBindFromTokenMailMismatch(): void {
    $account = $this->operatorUser((int) $this->operatorA);
    $account->setEmail('alice@example.test');
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'email' => 'other@example.test',
        'email_verified' => TRUE,
      ])),
    ], [
      McpOperatorBinding::SETTING_MAIL_CLAIM => 'email',
    ]);
    try {
      $this->bindToken('any-token', $account);
      $this->fail('A token whose mail claim does not match must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_MISMATCH, $e->reasonCode);
    }
  }

  /**
   * Bind refuses when the mail claim is set and email_verified is not true.
   */
  public function testBindFromTokenMailUnverified(): void {
    $account = $this->operatorUser((int) $this->operatorA);
    $account->setEmail('alice@example.test');
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'email' => 'alice@example.test',
        'email_verified' => FALSE,
      ])),
    ], [
      McpOperatorBinding::SETTING_MAIL_CLAIM => 'email',
    ]);
    try {
      $this->bindToken('any-token', $account);
      $this->fail('An unverified mail claim must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_MISMATCH, $e->reasonCode);
    }
  }

  /**
   * Bind refuses when email_verified is missing and a mail claim is pinned.
   */
  public function testBindFromTokenMailVerifiedKeyMissing(): void {
    $account = $this->operatorUser((int) $this->operatorA);
    $account->setEmail('alice@example.test');
    $payload = json_decode($this->activeIntrospectionJson([
      'email' => 'alice@example.test',
    ]), TRUE);
    $this->assertIsArray($payload);
    unset($payload['email_verified']);
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], json_encode($payload, JSON_THROW_ON_ERROR)),
    ], [
      McpOperatorBinding::SETTING_MAIL_CLAIM => 'email',
    ]);
    try {
      $this->bindToken('any-token', $account);
      $this->fail('A missing email_verified claim must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_MISMATCH, $e->reasonCode);
    }
  }

  /**
   * A mail-type name claim is refused unless a mail claim is also pinned.
   */
  public function testBindFromTokenMailTypeNameClaimRequiresMailPin(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'email' => 'alice@example.test',
        'email_verified' => TRUE,
      ])),
    ], [
      McpOperatorBinding::SETTING_NAME_CLAIM => 'email',
    ]);
    try {
      $this->bindToken('any-token');
      $this->fail('A mail-type name claim without a mail pin must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_MISMATCH, $e->reasonCode);
    }
  }

  /**
   * Bind derives iss|sub from an active Paladin introspection, not input.
   */
  public function testBindFromTokenUsesIntrospectedIssSub(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson()),
    ]);
    $operatorId = $this->bindToken('not-a-human-key');
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
   * Bind refuses when the token name claim does not match the account.
   */
  public function testBindFromTokenClaimMismatchIsRefused(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'preferred_username' => 'other-name',
      ])),
    ]);
    try {
      $this->bindToken('any-token');
      $this->fail('A token whose name claim does not match must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_MISMATCH, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::OPERATOR_MISMATCH, $audit['reason_code']);
    $this->assertArrayNotHasKey('token', $audit);
  }

  /**
   * A uid = 0 row is not first-come; only a matching token may re-bind it.
   */
  public function testUidZeroRowCannotBeClaimedFirstCome(): void {
    $paladin = $this->paladinA();
    $this->container->get('database')->insert(McpOperatorBinding::TABLE)
      ->fields([
        'identity_hash' => hash('sha256', 'paladin' . "\0" . $paladin->id),
        'identity_kind' => 'paladin',
        'identity_id' => $paladin->id,
        'operator_id' => '00000000-0000-4000-8000-000000000077',
        'uid' => 0,
        'unbind_batch_id' => '',
        'unbind_requested_by' => '',
        'unbind_requested_at' => 0,
        'unbind_confirm_until' => 0,
      ])
      ->execute();
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'preferred_username' => 'other-name',
      ])),
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson()),
    ]);
    try {
      $this->bindToken('any-token');
      $this->fail('A uid = 0 row must not be claimed without a matching token.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_MISMATCH, $e->reasonCode);
    }
    $this->assertSame(0, $this->bindings()->uidFor($paladin));
    $operatorId = $this->bindToken('any-token');
    $this->assertSame('00000000-0000-4000-8000-000000000077', $operatorId);
    $this->assertSame((int) $this->operatorA, $this->bindings()->uidFor($paladin));
  }

  /**
   * Guard bypass: a mismatched claim binds when the claim check is off.
   */
  public function testBindClaimMismatchSucceedsWhenClaimCheckIsWeakened(): void {
    $this->bindingWeaken[] = McpOperatorBinding::WEAKEN_SKIP_BIND_CLAIM_MATCH;
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'preferred_username' => 'other-name',
      ])),
    ]);
    $operatorId = $this->bindToken('any-token');
    $this->assertNotSame('', $operatorId);
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
      $this->bindToken('inactive-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
      $this->fail('An agent token with an act claim must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * A token with a top-level actor claim cannot bind.
   */
  public function testBindRefusesActorClaim(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'actor' => ['sub' => 'agent-1'],
      ])),
    ]);
    try {
      $this->bindToken('any-token');
      $this->fail('An agent token with an actor claim must not bind.');
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
      $this->bindToken('any-token');
      $this->fail('A token without the operator audience must not bind.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * Operator audience on azp alone is not an operator grant.
   */
  public function testBindRefusesOperatorAudienceOnAzpOnly(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'aud' => self::AUDIENCE,
        'azp' => self::OPERATOR_AUDIENCE,
        'client_id' => self::AUDIENCE,
      ])),
    ]);
    try {
      $this->bindToken('any-token');
      $this->fail(
        'Operator audience on azp or client_id alone must not bind.',
      );
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * Operator audience on client_id alone is not an operator grant.
   */
  public function testBindRefusesOperatorAudienceOnClientIdOnly(): void {
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'aud' => self::AUDIENCE,
        'azp' => self::AUDIENCE,
        'client_id' => self::OPERATOR_AUDIENCE,
      ])),
    ]);
    try {
      $this->bindToken('any-token');
      $this->fail(
        'Operator audience on azp or client_id alone must not bind.',
      );
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::UNVERIFIED_OPERATOR, $e->reasonCode);
    }
  }

  /**
   * Guard bypass: azp-only operator audience binds when that check is off.
   */
  public function testAzpOperatorAudienceBindsWhenAudienceCheckIsWeakened(): void {
    $this->introspectionWeaken = [
      McpPaladinIntrospection::WEAKEN_SKIP_OPERATOR_AUDIENCE,
    ];
    $this->stubPaladinIntrospection([
      new Response(200, ['Content-Type' => 'application/json'], $this->activeIntrospectionJson([
        'aud' => self::AUDIENCE,
        'azp' => self::OPERATOR_AUDIENCE,
        'client_id' => self::AUDIENCE,
      ])),
    ]);
    $operatorId = $this->bindToken('any-token');
    $this->assertNotSame('', $operatorId);
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
    $operatorId = $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
      $this->bindToken('any-token');
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
    $operatorId = $this->bindToken('any-token');
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
    $operatorId = $this->bindToken('any-token');
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
    $operatorId = $this->bindToken('any-token');
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
      $this->bindings()->bindIdentityForTest($paladin, (int) $this->operatorA);
      $this->fail('A unique-constraint race must be a binding conflict.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $e->reasonCode);
    }
    $audit = $this->lastAuditMetadata(McpOperatorBinding::AUDIT_BIND_REFUSED);
    $this->assertSame(McpKillSwitchException::OPERATOR_BINDING_CONFLICT, $audit['reason_code']);
  }

  /**
   * Guard bypass: the same operator can confirm unbind when weakened.
   *
   * This is the red mutation for testUnbindNeedsTwoOperators.
   */
  public function testUnbindCompletesWhenSameOperatorIsWeakened(): void {
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_SAME_OPERATOR);
    $this->bindings()->weakenForTest(McpOperatorBinding::WEAKEN_SKIP_UID_MATCH);
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
    $batch = $this->bindings()->requestUnbind($this->paladinA());
    $this->bindings()->confirmUnbind($batch, $this->paladinA());
    $this->assertNull($this->bindings()->recordId('paladin', self::ISS . '|operator-a'));
  }

  /**
   * A refused bind writes an HMAC row without a token.
   */
  public function testBindRefusalIsAudited(): void {
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
    $this->bindings()->bindIdentityForTest($this->paladinB(), (int) $this->operatorB);
    try {
      $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorB);
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
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
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
  }

  /**
   * Unbind request and confirm write audit rows without tokens.
   */
  public function testUnbindWritesAuditRows(): void {
    $this->bindings()->bindIdentityForTest($this->paladinA(), (int) $this->operatorA);
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
   *
   * @param string $sub
   *   Subject claim.
   * @param string $azp
   *   Authorized-party claim.
   * @param string|null $actSub
   *   Top-level act.sub when sealing a delegated token.
   */
  private function sealSubject(string $sub, string $azp, ?string $actSub = NULL): void {
    $claims = [
      'iss' => self::ISS,
      'sub' => $sub,
      'azp' => $azp,
      'tenant' => 'tenant-a',
    ];
    if ($actSub !== NULL) {
      $claims['act'] = ['sub' => $actSub];
    }
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $claims);
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
   * Inserts a Drush-requested unconfirmed freeze for update 10037 keep.
   */
  private function insertDrushPendingFreeze(string $batchId, string $humanKey): void {
    $this->container->get('database')->insert(McpKillSwitch::TABLE)
      ->fields([
        'selector_hash' => hash('sha256', 'human_key:' . $humanKey),
        'selector_type' => 'human_key',
        'selector_key' => $humanKey,
        'status' => McpKillBlockStatus::KillPending->value,
        'batch_id' => $batchId,
        'requested_by' => 'drush:' . str_repeat('a', 64),
        'requested_at' => 1,
        'confirm_until' => 999999999,
        'block_until' => 2147483647,
        'ttl' => 86400,
        'reason' => 'upgrade',
        'changed' => 1,
      ])
      ->execute();
  }

  /**
   * Durable 10037 kept-marker map.
   *
   * @return array<string, mixed>
   *   Marker keys still stored in site state.
   */
  private function upgradeKeptMarkers(): array {
    $kept = $this->container->get('state')->get(McpKillSwitch::STATE_UPGRADE_KEPT, []);
    $this->assertIsArray($kept);
    return $kept;
  }

  /**
   * State key used by update 10037 for one kept freeze.
   */
  private function upgradeKeptKey(string $batchId, string $humanKey): string {
    return $batchId . "\0" . 'human_key:' . $humanKey;
  }

  /**
   * Audit rows written when 10037 keeps a Drush freeze.
   */
  private function upgradeKeptAuditCount(): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'operator_binding_upgrade_pending_kept')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * First verified Paladin operator.
   */
  private function paladinA(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|operator-a');
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
   * @param array<string, mixed> $settingsOverride
   *   Extra settings.php pins for this stub.
   */
  private function stubPaladinIntrospection(array $responses, array $settingsOverride = []): void {
    $this->pinPaladinSettings($settingsOverride);
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
    $values = $this->settingsSnapshot !== [] ? $this->settingsSnapshot : Settings::getAll();
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
    $factory = new McpOperatorIdentityFactory($introspection);
    $binding = new McpOperatorBinding(
      $this->container->get('database'),
      $this->container->get('uuid'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('datetime.time'),
      $this->container->get('config.factory'),
      $introspection,
      $factory,
      $this->container->get('settings'),
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
    $account = $this->operatorUser((int) $this->operatorA);
    $payload = $override + [
      'active' => TRUE,
      'iss' => self::ISS,
      'sub' => 'operator-a',
      'aud' => [self::AUDIENCE, self::OPERATOR_AUDIENCE],
      'preferred_username' => $account->getAccountName(),
      'exp' => $this->container->get('datetime.time')->getRequestTime() + 3600,
    ];
    return json_encode($payload, JSON_THROW_ON_ERROR);
  }

  /**
   * Restores settings from the setUp snapshot and rebuilds identity services.
   */
  private function isolateOperatorSettings(): void {
    $this->container->set('settings', new Settings($this->settingsSnapshot));
    $this->rebuildPaladinServices();
  }

  /**
   * Bind helper that uses the operator-A account.
   */
  private function bindToken(string $token, ?User $account = NULL): string {
    $account ??= $this->operatorUser((int) $this->operatorA);
    return $this->bindings()->bindFromToken($token, $account);
  }

  /**
   * Loaded operator account.
   */
  private function operatorUser(int $uid): User {
    $account = User::load($uid);
    $this->assertInstanceOf(User::class, $account);
    return $account;
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
