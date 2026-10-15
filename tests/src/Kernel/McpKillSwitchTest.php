<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Entity\EntityStorageException;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
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
      $this->operatorA,
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
      $this->operatorA,
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
    $this->killSwitch()->kill([$selector], 'queued work', $this->operatorA);
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
    $this->assertSame(
      McpKillSwitch::DENY_REASON,
      $this->lastAuditMetadata('denied_access')['reason'],
    );
  }

  /**
   * Default TTL is 24 h; a request above 7 d is capped. Re-kill extends.
   */
  public function testTtlDefaultAndCapAndExtension(): void {
    $selector = $this->principalSelector('subject-ttl', 'agent-ttl');
    $first = $this->killSwitch()->kill([$selector], 'ttl-default', $this->operatorA);
    $this->assertSame(McpKillTtl::DEFAULT, $first->ttl);
    $now = (int) $this->container->get('datetime.time')->getRequestTime();
    $this->assertGreaterThanOrEqual($now + McpKillTtl::DEFAULT - 1, $first->blockUntil);

    $capped = $this->killSwitch()->kill(
      [$this->principalSelector('subject-cap', 'agent-cap')],
      'ttl-cap',
      $this->operatorA,
      McpKillTtl::MAX + 86400,
    );
    $this->assertSame(McpKillTtl::MAX, $capped->ttl);

    $extended = $this->killSwitch()->kill(
      [$selector],
      'ttl-extend',
      $this->operatorA,
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
    $this->killSwitch()->kill([$selector], 'short', $this->operatorA, 60);
    $this->expectGenericDeny();

    $this->container->get('database')->update(McpKillSwitch::TABLE)
      ->fields(['block_until' => 1])
      ->condition('selector_hash', $selector->hash())
      ->execute();
    $this->assertGreaterThan(0, $this->killSwitch()->expireDue());
    $this->assertFalse($this->killSwitch()->isKilled($selector->key));
    $this->assertSame('subject-exp', $this->dispatcher()->admit(['note' => 'ok'], 'probe')->subject());
    $this->assertSame('ttl', $this->lastAuditMetadata(McpKillSwitch::AUDIT_EXPIRE)['reason']);
  }

  /**
   * A mass kill stays pending without a second operator.
   */
  public function testMassKillStaysPendingWithoutSecondOperator(): void {
    $one = $this->principalSelector('subject-m1', 'agent-m1');
    $two = $this->principalSelector('subject-m2', 'agent-m2');
    $result = $this->killSwitch()->kill([$one, $two], 'mass', $this->operatorA);
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
    $result = $this->killSwitch()->kill([$human], 'all agents of this person', $this->operatorA);
    $this->assertTrue($result->needsConfirm);
    try {
      $this->killSwitch()->confirm($result->batchId, $this->operatorA);
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
    $this->killSwitch()->kill([$selector], 'kill', $this->operatorA);
    $pending = $this->killSwitch()->requestUnkill(
      [$selector],
      'restore',
      $this->operatorA,
    );
    $this->assertTrue($pending->needsConfirm);
    $this->assertTrue($this->killSwitch()->isKilled($selector->key));
    try {
      $this->killSwitch()->confirmUnkill($pending->batchId, $this->operatorA);
      $this->fail('Un-kill must not complete with one operator.');
    }
    catch (McpKillSwitchException $e) {
      $this->assertSame(McpKillSwitchException::SAME_OPERATOR, $e->reasonCode);
    }
    $done = $this->killSwitch()->confirmUnkill($pending->batchId, $this->operatorB);
    $this->assertFalse($done->needsConfirm);
    $this->assertFalse($this->killSwitch()->isKilled($selector->key));
  }

  /**
   * An audit row is written for each kill-switch transition.
   */
  public function testAuditRowForEachTransition(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-audit');
    $kill = $this->killSwitch()->kill([$human], 'audit-kill', $this->operatorA);
    $this->assertSame($this->operatorA, $this->lastAuditMetadata(McpKillSwitch::AUDIT_KILL)['actor']);
    $this->assertSame('', $this->lastAuditMetadata(McpKillSwitch::AUDIT_KILL)['second_confirmer']);

    $this->killSwitch()->confirm($kill->batchId, $this->operatorB);
    $confirm = $this->lastAuditMetadata(McpKillSwitch::AUDIT_CONFIRM);
    $this->assertSame($this->operatorB, $confirm['actor']);
    $this->assertSame($this->operatorB, $confirm['second_confirmer']);
    $this->assertArrayNotHasKey('token', $confirm);
    $this->assertArrayNotHasKey('access_token', $confirm);

    $unkill = $this->killSwitch()->requestUnkill([$human], 'audit-unkill', $this->operatorA);
    $this->assertSame(
      $this->operatorA,
      $this->lastAuditMetadata(McpKillSwitch::AUDIT_UNKILL_REQUEST)['actor'],
    );

    $this->killSwitch()->confirmUnkill($unkill->batchId, $this->operatorB);
    $this->assertSame(
      $this->operatorB,
      $this->lastAuditMetadata(McpKillSwitch::AUDIT_UNKILL)['second_confirmer'],
    );
  }

  /**
   * A pending mass kill that times out does not apply and does not weaken.
   */
  public function testUnavailableConfirmerDoesNotWeakenTwoPersonRule(): void {
    $human = McpKillSelector::humanKey(self::ISS . '|subject-unavailable');
    $result = $this->killSwitch()->kill([$human], 'pending', $this->operatorA);
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
      $this->operatorA,
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
