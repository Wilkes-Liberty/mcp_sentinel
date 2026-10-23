<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use ColinODell\PsrTestLogger\TestLogger;
use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider;
use Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\Tests\mcp_sentinel\Traits\McpSealedTokenDenialAuditTestTrait;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use Drupal\user\UserStorageInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Every sealed-token denial writes one audit_chain row with a reason.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpSealedTokenManager
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSealedTokenManager::class)]
#[CoversClass(McpSealedTokenDenialAuditor::class)]
#[CoversClass(McpSealedTokenAuthProvider::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSealedTokenDenialAuditTest extends KernelTestBase {

  use McpSealedTokenDenialAuditTestTrait;

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
    'image',
    'options',
    'path_alias',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * Designated client used by most tests.
   */
  private const CLIENT_ID = 'mcp-agent-prod';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSealedTokenDenialAudit();
  }

  /**
   * A bearer without the mcs1. prefix is malformed.
   *
   * @covers ::verify
   */
  public function testMalformedPrefixWritesDenial(): void {
    $token = 'not-a-sealed-token';
    $this->assertNull($this->manager()->verify($token));
    $this->assertDenial(McpSealedTokenDenyReason::Malformed, $token);
  }

  /**
   * A prefix-bearing bearer with the wrong part count is malformed.
   *
   * @covers ::verify
   */
  public function testMalformedPartCountWritesDenial(): void {
    $token = McpSealedTokenManager::PREFIX . 'only.two';
    $this->assertNull($this->manager()->verify($token));
    $this->assertDenial(McpSealedTokenDenyReason::Malformed, $token);
  }

  /**
   * An empty body part is malformed.
   *
   * @covers ::verify
   */
  public function testMalformedEmptyPartWritesDenial(): void {
    $token = McpSealedTokenManager::PREFIX . 'jti..sig';
    $this->assertNull($this->manager()->verify($token));
    $this->assertDenial(McpSealedTokenDenyReason::Malformed, $token);
  }

  /**
   * A signed body missing required claims is malformed.
   *
   * @covers ::verify
   */
  public function testMalformedBodyWritesDenial(): void {
    $issued = $this->mint();
    $token = $this->resign($issued['jti'], [
      'v' => 1,
      'jti' => $issued['jti'],
      'cid' => self::CLIENT_ID,
    ]);
    $this->assertNull($this->manager()->verify($token));
    $this->assertDenial(McpSealedTokenDenyReason::Malformed, $token, $issued['jti']);
  }

  /**
   * A forged HMAC is bad_signature.
   *
   * @covers ::verify
   */
  public function testBadSignatureWritesDenial(): void {
    $issued = $this->mint();
    $token = $issued['token'] . 'x';
    $this->assertNull($this->manager()->verify($token));
    $this->assertDenial(McpSealedTokenDenyReason::BadSignature, $token, $issued['jti']);
  }

  /**
   * A body exp in the past is expired.
   *
   * @covers ::verify
   */
  public function testExpiredBodyWritesDenial(): void {
    $issued = $this->mint();
    $token = $this->resign($issued['jti'], [
      'v' => 1,
      'jti' => $issued['jti'],
      'cid' => self::CLIENT_ID,
      'uid' => $issued['uid'],
      'scp' => [],
      'exp' => 1,
    ]);
    $this->assertNull($this->manager()->verify($token));
    $this->assertDenial(McpSealedTokenDenyReason::Expired, $token, $issued['jti']);
  }

  /**
   * A stored row whose expires is in the past is expired.
   *
   * @covers ::verify
   */
  public function testExpiredRowWritesDenial(): void {
    $issued = $this->mint();
    $this->container->get('database')->update(McpSealedTokenManager::TABLE)
      ->fields(['expires' => 1])
      ->condition('jti', $issued['jti'])
      ->execute();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::Expired,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A signed jti with no row is unknown_token.
   *
   * @covers ::verify
   */
  public function testUnknownTokenWritesDenial(): void {
    $issued = $this->mint();
    $jti = '00000000-0000-4000-8000-000000000099';
    $token = $this->resign($jti, [
      'v' => 1,
      'jti' => $jti,
      'cid' => self::CLIENT_ID,
      'uid' => $issued['uid'],
      'scp' => [],
      'exp' => $issued['expires'],
    ]);
    $this->assertNull($this->manager()->verify($token));
    $this->assertDenial(McpSealedTokenDenyReason::UnknownToken, $token, $jti);
  }

  /**
   * A revoked row is revoked.
   *
   * @covers ::verify
   */
  public function testRevokedWritesDenial(): void {
    $issued = $this->mint();
    $this->assertTrue(
      $this->manager()->revoke($issued['jti'], $this->operator()),
    );
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::Revoked,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A stored hash that does not match is hash_mismatch.
   *
   * @covers ::verify
   */
  public function testHashMismatchWritesDenial(): void {
    $issued = $this->mint();
    $this->container->get('database')->update(McpSealedTokenManager::TABLE)
      ->fields(['token_hash' => str_repeat('a', 64)])
      ->condition('jti', $issued['jti'])
      ->execute();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::HashMismatch,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A client dropped from the designated list is client_not_designated.
   *
   * @covers ::verify
   */
  public function testClientNotDesignatedWritesDenial(): void {
    $issued = $this->mint();
    $this->config('mcp_sentinel.settings')
      ->set('agent_oauth_clients', [])
      ->save();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::ClientNotDesignated,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A stored client_id that does not match the body is audience_mismatch.
   *
   * @covers ::verify
   */
  public function testAudienceMismatchClientWritesDenial(): void {
    $issued = $this->mint();
    $other = $this->createDesignatedConsumer('mcp-agent-other', $this->owner());
    $this->config('mcp_sentinel.settings')
      ->set('agent_oauth_clients', [self::CLIENT_ID, 'mcp-agent-other'])
      ->save();
    $this->container->get('database')->update(McpSealedTokenManager::TABLE)
      ->fields(['client_id' => 'mcp-agent-other'])
      ->condition('jti', $issued['jti'])
      ->execute();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::AudienceMismatch,
      $issued['token'],
      $issued['jti'],
    );
    $this->assertSame('mcp-agent-other', (string) $other->get('client_id')->value);
  }

  /**
   * A stored uid that does not match the body is audience_mismatch.
   *
   * @covers ::verify
   */
  public function testAudienceMismatchUidWritesDenial(): void {
    $issued = $this->mint();
    $other = User::create([
      'name' => 'mcp-other-uid',
      'status' => 1,
    ]);
    $other->save();
    $this->container->get('database')->update(McpSealedTokenManager::TABLE)
      ->fields(['uid' => (int) $other->id()])
      ->condition('jti', $issued['jti'])
      ->execute();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::AudienceMismatch,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A missing Consumer is consumer_missing.
   *
   * @covers ::verify
   */
  public function testConsumerMissingWritesDenial(): void {
    $issued = $this->mint();
    $found = $this->container->get('entity_type.manager')
      ->getStorage('consumer')
      ->loadByProperties(['client_id' => self::CLIENT_ID]);
    $consumer = $found ? reset($found) : NULL;
    $this->assertInstanceOf(Consumer::class, $consumer);
    $consumer->delete();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::ConsumerMissing,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * An unpublished Consumer is consumer_unpublished.
   *
   * @covers ::verify
   */
  public function testConsumerUnpublishedWritesDenial(): void {
    $issued = $this->mint();
    $found = $this->container->get('entity_type.manager')
      ->getStorage('consumer')
      ->loadByProperties(['client_id' => self::CLIENT_ID]);
    $consumer = $found ? reset($found) : NULL;
    $this->assertInstanceOf(Consumer::class, $consumer);
    $consumer->set('status', 0);
    $consumer->save();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::ConsumerUnpublished,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A Consumer reassigned to another owner is owner_mismatch.
   *
   * @covers ::verify
   */
  public function testOwnerMismatchWritesDenial(): void {
    $issued = $this->mint();
    $found = $this->container->get('entity_type.manager')
      ->getStorage('consumer')
      ->loadByProperties(['client_id' => self::CLIENT_ID]);
    $consumer = $found ? reset($found) : NULL;
    $this->assertInstanceOf(Consumer::class, $consumer);
    $other = User::create([
      'name' => 'mcp-reassigned-owner',
      'status' => 1,
    ]);
    $other->save();
    $consumer->set('owner_id', $other->id());
    if ($consumer->hasField('user_id')) {
      $consumer->set('user_id', $other->id());
    }
    $consumer->save();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::OwnerMismatch,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A missing owner account is account_missing.
   *
   * @covers ::verify
   */
  public function testAccountMissingWritesDenial(): void {
    $issued = $this->mint();
    $owner = $this->owner();
    $owner->delete();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::AccountMissing,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A blocked owner account is account_blocked.
   *
   * @covers ::verify
   */
  public function testAccountBlockedWritesDenial(): void {
    $issued = $this->mint();
    $owner = $this->owner();
    $owner->block();
    $owner->save();
    $this->assertNull($this->manager()->verify($issued['token']));
    $this->assertDenial(
      McpSealedTokenDenyReason::AccountBlocked,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * Authenticate() does not write a second row when verify() already denied.
   *
   * @covers \Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider::authenticate
   */
  public function testAuthenticateDoesNotDoubleAuditVerifyDenial(): void {
    $token = McpSealedTokenManager::PREFIX . 'only.two';
    $request = Request::create('https://sentinel.example/jsonapi/node/page');
    $request->headers->set('Authorization', 'Bearer ' . $token);
    $this->pushRequestKeepingSession($request);
    $this->assertNull($this->provider()->authenticate($request));
    $this->assertDenial(McpSealedTokenDenyReason::Malformed, $token);
  }

  /**
   * A missing account after verify() is account_missing.
   *
   * @covers \Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider::authenticate
   */
  public function testAuthenticateAccountMissingWritesDenial(): void {
    $issued = $this->mint();
    $storage = $this->createMock(UserStorageInterface::class);
    $storage->expects($this->once())->method('load')->willReturn(NULL);
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->expects($this->once())
      ->method('getStorage')
      ->with('user')
      ->willReturn($storage);
    $provider = new McpSealedTokenAuthProvider(
      fn () => $this->manager(),
      $entityTypeManager,
      static fn () => new TestLogger(),
    );
    $request = Request::create('https://sentinel.example/jsonapi/node/page');
    $request->headers->set('Authorization', 'Bearer ' . $issued['token']);
    $this->assertNull($provider->authenticate($request));
    $this->assertFalse(
      $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE),
    );
    $this->assertDenial(
      McpSealedTokenDenyReason::AccountMissing,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A blocked account after verify() is account_blocked.
   *
   * @covers \Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider::authenticate
   */
  public function testAuthenticateAccountBlockedWritesDenial(): void {
    $issued = $this->mint();
    $account = $this->createMock(UserInterface::class);
    $account->method('isActive')->willReturn(FALSE);
    $storage = $this->createMock(UserStorageInterface::class);
    $storage->expects($this->once())->method('load')->willReturn($account);
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->expects($this->once())
      ->method('getStorage')
      ->with('user')
      ->willReturn($storage);
    $provider = new McpSealedTokenAuthProvider(
      fn () => $this->manager(),
      $entityTypeManager,
      static fn () => new TestLogger(),
    );
    $request = Request::create('https://sentinel.example/jsonapi/node/page');
    $request->headers->set('Authorization', 'Bearer ' . $issued['token']);
    $this->assertNull($provider->authenticate($request));
    $this->assertDenial(
      McpSealedTokenDenyReason::AccountBlocked,
      $issued['token'],
      $issued['jti'],
    );
  }

  /**
   * A throwing audit writer still denies.
   *
   * @covers ::verify
   * @covers \Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor::record
   */
  public function testThrowingAuditWriterStillDenies(): void {
    $spy = new TestLogger();
    $throwing = $this->createMock(McpAuditLogger::class);
    $throwing->expects($this->once())
      ->method('logAlways')
      ->willThrowException(new \RuntimeException('audit down'));
    $auditor = new McpSealedTokenDenialAuditor(
      $throwing,
      $this->container->get('config.factory'),
      $this->container->get('datetime.time'),
      $this->container->get('request_stack'),
      $spy,
      $this->container->get('keyvalue.expirable'),
    );
    $manager = new McpSealedTokenManager(
      $this->container->get('database'),
      $this->container->get('config.factory'),
      $this->container->get('entity_type.manager'),
      $this->container->get('datetime.time'),
      $this->container->get('uuid'),
      $this->container->get('private_key'),
      $this->container->get('settings'),
      $throwing,
      $auditor,
    );
    $token = McpSealedTokenManager::PREFIX . 'forged.not.real';
    $this->assertNull($manager->verify($token));
    $this->assertTrue($spy->hasErrorRecords());
    $encoded = json_encode($spy->records) ?: '';
    $this->assertStringNotContainsString($token, $encoded);
    $this->assertStringContainsString(
      'RuntimeException',
      $encoded,
    );
  }

  /**
   * Repeat denials of the same reason and principal share one row.
   *
   * The window is 60 seconds by default
   * (mcp_sentinel.settings:sealed_token_deny_audit_window).
   *
   * @covers \Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor::record
   */
  public function testDenialAuditDedupesWithinWindow(): void {
    $now = $this->container->get('datetime.time')->getRequestTime();
    $clock = new McpSealedTokenDenyAuditTestClock($now);
    $auditor = new McpSealedTokenDenialAuditor(
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('config.factory'),
      $clock,
      $this->container->get('request_stack'),
      new TestLogger(),
      $this->container->get('keyvalue.expirable'),
    );
    $token = McpSealedTokenManager::PREFIX . 'forged.not.real';
    $manager = new McpSealedTokenManager(
      $this->container->get('database'),
      $this->container->get('config.factory'),
      $this->container->get('entity_type.manager'),
      $clock,
      $this->container->get('uuid'),
      $this->container->get('private_key'),
      $this->container->get('settings'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $auditor,
    );
    $this->assertNull($manager->verify($token));
    $this->assertNull($manager->verify($token));
    $this->assertNull($manager->verify($token));
    $this->assertCount(1, $this->sealedTokenDenialRows());
    $clock->now += McpSealedTokenDenialAuditor::DEFAULT_WINDOW;
    $this->assertNull($manager->verify($token));
    $this->assertCount(2, $this->sealedTokenDenialRows());
  }

  /**
   * Secret material supplied as context is never written.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor::record
   */
  public function testAuditorDropsSecretContextKeys(): void {
    $token = 'mcs1.this-must-never-be-logged';
    $this->container->get('mcp_sentinel.sealed_token_denial_auditor')
      ->record(McpSealedTokenDenyReason::Malformed, [
        'token' => $token,
        'signature' => 'deadbeef',
        'jti' => 'visible-jti',
      ]);
    $rows = $this->sealedTokenDenialRows();
    $this->assertCount(1, $rows);
    $encoded = json_encode($rows) ?: '';
    $this->assertStringNotContainsString($token, $encoded);
    $this->assertStringNotContainsString('deadbeef', $encoded);
    $this->assertSame('visible-jti', $rows[0]['jti'] ?? NULL);
  }

  /**
   * Asserts one sealed-token denied_access row for $reason.
   *
   * Fails if the production audit write is removed.
   */
  private function assertDenial(
    McpSealedTokenDenyReason $reason,
    string $token,
    ?string $jti = NULL,
  ): void {
    $rows = $this->sealedTokenDenialRows();
    $this->assertCount(
      1,
      $rows,
      'Expected one sealed-token denied_access row for ' . $reason->value,
    );
    $meta = $rows[0];
    $this->assertSame($reason->value, $meta['reason'] ?? NULL);
    $this->assertSame('sealed_token', $meta['tool'] ?? NULL);
    $this->assertSame(1, $meta['count'] ?? NULL);
    $this->assertSame(
      McpSealedTokenDenialAuditor::DEFAULT_WINDOW,
      $meta['window_seconds'] ?? NULL,
    );
    $this->assertSame('/jsonapi/node/page', $meta['path'] ?? NULL);
    $this->assertSame('sentinel.example', $meta['site'] ?? NULL);
    if ($jti !== NULL && $jti !== '') {
      $this->assertSame($jti, $meta['jti'] ?? NULL);
    }
    $encoded = json_encode($meta) ?: '';
    $this->assertStringNotContainsString($token, $encoded);
    $this->assertArrayNotHasKey('token', $meta);
    $this->assertArrayNotHasKey('signature', $meta);
    $this->assertArrayNotHasKey('sig', $meta);
  }

  /**
   * Mints a designated-client token and returns claims plus uid.
   *
   * @return array{token: string, jti: string, uid: int, expires: int}
   *   Issued token metadata.
   */
  private function mint(): array {
    $owner = $this->owner();
    $this->createDesignatedConsumer(self::CLIENT_ID, $owner);
    $issued = $this->manager()->mint(self::CLIENT_ID, 900, $this->operator());
    return [
      'token' => $issued['token'],
      'jti' => $issued['jti'],
      'uid' => (int) $owner->id(),
      'expires' => $issued['expires'],
    ];
  }

  /**
   * Rebuilds a signed sealed token with a substituted body.
   *
   * @param string $jti
   *   Token id.
   * @param array<string, mixed> $body
   *   Body claims.
   *
   * @return string
   *   Bearer. Tests must not log this value.
   */
  private function resign(string $jti, array $body): string {
    $manager = $this->manager();
    $material = new \ReflectionMethod($manager, 'material');
    $material->setAccessible(TRUE);
    $b64 = new \ReflectionMethod($manager, 'b64');
    $b64->setAccessible(TRUE);
    $bodyEncoded = $b64->invoke(
      $manager,
      json_encode($body, JSON_THROW_ON_ERROR),
    );
    $sig = $b64->invoke(
      $manager,
      hash_hmac(
        'sha256',
        $jti . '.' . $bodyEncoded,
        $material->invoke($manager),
        TRUE,
      ),
    );
    return McpSealedTokenManager::PREFIX . $jti . '.' . $bodyEncoded . '.' . $sig;
  }

  /**
   * Returns the manager.
   */
  private function manager(): McpSealedTokenManager {
    return $this->container->get('mcp_sentinel.sealed_token_manager');
  }

  /**
   * Returns the auth provider.
   */
  private function provider(): McpSealedTokenAuthProvider {
    return $this->container->get('mcp_sentinel.sealed_token_auth');
  }

  /**
   * Operator account, created once.
   */
  private function operator(): User {
    $existing = $this->loadUserByName('mcp-operator');
    if ($existing instanceof User) {
      return $existing;
    }
    $user = User::create([
      'name' => 'mcp-operator',
      'status' => 1,
    ]);
    $user->save();
    return $user;
  }

  /**
   * Designated consumer owner, created once.
   */
  private function owner(): User {
    $existing = $this->loadUserByName('mcp-agent-content');
    if ($existing instanceof User) {
      return $existing;
    }
    $user = User::create([
      'name' => 'mcp-agent-content',
      'status' => 1,
    ]);
    $user->save();
    return $user;
  }

  /**
   * Loads a user by name, or NULL when missing.
   */
  private function loadUserByName(string $name): ?User {
    $found = $this->container->get('entity_type.manager')
      ->getStorage('user')
      ->loadByProperties(['name' => $name]);
    $user = $found ? reset($found) : NULL;
    return $user instanceof User ? $user : NULL;
  }

  /**
   * Creates and designates a Consumer.
   */
  private function createDesignatedConsumer(string $clientId, User $owner): Consumer {
    $found = $this->container->get('entity_type.manager')
      ->getStorage('consumer')
      ->loadByProperties(['client_id' => $clientId]);
    $consumer = $found ? reset($found) : NULL;
    if (!$consumer instanceof Consumer) {
      $consumer = Consumer::create([
        'client_id' => $clientId,
        'label' => $clientId,
        'owner_id' => $owner->id(),
        'user_id' => $owner->id(),
        'secret' => 'not-echoed',
        'confidential' => TRUE,
        'status' => 1,
      ]);
      $consumer->save();
    }
    $ids = (array) ($this->config('mcp_sentinel.settings')
      ->get('agent_oauth_clients') ?? []);
    $ids[] = $clientId;
    $this->config('mcp_sentinel.settings')
      ->set('agent_oauth_clients', array_values(array_unique($ids)))
      ->save();
    return $consumer;
  }

}
