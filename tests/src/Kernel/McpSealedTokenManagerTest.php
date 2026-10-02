<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\consumers\Entity\Consumer;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Mint, verify, and revoke sealed tokens without storing the secret.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpSealedTokenManager
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSealedTokenManager::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSealedTokenManagerTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('consumer');
    // simple_oauth queries oauth2_token when a consumer is saved.
    $this->installEntitySchema('oauth2_token');
    $this->installConfig(['mcp_sentinel']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_sealed_token']);
  }

  /**
   * A designated client can mint a token that verifies and then revokes.
   *
   * @covers ::mint
   * @covers ::verify
   * @covers ::revoke
   * @covers ::list
   */
  public function testMintVerifyRevokeAndNoSecretInList(): void {
    $owner = $this->createAgentOwner();
    $this->createDesignatedConsumer('mcp-agent-prod', $owner);
    $operator = $this->createOperator();

    $manager = $this->manager();
    $issued = $manager->mint('mcp-agent-prod', 900, $operator);
    $this->assertStringStartsWith(McpSealedTokenManager::PREFIX, $issued['token']);
    $this->assertSame('mcp-agent-prod', $issued['client_id']);
    $this->assertSame(900, $issued['ttl']);

    $claims = $manager->verify($issued['token']);
    $this->assertIsArray($claims);
    $this->assertSame('mcp-agent-prod', $claims['client_id']);
    $this->assertSame((int) $owner->id(), $claims['uid']);

    $listed = $manager->list();
    $this->assertCount(1, $listed);
    $this->assertSame($issued['jti'], $listed[0]['jti']);
    $this->assertArrayNotHasKey('token', $listed[0]);
    $this->assertStringNotContainsString($issued['token'], json_encode($listed) ?: '');

    $this->assertTrue($manager->revoke($issued['jti'], $operator));
    $this->assertNull($manager->verify($issued['token']));
  }

  /**
   * Undesignated clients cannot mint.
   *
   * @covers ::mint
   */
  public function testUndesignatedClientCannotMint(): void {
    $owner = $this->createAgentOwner();
    $this->createDesignatedConsumer('mcp-agent-prod', $owner);
    $this->createConsumer('other-client', $owner);
    $operator = $this->createOperator();

    $this->expectException(\InvalidArgumentException::class);
    $this->manager()->mint('other-client', 3600, $operator);
  }

  /**
   * An expired token does not verify.
   *
   * @covers ::verify
   */
  public function testExpiredTokenDoesNotVerify(): void {
    $owner = $this->createAgentOwner();
    $this->createDesignatedConsumer('mcp-agent-prod', $owner);
    $operator = $this->createOperator();

    $issued = $this->manager()->mint('mcp-agent-prod', 900, $operator);
    $this->container->get('database')->update(McpSealedTokenManager::TABLE)
      ->fields(['expires' => 1])
      ->condition('jti', $issued['jti'])
      ->execute();
    $this->assertNull($this->manager()->verify($issued['token']));
  }

  /**
   * A disabled or reassigned Consumer cannot verify a previously minted token.
   *
   * @covers ::verify
   */
  public function testVerifyRechecksConsumerAndOwner(): void {
    $owner = $this->createAgentOwner();
    $consumer = $this->createDesignatedConsumer('mcp-agent-prod', $owner);
    $operator = $this->createOperator();
    $issued = $this->manager()->mint('mcp-agent-prod', 900, $operator);
    $this->assertIsArray($this->manager()->verify($issued['token']));

    $consumer->set('status', 0);
    $consumer->save();
    $this->assertNull($this->manager()->verify($issued['token']));

    $consumer->set('status', 1);
    $consumer->save();
    $reenabled = $this->manager()->verify($issued['token']);
    // bleedingEdge remembers verify() as null after assertNull() above.
    // @phpstan-ignore-next-line
    $this->assertNotNull($reenabled);
    // @phpstan-ignore-next-line
    $this->assertIsArray($reenabled);

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
  }

  /**
   * The plaintext reveal handoff expires after REVEAL_STORE_TTL, not a week.
   *
   * PrivateTempStoreFactory::get() takes only a collection; the expiry is a
   * factory argument. A TTL passed to get() is dropped, and an unrevealed
   * secret then sits in key_value_expire for the site-wide tempstore expiry.
   *
   * @covers ::revealTempStore
   */
  public function testRevealStoreExpiresWithinTheRevealTtl(): void {
    $this->container->get('current_user')->setAccount($this->createOperator());
    $now = $this->container->get('datetime.time')->getRequestTime();

    $this->container->get('mcp_sentinel.sealed_token_reveal_store')
      ->get('mcp_sentinel_sealed_token')
      ->set('reveal', ['token' => 'mcs1.not-a-real-token']);

    $expire = (int) $this->container->get('database')
      ->select('key_value_expire', 'k')
      ->fields('k', ['expire'])
      ->condition('collection', 'tempstore.private.mcp_sentinel_sealed_token')
      ->execute()
      ->fetchField();
    $this->assertGreaterThan($now, $expire);
    $this->assertLessThanOrEqual($now + McpSealedTokenManager::REVEAL_STORE_TTL, $expire);
  }

  /**
   * Returns the manager.
   */
  private function manager(): McpSealedTokenManager {
    return $this->container->get('mcp_sentinel.sealed_token_manager');
  }

  /**
   * Creates the minting operator account.
   */
  private function createOperator(): User {
    $user = User::create([
      'name' => 'mcp-operator',
      'status' => 1,
    ]);
    $user->save();
    return $user;
  }

  /**
   * Creates the designated consumer owner.
   */
  private function createAgentOwner(): User {
    $user = User::create([
      'name' => 'mcp-agent-content',
      'status' => 1,
    ]);
    $user->save();
    return $user;
  }

  /**
   * Creates and designates a Consumer.
   */
  private function createDesignatedConsumer(string $clientId, User $owner): Consumer {
    $consumer = $this->createConsumer($clientId, $owner);
    $this->config('mcp_sentinel.settings')
      ->set('agent_oauth_clients', [$clientId])
      ->save();
    return $consumer;
  }

  /**
   * Creates a Consumer entity.
   */
  private function createConsumer(string $clientId, User $owner): Consumer {
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
    return $consumer;
  }

}
