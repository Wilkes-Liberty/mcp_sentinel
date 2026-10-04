<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\Core\Session\AccountEvents;
use Drupal\Core\Session\UserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Deferred denial rows keep the caller and request context of the refusal.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDeferredAuditAttributionTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * Requests removed from the stack, restored in tearDown().
   *
   * @var \Symfony\Component\HttpFoundation\Request[]
   */
  private array $poppedRequests = [];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Deferred failures restore context and do not inherit a later request.
   */
  public function testDeferredFailureRestoresContextWithoutOriginalRequest(): void {
    $actor = $this->container->get('current_user');
    $actor->setAccount(new UserSession(['uid' => 42]));
    $stack = $this->container->get('request_stack');
    $this->emptyRequestStack();
    $chain = $this->createMock(AuditChainLoggerInterface::class);
    $chain->expects($this->once())->method('log')->willReturnCallback(function (string $channel, string $operation, array $metadata) use ($actor): void {
      $this->assertSame(42, (int) $actor->id());
      // Read through the container: the loop above narrows $stack to empty.
      $current = $this->container->get('request_stack')->getCurrentRequest();
      $this->assertInstanceOf(Request::class, $current);
      $this->assertNull($current->getClientIp());
      $this->assertFalse($current->headers->has('Authorization'));
      $this->assertArrayNotHasKey('mcp_client', $metadata);
      $this->assertArrayHasKey('policy_bundle_digest', $metadata);
      $this->assertNull($metadata['policy_bundle_digest']);
      throw new \RuntimeException('Synthetic append failure');
    });
    $database = $this->container->get('database');
    $logger = new McpAuditLogger(
      $this->container->get('config.factory'),
      $stack,
      $chain,
      database: $database,
      policyBundles: $this->container->get('mcp_sentinel.policy_bundle_registry'),
      currentUser: $actor,
      accountSwitcher: $this->container->get('account_switcher'),
    );
    $transaction = $database->startTransaction();
    $logger->logSurvivingRollback('denied_access');
    $later = Request::create('/later', server: ['REMOTE_ADDR' => '192.0.2.43', 'HTTP_X_MCP_CLIENT' => 'later-client']);
    $stack->push($later);
    $actor->setAccount(new UserSession(['uid' => 43]));
    $this->container->get('state')->set(McpPolicyBundleRegistry::STATE_ACTIVE, ['digest' => 'later-policy']);
    try {
      $transaction->rollBack();
      unset($transaction);
      $this->fail('The synthetic append failure must propagate.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('Synthetic append failure', $exception->getMessage());
    }
    $this->assertSame(43, (int) $actor->id());
    $this->assertSame($later, $stack->getCurrentRequest());
    $stack->pop();
  }

  /**
   * A deferred row without a source request survives a trusted-proxy setup.
   */
  public function testDeferredRowWithoutRequestBehindTrustedProxy(): void {
    $this->container->get('current_user')->setAccount(new UserSession(['uid' => 42]));
    $stack = $this->container->get('request_stack');
    $this->emptyRequestStack();
    $proxies = Request::getTrustedProxies();
    $headers = Request::getTrustedHeaderSet();
    Request::setTrustedProxies(['192.0.2.1'], Request::HEADER_X_FORWARDED_FOR);
    try {
      $database = $this->container->get('database');
      $transaction = $database->startTransaction();
      $this->container->get('mcp_sentinel.audit_logger')->logSurvivingRollback('denied_access');
      $transaction->rollBack();
      unset($transaction);
    }
    finally {
      Request::setTrustedProxies($proxies, $headers);
    }
    $rows = $database->select('audit_chain_log', 'l')
      ->fields('l', ['operation', 'uid', 'ip_address'])->execute()->fetchAll();
    $this->assertCount(1, $rows);
    $this->assertSame('denied_access', $rows[0]->operation);
    $this->assertSame(42, (int) $rows[0]->uid);
    $this->assertEmpty($rows[0]->ip_address);
    $this->assertNull($stack->getCurrentRequest());
  }

  /**
   * A throwing account listener cannot strand a nested audit actor switch.
   */
  public function testAccountListenerFailurePreservesOuterSwitch(): void {
    $actor = $this->container->get('current_user');
    $switcher = $this->container->get('account_switcher');
    $actor->setAccount(new UserSession(['uid' => 44]));
    $switcher->switchTo(new UserSession(['uid' => 43]));
    $actor->setAccount(new UserSession(['uid' => 42]));
    $database = $this->container->get('database');
    $transaction = $database->startTransaction();
    $this->container->get('mcp_sentinel.audit_logger')->logSurvivingRollback('denied_access');
    $actor->setAccount(new UserSession(['uid' => 43]));
    $failed = FALSE;
    $this->container->get('event_dispatcher')->addListener(AccountEvents::SET_USER, static function () use ($actor, &$failed): void {
      if (!$failed && (int) $actor->id() === 42) {
        $failed = TRUE;
        throw new \RuntimeException('Synthetic account listener failure');
      }
    });
    try {
      $transaction->rollBack();
      unset($transaction);
      $this->fail('The account listener failure must propagate.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('Synthetic account listener failure', $exception->getMessage());
    }
    $this->assertTrue($failed);
    $this->assertSame(43, (int) $actor->id());
    $switcher->switchBack();
    $this->assertSame(44, (int) $actor->id());
  }

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    // KernelTestBase reads the session from the master request on teardown.
    $stack = $this->container->get('request_stack');
    foreach (array_reverse($this->poppedRequests) as $request) {
      $stack->push($request);
    }
    $this->poppedRequests = [];
    parent::tearDown();
  }

  /**
   * Removes every request from the stack, keeping them for tearDown().
   */
  private function emptyRequestStack(): void {
    $stack = $this->container->get('request_stack');
    while (($request = $stack->pop()) !== NULL) {
      $this->poppedRequests[] = $request;
    }
  }

}
