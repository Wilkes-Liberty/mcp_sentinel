<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_server\Kernel;

use Mcp\Event\ErrorEvent;
use Drupal\Core\Session\AccountEvents;
use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\Core\Lock\DatabaseLockBackend;
use Drupal\Core\Session\UserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry;
use Drupal\mcp_server\Controller\McpServerController;
use Drupal\mcp_server\Exception\McpAuthorizationDeniedException;
use Drupal\mcp_server\Event\McpAuthorizationDeniedEvent;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Mcp\Event\RequestEvent;
use Mcp\Schema\Request\CallToolRequest;
use Mcp\Server;
use Mcp\Server\Session\InMemorySessionStore;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Checks durable denial evidence through real protocol and stream cleanup.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_server
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_server')]
#[RunTestsInSeparateProcesses]
final class McpAuthorizationAuditTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel', 'mcp_server', 'mcp_server_tool_bridge',
    'mcp_sentinel_server',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('consumer');
    $this->installAuditChainSchema();
    $this->installConfig(['mcp_sentinel', 'mcp_server']);
  }

  /**
   * A denied batch member cannot discard a stream or strand its session lock.
   */
  public function testDeniedBatchMemberPreservesStreamAndSessionCleanup(): void {
    if (!class_exists(McpAuthorizationDeniedEvent::class)) {
      // The deferred-attribution cases below run on every MCP Server version.
      $this->markTestSkipped('Needs the MCP Server authorization-denied event, which is not in an MCP Server release yet.');
    }
    $actor = $this->container->get('current_user');
    $actor->setAccount(new UserSession(['uid' => 42]));
    /** @var \ArrayObject<string, mixed> $state */
    $state = new \ArrayObject();
    [$response, $lock_name] = $this->callSuspendingTool($state, TRUE, TRUE);
    $lock = $this->container->get('lock');
    $this->assertFalse($lock->lockMayBeAvailable($lock_name));
    $actor->setAccount(new UserSession(['uid' => 43]));
    $prior_request = $this->container->get('request_stack')->getCurrentRequest();
    $wire = '';
    ob_start(static function (string $chunk) use (&$wire): string {
      $wire .= $chunk;
      return '';
    });
    try {
      $response->sendContent();
    }
    finally {
      ob_end_clean();
    }
    $this->assertStringContainsString('Suspending tool finished', $wire, $state['error'] ?? '');
    $this->assertStringContainsString('"id":2', $wire);
    $this->assertStringContainsString('"code":-32002', $wire);
    $this->assertTrue($state['completed']);
    $this->assertFalse($state['denied_handler_ran']);
    $this->assertSame(1, $state['denial_events']);
    $rows = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['operation', 'metadata', 'uid', 'ip_address', 'user_agent', 'timestamp'])->execute()->fetchAll();
    $this->assertCount(1, $rows, 'Exactly one denial must survive the unrelated tool rollback.');
    $this->assertSame('denied_access', $rows[0]->operation);
    $this->assertSame(42, (int) $rows[0]->uid, 'Deferred evidence must retain the denied caller.');
    $this->assertSame('192.0.2.42', $rows[0]->ip_address);
    $this->assertSame(1234567890, (int) $rows[0]->timestamp);
    $this->assertSame('Chronicle qualification', $rows[0]->user_agent);
    $this->assertSame(43, (int) $actor->id());
    $this->assertSame($prior_request, $this->container->get('request_stack')->getCurrentRequest());
    $metadata = $this->container->get('mcp_sentinel.audit_logger')->decodeMetadata($rows[0]->metadata);
    $this->assertSame('insufficient_scope', $metadata['reason']);
    $this->assertSame('original-client', $metadata['mcp_client']);
    $this->assertSame(403, $metadata['http_status']);
    $this->assertStringNotContainsString('Private diagnostic', $rows[0]->metadata);
    $this->assertFalse($this->container->get('database')->inTransaction());
    $this->assertTrue($lock->lockMayBeAvailable($lock_name));
  }

  /**
   * Deferred failures restore context and do not inherit a later request.
   */
  public function testDeferredFailureRestoresContextWithoutOriginalRequest(): void {
    $actor = $this->container->get('current_user');
    $actor->setAccount(new UserSession(['uid' => 42]));
    $stack = $this->container->get('request_stack');
    while ($stack->getCurrentRequest() !== NULL) {
      $stack->pop();
    }
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
    while ($stack->getCurrentRequest() !== NULL) {
      $stack->pop();
    }
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
   * Calls a tool that suspends its Fiber, through the real SDK transport.
   *
   * @param \ArrayObject<string, mixed> $state
   *   Receives a 'completed' key, TRUE once the tool resumes and returns.
   * @param bool $in_transaction
   *   Whether the tool suspends inside a transaction that it then rolls back.
   * @param bool $denied_batch
   *   Whether to include a policy-denied member in the same batch.
   *
   * @return array{\Symfony\Component\HttpFoundation\StreamedResponse, string}
   *   The unsent streamed response and the session lock name.
   */
  private function callSuspendingTool(\ArrayObject $state, bool $in_transaction, bool $denied_batch = FALSE): array {
    $state['completed'] = FALSE;
    $state['denied_handler_ran'] = FALSE;
    $state['denial_events'] = 0;
    $dispatcher = $this->container->get('event_dispatcher');
    $dispatcher->addListener(ErrorEvent::class, static function (ErrorEvent $event) use ($state): void {
      if ($event->getThrowable() !== NULL) {
        $state['error'] = $event->getThrowable()->getMessage();
      }
    });
    $dispatcher->addListener(RequestEvent::class, static function (RequestEvent $event): void {
      $request = $event->getRequest();
      if ($request instanceof CallToolRequest && $request->name === 'denied_fixture') {
        throw new McpAuthorizationDeniedException('Private diagnostic must not leak', 403);
      }
    });
    $dispatcher->addListener(McpAuthorizationDeniedEvent::class, static function () use ($state): void {
      $state['denial_events']++;
    });
    $database = $this->container->get('database');
    $this->container->set('lock', new DatabaseLockBackend($database));
    $server = Server::builder()
      ->setServerInfo('lock-regression', '1.0.0')
      ->setEventDispatcher($dispatcher)
      ->setSession(new InMemorySessionStore())
      ->addTool(static function () use ($database, $in_transaction, $state): string {
        $transaction = $in_transaction ? $database->startTransaction() : NULL;
        \Fiber::suspend();
        $transaction?->rollBack();
        $state['completed'] = TRUE;
        return 'Suspending tool finished';
      }, name: 'suspending_fixture')
      ->addTool(static function () use ($state): string {
        $state['denied_handler_ran'] = TRUE;
        return 'Must never execute';
      }, name: 'denied_fixture')
      ->build();
    $this->container->set('mcp_server.server', $server);
    $controller = McpServerController::create($this->container);
    $factory = $this->container->get('psr7.http_message_factory');

    $request = $this->buildJsonRpcRequest('initialize', [
      'protocolVersion' => '2025-06-18',
      'capabilities' => [],
      'clientInfo' => ['name' => 'lock-regression', 'version' => '1.0'],
    ]);
    $initialized = $controller->handle($request, $factory->createRequest($request));
    $session_id = $initialized->getHeaderLine('Mcp-Session-Id');
    $this->assertNotEmpty($session_id);

    $request = $this->buildJsonRpcRequest('tools/call', [
      'name' => 'suspending_fixture',
      'arguments' => new \stdClass(),
    ], $session_id);
    if ($denied_batch) {
      $allowed = json_decode($request->getContent(), TRUE, 512, JSON_THROW_ON_ERROR);
      $denied = [
        'jsonrpc' => '2.0',
        'id' => 2,
        'method' => 'tools/call',
        'params' => [
          'name' => 'denied_fixture',
          'arguments' => new \stdClass(),
        ],
      ];
      $request = Request::create('/mcp', 'POST', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_MCP_SESSION_ID' => $session_id,
        'REMOTE_ADDR' => '192.0.2.42',
        'REQUEST_TIME' => 1234567890,
        'REQUEST_TIME_FLOAT' => 1234567890.25,
        'HTTP_USER_AGENT' => 'Chronicle qualification',
        'HTTP_X_MCP_CLIENT' => 'original-client',
      ], json_encode([$allowed, $denied], JSON_THROW_ON_ERROR));
      $request->attributes->set('_route', 'mcp_server.handle');
      $this->container->get('request_stack')->push($request);
    }
    $response = $controller->handle($request, $factory->createRequest($request));
    $this->assertInstanceOf(StreamedResponse::class, $response);
    if ($denied_batch) {
      $event = new ResponseEvent($this->container->get('http_kernel'), $request, HttpKernelInterface::MAIN_REQUEST, $response);
      $dispatcher->dispatch($event, KernelEvents::RESPONSE);
      $this->container->get('request_stack')->pop();
      $this->assertSame($response, $event->getResponse(), 'The streaming response and cleanup callback must survive policy denial.');
    }

    return [$response, 'mcp_session:' . hash('sha256', $session_id)];
  }

  /**
   * Builds a POST request to /mcp with a JSON-RPC payload.
   *
   * @param string $method
   *   JSON-RPC method name.
   * @param array<string, mixed> $params
   *   Method parameters.
   * @param string|null $sessionId
   *   Optional Mcp-Session-Id header value.
   */
  private function buildJsonRpcRequest(string $method, array $params = [], ?string $sessionId = NULL): Request {
    $server = ['CONTENT_TYPE' => 'application/json'];
    if ($sessionId !== NULL) {
      $server['HTTP_MCP_SESSION_ID'] = $sessionId;
    }
    return Request::create(
      '/mcp',
      'POST',
      [],
      [],
      [],
      $server,
      json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => $method, 'params' => $params], JSON_THROW_ON_ERROR),
    );
  }

}
