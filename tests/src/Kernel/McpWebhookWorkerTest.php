<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Queue\RequeueException;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Plugin\QueueWorker\McpWebhookWorker;
use Drupal\key\Entity\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the McpWebhookWorker delivery, retry, backoff and SSRF guard.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Plugin\QueueWorker\McpWebhookWorker
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpWebhookWorkerTest extends KernelTestBase {

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
    'key',
    'tool',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_webhook_delivery']);
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Builds a worker instance with a mock HTTP client.
   *
   * @param \GuzzleHttp\Psr7\Response[]|\Throwable[] $responses
   *   Queue of mock responses/exceptions for the handler.
   * @param array $history
   *   History container populated with the captured requests.
   *
   * @return \Drupal\mcp_sentinel\Plugin\QueueWorker\McpWebhookWorker
   *   The worker plugin.
   *
   * @param-out array|\ArrayAccess<int, array> $history
   */
  private function buildWorker(array $responses, array &$history): McpWebhookWorker {
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));
    $this->container->set('http_client', new Client(['handler' => $stack]));
    $manager = $this->container->get('plugin.manager.queue_worker');
    $worker = $manager->createInstance('mcp_sentinel_webhook_delivery');
    assert($worker instanceof McpWebhookWorker);
    return $worker;
  }

  /**
   * Inserts a pending delivery row and returns its ID.
   */
  private function seedRow(int $attempts = 0): int {
    return (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id'  => 'ep1',
        'event_name'   => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'status'       => 'pending',
        'attempts'     => $attempts,
        'created'      => \Drupal::time()->getRequestTime(),
      ])->execute();
  }

  /**
   * Loads a delivery row by ID.
   */
  private function loadRow(int $id): array {
    return $this->container->get('database')
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('d.id', $id)->execute()->fetchAssoc() ?: [];
  }

  /**
   * A 200 response marks the row sent.
   *
   * @covers ::processItem
   */
  public function testWorkerMarksDeliveredOnHttp200(): void {
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker([new Response(200, [], 'ok')], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => '',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $row = $this->loadRow($id);
    $this->assertSame('sent', $row['status']);
    $this->assertSame('1', (string) $row['attempts']);
    $this->assertSame('200', (string) $row['last_response_code']);
    $this->assertCount(1, $history);
  }

  /**
   * A 500 response schedules a retry with backoff.
   *
   * @covers ::processItem
   */
  public function testWorkerSchedulesRetryOnHttp500(): void {
    $id = $this->seedRow();
    $now = \Drupal::time()->getRequestTime();
    $history = [];
    $worker = $this->buildWorker([new Response(500, [], 'err')], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => '',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $row = $this->loadRow($id);
    $this->assertSame('pending', $row['status']);
    $this->assertSame('1', (string) $row['attempts']);
    $this->assertSame('500', (string) $row['last_response_code']);
    // First retry backoff is 30 s.
    $this->assertSame($now + 30, (int) $row['next_attempt']);
  }

  /**
   * After the maximum attempts a 500 marks the row failed.
   *
   * @covers ::processItem
   */
  public function testWorkerMarksFailedAfterMaxAttempts(): void {
    // attempts=4: this send becomes the 5th and final attempt.
    $id = $this->seedRow(4);
    $history = [];
    $worker = $this->buildWorker([new Response(500, [], 'err')], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => '',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $row = $this->loadRow($id);
    $this->assertSame('failed', $row['status']);
    $this->assertSame('5', (string) $row['attempts']);
  }

  /**
   * An already-sent row is never re-delivered.
   *
   * @covers ::processItem
   */
  public function testWorkerSkipsAlreadySentRow(): void {
    $id = $this->seedRow();
    $this->container->get('database')
      ->update('mcp_sentinel_webhook_delivery')
      ->condition('id', $id)
      ->fields(['status' => 'sent', 'attempts' => 1])
      ->execute();
    $history = [];
    $worker = $this->buildWorker([new Response(200)], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => '',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $this->assertCount(0, $history, 'No HTTP request is made for a sent row.');
  }

  /**
   * A URL resolving to an internal address is blocked as SSRF.
   *
   * @covers ::processItem
   */
  public function testWorkerBlocksSsrfUrl(): void {
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker([new Response(200)], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://192.168.1.1/hook',
        'secret_key' => '',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $row = $this->loadRow($id);
    $this->assertSame('failed_ssrf', $row['status']);
    $this->assertSame('0', (string) $row['attempts']);
    $this->assertCount(0, $history, 'No HTTP request is made for an SSRF URL.');
  }

  /**
   * The HMAC signature header is set when a Key-backed secret is configured.
   *
   * @covers ::processItem
   */
  public function testWorkerSignsWithKeyValue(): void {
    Key::create([
      'id' => 'mcp_wh_secret',
      'label' => 'WH secret',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'topsecret'],
    ])->save();
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker([new Response(200)], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => 'mcp_wh_secret',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{"a":1}',
    ]);
    $this->assertCount(1, $history);
    $request = $history[0]['request'];
    $expected = 'sha256=' . hash_hmac('sha256', '{"a":1}', 'topsecret');
    $this->assertSame($expected, $request->getHeaderLine('X-MCP-Signature'));
  }

  /**
   * A network exception below max attempts requeues the item.
   *
   * @covers ::processItem
   */
  public function testWorkerRequeuesOnNetworkException(): void {
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker(
      [new \RuntimeException('connection refused')],
      $history
    );
    $this->expectException(RequeueException::class);
    try {
      $worker->processItem([
        'delivery_id' => $id,
        'endpoint' => [
          'id' => 'ep1',
          'url' => 'https://example.com/hook',
          'secret_key' => '',
        ],
        'event_name' => 'mcp.entity.presave',
        'payload' => '{}',
      ]);
    }
    finally {
      $row = $this->loadRow($id);
      $this->assertSame('pending', $row['status']);
      $this->assertSame('1', (string) $row['attempts']);
    }
  }

}
