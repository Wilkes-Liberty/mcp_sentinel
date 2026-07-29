<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

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
 *
 * @runTestsInSeparateProcesses
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
    'audit_chain',
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
   *
   * @param int $attempts
   *   Initial attempt count.
   * @param string $payload
   *   Optional payload JSON to store in the row.
   */
  private function seedRow(int $attempts = 0, string $payload = '{}'): int {
    return (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id'  => 'ep1',
        'event_name'   => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', $payload),
        'payload'      => $payload,
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
   * A 3xx answer is a terminal configuration failure, never followed.
   *
   * #3613242: following a 301 would re-issue the signed POST as a bodyless
   * GET (and re-send to a host the SSRF pin never validated), so redirect
   * following is disabled on the request and a 3xx fails terminally with the
   * Location recorded — retrying cannot fix a misconfigured URL.
   *
   * @covers ::processItem
   */
  public function testWorkerFailsTerminallyOnRedirect(): void {
    $id = $this->seedRow();
    $item = [
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => '',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ];
    $history = [];
    $worker = $this->buildWorker([
      new Response(301, ['Location' => 'https://www.example.com/hook']),
    ], $history);
    $worker->processItem($item);

    $row = $this->loadRow($id);
    $this->assertSame('failed_redirect', $row['status']);
    $this->assertSame('301', (string) $row['last_response_code']);
    $this->assertStringContainsString('https://www.example.com/hook', (string) $row['last_response_body']);
    // The redirect was recorded, not followed: exactly one request left the
    // client, and redirect following was disabled on it.
    $this->assertCount(1, $history);
    $this->assertFalse($history[0]['options']['allow_redirects']);

    // failed_redirect is terminal: a replayed queue item must not re-send.
    $history2 = [];
    $worker2 = $this->buildWorker([new Response(200, [], 'ok')], $history2);
    $worker2->processItem($item);
    $this->assertSame('failed_redirect', $this->loadRow($id)['status']);
    $this->assertCount(0, $history2);
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
   * Fix 1: a plain-HTTP URL is blocked at the worker (sender).
   *
   * Not just at enqueue — the worker enforces HTTPS independently.
   *
   * @covers ::processItem
   */
  public function testWorkerBlocksHttpUrl(): void {
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker([new Response(200)], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'http://example.com/hook',
        'secret_key' => '',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $row = $this->loadRow($id);
    $this->assertSame('failed_ssrf', $row['status'],
      'HTTP (non-HTTPS) URL must be blocked at the worker with failed_ssrf status.');
    $this->assertCount(0, $history, 'No HTTP request is made for a plain-HTTP URL.');
  }

  /**
   * Fix 3: a row already claimed as in_progress is not re-sent.
   *
   * @covers ::processItem
   */
  public function testWorkerSkipsInProgressRow(): void {
    $id = $this->seedRow();
    // Simulate another worker claiming the row.
    $this->container->get('database')
      ->update('mcp_sentinel_webhook_delivery')
      ->condition('id', $id)
      ->fields(['status' => 'in_progress'])
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
    $this->assertCount(0, $history,
      'No HTTP request is made for an in_progress row (already claimed).');
    // Status must remain in_progress (the claiming worker will resolve it).
    $row = $this->loadRow($id);
    $this->assertSame('in_progress', $row['status']);
  }

  /**
   * Fix 4: the worker re-sends the stored payload byte-for-byte.
   *
   * Not a synthetic envelope — the stored row payload is used.
   *
   * @covers ::processItem
   */
  public function testWorkerSendsStoredPayload(): void {
    $originalPayload = '{"event":"mcp.entity.presave",'
      . '"entity_type":"node","entity_id":"42"}';
    $id = $this->seedRow(0, $originalPayload);
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
      // Intentionally pass a DIFFERENT payload in the queue item to confirm
      // the worker uses the stored row payload, not the queue item value.
      'payload' => '{"different":"envelope"}',
    ]);
    $this->assertCount(1, $history);
    $sentBody = (string) $history[0]['request']->getBody();
    $this->assertSame($originalPayload, $sentBody,
      'Worker must send the stored row payload byte-for-byte, ignoring the queue-item envelope.');
  }

  /**
   * A declared signing key that is missing refuses the delivery, fail closed.
   *
   * #3613291: an endpoint with no secret_key sends unsigned by design; one
   * that declares a key which cannot be resolved must not silently degrade
   * to unsigned — a month of production deliveries once did exactly that.
   *
   * @covers ::processItem
   */
  public function testWorkerRefusesMissingSigningKey(): void {
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker([new Response(200)], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => 'does_not_exist',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $row = $this->loadRow($id);
    $this->assertSame('failed_key', $row['status']);
    $this->assertStringContainsString('does_not_exist', (string) $row['last_response_body']);
    // Refused means REFUSED: nothing left the client.
    $this->assertCount(0, $history);
  }

  /**
   * A declared signing key that resolves to an empty value also refuses.
   *
   * @covers ::processItem
   */
  public function testWorkerRefusesEmptySigningKey(): void {
    Key::create([
      'id' => 'empty_secret',
      'label' => 'Empty secret',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => ''],
    ])->save();
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker([new Response(200)], $history);
    $worker->processItem([
      'delivery_id' => $id,
      'endpoint' => [
        'id' => 'ep1',
        'url' => 'https://example.com/hook',
        'secret_key' => 'empty_secret',
      ],
      'event_name' => 'mcp.entity.presave',
      'payload' => '{}',
    ]);
    $row = $this->loadRow($id);
    $this->assertSame('failed_key', $row['status']);
    $this->assertCount(0, $history);
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
    $id = $this->seedRow(0, '{"a":1}');
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
    // HMAC is over the STORED payload ('{"a":1}'), not the queue item value.
    $expected = 'sha256=' . hash_hmac('sha256', '{"a":1}', 'topsecret');
    $this->assertSame($expected, $request->getHeaderLine('X-MCP-Signature'));
  }

  /**
   * A network exception schedules a retry without re-queuing (no busy-loop).
   *
   * @covers ::processItem
   */
  public function testWorkerSchedulesRetryOnNetworkException(): void {
    $id = $this->seedRow();
    $history = [];
    $worker = $this->buildWorker(
      [new \RuntimeException('connection refused')],
      $history
    );
    // Fix 6: no RequeueException is thrown; the row goes back to pending with
    // a backoff timestamp so the cron scan picks it up when due.
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
    $this->assertNotNull($row['next_attempt'],
      'next_attempt must be set so cron can re-enqueue when due.');
  }

}
