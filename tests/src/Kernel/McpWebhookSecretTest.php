<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Entity\EntityInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Utils;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests that webhook signing resolves the secret from a Key entity.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpEventDispatcher
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpWebhookSecretTest extends KernelTestBase {

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
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * @covers ::dispatch
   */
  public function testWebhookSignsWithKeyValue(): void {
    // A Key holding the signing secret.
    Key::create([
      'id' => 'mcp_test_secret',
      'label' => 'MCP test secret',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'topsecret'],
    ])->save();

    $this->config('mcp_sentinel.settings')
      ->set('webhook_enabled', TRUE)
      ->set('webhook_url', 'https://example.com/hook')
      ->set('webhook_secret_key', 'mcp_test_secret')
      ->save();

    // Capture the outbound request with a mocked HTTP client.
    $history = [];
    $stack = HandlerStack::create(new MockHandler([new Response(200)]));
    $stack->push(Middleware::history($history));
    $this->container->set('http_client', new Client(['handler' => $stack]));

    $entity = $this->createMock(EntityInterface::class);
    $entity->method('getEntityTypeId')->willReturn('node');
    $entity->method('bundle')->willReturn('article');
    $entity->method('id')->willReturn('7');
    $entity->method('uuid')->willReturn('uuid-7');
    $entity->method('label')->willReturn('Test');

    $this->container->get('mcp_sentinel.event_dispatcher')
      ->dispatch('mcp.entity.presave', $entity);

    // The webhook fires asynchronously; flush the promise queue so the mock
    // handler and history middleware record the request.
    Utils::queue()->run();

    $this->assertCount(1, $history, 'One webhook request was sent.');
    $request = $history[0]['request'];
    $body = (string) $request->getBody();
    $expected = 'sha256=' . hash_hmac('sha256', $body, 'topsecret');
    $this->assertSame($expected, $request->getHeaderLine('X-MCP-Signature'));
  }

}
