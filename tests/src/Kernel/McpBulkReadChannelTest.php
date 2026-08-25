<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * JSON:API collection reads emit entity_read rows for bulk-read (#3616612).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpBulkReadChannelTest extends KernelTestBase {

  use UserCreationTrait;

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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('system', ['sequences']);
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['filter', 'node', 'mcp_sentinel', 'user']);

    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('audit_enabled', TRUE)
      ->set('audit_log_reads', TRUE)
      ->save();
    McpPolicyProfile::create([
      'id' => 'agent_reads',
      'label' => 'Agent reads',
      'roles' => ['mcp_api'],
      'weight' => 10,
      'allow_read' => TRUE,
    ])->save();
    $this->createUser();
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($agent);
  }

  /**
   * A governed JSON:API collection GET writes one entity_read per resource.
   */
  public function testCollectionWritesEntityReads(): void {
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $event = $this->jsonApiEvent('/jsonapi/node/article', [
      'data' => [
        ['type' => 'node--article', 'id' => 'aaa-1', 'attributes' => ['title' => 'One']],
        ['type' => 'node--article', 'id' => 'aaa-2', 'attributes' => ['title' => 'Two']],
      ],
      'included' => [
        ['type' => 'node--article', 'id' => 'aaa-3'],
      ],
    ]);
    $subscriber->onResponse($event);

    $ids = $this->entityReadIds();
    sort($ids);
    $this->assertSame(['aaa-1', 'aaa-2', 'aaa-3'], $ids);
    $this->assertSame('node', $this->entityReadTypes()[0]);
  }

  /**
   * Read logging is dark when audit_log_reads is off.
   */
  public function testCollectionSilentWhenReadsAreOff(): void {
    $this->config('mcp_sentinel.settings')->set('audit_log_reads', FALSE)->save();
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $subscriber->onResponse($this->jsonApiEvent('/jsonapi/node/article', [
      'data' => [['type' => 'node--article', 'id' => 'silent-1']],
    ]));
    $this->assertSame([], $this->entityReadIds());
  }

  /**
   * A write echo is not a collection read.
   */
  public function testWriteEchoDoesNotCountAsRead(): void {
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $subscriber->onResponse($this->jsonApiEvent('/jsonapi/node/article', [
      'data' => ['type' => 'node--article', 'id' => 'new-1'],
    ], 'POST', 201));
    $this->assertSame([], $this->entityReadIds());
  }

  /**
   * Builds a JSON:API response event on a governed path.
   *
   * @param string $path
   *   Request path.
   * @param array<string, mixed> $body
   *   The document.
   * @param string $method
   *   HTTP method.
   * @param int $status
   *   Response status.
   */
  private function jsonApiEvent(string $path, array $body, string $method = 'GET', int $status = 200): ResponseEvent {
    $request = Request::create($path, $method);
    $stack = $this->container->get('request_stack');
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    $response = new Response(
      (string) json_encode($body),
      $status,
      ['Content-Type' => 'application/vnd.api+json'],
    );
    return new ResponseEvent(
      $this->container->get('http_kernel'),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      $response,
    );
  }

  /**
   * Distinct entity_id values of entity_read rows.
   *
   * @return list<string>
   *   The ids.
   */
  private function entityReadIds(): array {
    $ids = [];
    foreach (\Drupal::database()->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id'])
      ->condition('l.operation', 'entity_read')
      ->execute() as $row) {
      $ids[] = (string) $row->entity_id;
    }
    return $ids;
  }

  /**
   * Entity types of entity_read rows.
   *
   * @return list<string>
   *   The types.
   */
  private function entityReadTypes(): array {
    $types = [];
    foreach (\Drupal::database()->select('audit_chain_log', 'l')
      ->fields('l', ['entity_type'])
      ->condition('l.operation', 'entity_read')
      ->execute() as $row) {
      $types[] = (string) $row->entity_type;
    }
    return $types;
  }

}
