<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Classification egress at the JSON:API request and response seams.
 *
 * The request seam refuses an over-ceiling resource type before the
 * controller runs (every method — a write echoes the entity); the response
 * seam is defense in depth: an over-ceiling type that survives to
 * serialization is refused with the same structured code, and an at-ceiling
 * body passes byte-identical (d.o #3616540 part 2, §5.1/§5.4/§5.5).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpClassificationEgressSeamsTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * A value that must never appear in evidence.
   */
  private const SENTINEL_VALUE = 'SENTINEL-BODY-2b7e';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt',
    'audit_chain', 'mcp_sentinel',
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

    NodeType::create(['type' => 'memo', 'name' => 'Memo'])->save();
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('classification_map', [
        ['entity_type' => 'node', 'bundle' => 'memo', 'field' => '', 'label' => 'restricted'],
      ])
      ->save();
    // The first account (uid 1) is a bystander; the agent is an ordinary one.
    $this->createUser();
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($agent);
  }

  /**
   * Sets the default profile's ceilings.
   *
   * @param array<string, string> $ceilings
   *   Surface value => label.
   */
  private function setCeilings(array $ceilings): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('egress_ceilings', $ceilings)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
  }

  /**
   * Whether a request of this test's own is on top of the stack.
   */
  private bool $pushedRequest = FALSE;

  /**
   * Makes a request current, keeping the kernel's master request underneath.
   */
  private function pushRequest(Request $request): void {
    $stack = $this->container->get('request_stack');
    if ($this->pushedRequest) {
      $stack->pop();
    }
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    $this->pushedRequest = TRUE;
  }

  /**
   * Builds a routed JSON:API request event for a bundle route.
   */
  private function requestEvent(string $bundle, string $method = 'GET', array $headers = [], string $suffix = ''): RequestEvent {
    $request = Request::create('/jsonapi/node/' . $bundle . $suffix, $method);
    $request->attributes->set(
      'resource_type',
      $this->container->get('jsonapi.resource_type.repository')->get('node', $bundle),
    );
    foreach ($headers as $name => $value) {
      $request->headers->set($name, $value);
    }
    $this->pushRequest($request);
    return new RequestEvent($this->container->get('http_kernel'), $request, HttpKernelInterface::MAIN_REQUEST);
  }

  /**
   * Builds a response event carrying a JSON:API body.
   */
  private function responseEvent(string $path, array|string $body, string $method = 'GET', int $status = 200, string $type = 'application/vnd.api+json'): ResponseEvent {
    $request = Request::create($path, $method);
    $this->pushRequest($request);
    $content = is_array($body) ? (string) json_encode($body) : $body;
    $response = new Response($content, $status, ['Content-Type' => $type]);
    return new ResponseEvent($this->container->get('http_kernel'), $request, HttpKernelInterface::MAIN_REQUEST, $response);
  }

  /**
   * Decoded classification evidence rows.
   */
  private function evidenceRows(): array {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $rows = [];
    $result = $this->container->get('database')->select('audit_chain_log', 'a')
      ->fields('a', ['entity_type', 'bundle', 'metadata'])
      ->condition('operation', McpClassificationResolver::DENIAL_CODE)
      ->orderBy('id')
      ->execute();
    foreach ($result as $record) {
      $rows[] = $logger->decodeMetadata((string) $record->metadata) + [
        'entity_type' => $record->entity_type,
        'bundle' => $record->bundle,
      ];
    }
    return $rows;
  }

  /**
   * Asserts a response is the structured classification refusal.
   */
  private function assertRefusal(?Response $response): void {
    $this->assertNotNull($response, 'A refusal response was set.');
    $this->assertSame(403, $response->getStatusCode());
    $document = json_decode((string) $response->getContent(), TRUE);
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $document['errors'][0]['code'] ?? NULL);
    $this->assertSame('403', $document['errors'][0]['status'] ?? NULL);
    $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
  }

  /**
   * The request seam refuses an over-ceiling bundle route for every method.
   */
  public function testRequestSeamRefusesOverCeilingResourceType(): void {
    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $this->setCeilings(['jsonapi' => 'internal']);

    foreach (['GET', 'POST', 'PATCH', 'DELETE'] as $method) {
      $event = $this->requestEvent('memo', $method);
      $subscriber->onRequest($event);
      $this->assertRefusal($event->getResponse());
    }
    // The individual route carries the same resource type.
    $event = $this->requestEvent('memo', 'GET', [], '/0f6d5e6a-3d1d-4c60-9f2b-1c1e6f8a9b0c');
    $subscriber->onRequest($event);
    $this->assertRefusal($event->getResponse());

    // An unlabelled bundle on the same entity type is untouched.
    $event = $this->requestEvent('article');
    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse());

    $rows = $this->evidenceRows();
    $this->assertNotEmpty($rows);
    $this->assertSame('jsonapi', $rows[0]['surface']);
    $this->assertSame('node', $rows[0]['entity_type']);
    $this->assertSame('memo', $rows[0]['bundle']);
    $this->assertSame('restricted', $rows[0]['classification']);
    $this->assertSame('internal', $rows[0]['ceiling']);
  }

  /**
   * At ceiling the request seam lets the same route through.
   */
  public function testRequestSeamPassesAtCeiling(): void {
    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $this->setCeilings(['jsonapi' => 'restricted']);
    $event = $this->requestEvent('memo');
    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse());
    $this->assertSame([], $this->evidenceRows());

    $this->setCeilings([]);
    $event = $this->requestEvent('memo');
    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse(), 'No ceiling: the mechanism is dark.');
  }

  /**
   * A declared ceiling below the profile's refuses; above changes nothing.
   */
  public function testRequestSeamHonoursDeclaredCeiling(): void {
    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $this->setCeilings(['jsonapi' => 'restricted']);
    $event = $this->requestEvent('memo', 'GET', [McpClassificationResolver::HEADER_DECLARED_CEILING => 'internal']);
    $subscriber->onRequest($event);
    $this->assertRefusal($event->getResponse());
    $this->assertSame('internal', $this->evidenceRows()[0]['declared_ceiling']);

    $this->setCeilings(['jsonapi' => 'internal']);
    $event = $this->requestEvent('memo', 'GET', [McpClassificationResolver::HEADER_DECLARED_CEILING => 'restricted']);
    $subscriber->onRequest($event);
    $this->assertRefusal($event->getResponse());

    $this->setCeilings(['jsonapi' => 'restricted']);
    $event = $this->requestEvent('memo', 'GET', [McpClassificationResolver::HEADER_DECLARED_CEILING => 'restricted']);
    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse());
  }

  /**
   * The response seam refuses a body carrying an over-ceiling type (§5.4).
   */
  public function testResponseSeamRefusesOverCeilingBody(): void {
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $this->setCeilings(['jsonapi' => 'internal']);

    // Primary data.
    $event = $this->responseEvent('/jsonapi/node/article', [
      'data' => [['type' => 'node--memo', 'id' => 'a', 'attributes' => ['title' => self::SENTINEL_VALUE]]],
    ]);
    $subscriber->onResponse($event);
    $this->assertRefusal($event->getResponse());

    // Included data.
    $event = $this->responseEvent('/jsonapi/node/article', [
      'data' => [['type' => 'node--article', 'id' => 'b']],
      'included' => [['type' => 'node--memo', 'id' => 'c', 'attributes' => ['title' => self::SENTINEL_VALUE]]],
    ]);
    $subscriber->onResponse($event);
    $this->assertRefusal($event->getResponse());

    // A single resource object.
    $event = $this->responseEvent('/jsonapi/node/memo/x', [
      'data' => ['type' => 'node--memo', 'id' => 'd'],
    ]);
    $subscriber->onResponse($event);
    $this->assertRefusal($event->getResponse());

    // A write echo: the created entity is egress too.
    $event = $this->responseEvent('/jsonapi/node/memo', [
      'data' => ['type' => 'node--memo', 'id' => 'e'],
    ], 'POST', 201);
    $subscriber->onResponse($event);
    $this->assertRefusal($event->getResponse());

    $rows = $this->evidenceRows();
    $this->assertNotEmpty($rows);
    foreach ($rows as $row) {
      $this->assertStringNotContainsString(self::SENTINEL_VALUE, (string) json_encode($row));
    }
  }

  /**
   * An at-ceiling body passes byte-identical; unlabelled bodies too.
   */
  public function testResponseSeamPassesAtCeilingByteIdentical(): void {
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $body = (string) json_encode([
      'data' => [['type' => 'node--memo', 'id' => 'a', 'attributes' => ['title' => 'x']]],
      'included' => [['type' => 'node--article', 'id' => 'b']],
    ]);

    $this->setCeilings(['jsonapi' => 'restricted']);
    $event = $this->responseEvent('/jsonapi/node/memo', $body);
    $subscriber->onResponse($event);
    $this->assertSame(200, $event->getResponse()->getStatusCode());
    $this->assertSame($body, $event->getResponse()->getContent());

    $this->setCeilings(['jsonapi' => 'internal']);
    $public = (string) json_encode(['data' => [['type' => 'node--article', 'id' => 'b']]]);
    $event = $this->responseEvent('/jsonapi/node/article', $public);
    $subscriber->onResponse($event);
    $this->assertSame($public, $event->getResponse()->getContent());
    $this->assertSame([], $this->evidenceRows());
  }

  /**
   * With a JSON:API ceiling in force, an undecodable body is refused.
   */
  public function testResponseSeamRefusesUndecodableBodyUnderCeiling(): void {
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $this->setCeilings(['jsonapi' => 'internal']);
    $event = $this->responseEvent('/jsonapi/node/article', '{not json');
    $subscriber->onResponse($event);
    $this->assertRefusal($event->getResponse());

    // Without a ceiling the same body is nobody's business.
    $this->setCeilings([]);
    $event = $this->responseEvent('/jsonapi/node/article', '{not json');
    $subscriber->onResponse($event);
    $this->assertSame('{not json', $event->getResponse()->getContent());
  }

  /**
   * Non-JSON:API bodies and errors are never re-typed.
   */
  public function testResponseSeamSkipsNonJsonApiAndErrorBodies(): void {
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $this->setCeilings(['jsonapi' => 'internal', 'graphql' => 'internal']);

    $graphql = '{"data":{"nodeMemos":[{"title":"x"}]}}';
    $event = $this->responseEvent('/graphql', $graphql, 'POST', 200, 'application/json');
    $subscriber->onResponse($event);
    $this->assertSame($graphql, $event->getResponse()->getContent(), 'GraphQL bodies carry no resource typing; entity/field access enforce there.');

    $error = (string) json_encode(['errors' => [['status' => '404']]]);
    $event = $this->responseEvent('/jsonapi/node/memo/x', $error, 'GET', 404);
    $subscriber->onResponse($event);
    $this->assertSame($error, $event->getResponse()->getContent());
  }

  /**
   * Ungoverned traffic is never touched by either seam.
   */
  public function testUngovernedTrafficUntouched(): void {
    $this->setCeilings(['jsonapi' => 'internal']);
    \Drupal::currentUser()->setAccount($this->createUser());

    $event = $this->requestEvent('memo');
    $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber')->onRequest($event);
    $this->assertNull($event->getResponse());

    $body = (string) json_encode(['data' => ['type' => 'node--memo', 'id' => 'a']]);
    $event = $this->responseEvent('/jsonapi/node/memo/a', $body);
    $this->container->get('mcp_sentinel.governed_response_subscriber')->onResponse($event);
    $this->assertSame($body, $event->getResponse()->getContent());
  }

}
