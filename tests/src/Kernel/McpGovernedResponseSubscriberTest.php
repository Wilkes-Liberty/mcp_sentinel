<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Tests McpGovernedResponseSubscriber: the response byte budget (#3616540).
 *
 * The Tool bridge already measures serialized responses; JSON:API and GraphQL
 * responses were unmeasured, so a governed agent could exfiltrate any volume
 * in one request. The subscriber measures governed responses on those paths
 * and replaces an over-budget body with a bounded 413 refusal.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpGovernedResponseSubscriberTest extends KernelTestBase {

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
    $this->installSchema('system', ['sequences']);
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel', 'user']);
  }

  /**
   * Switches the current user to a governed account (role-fallback path).
   */
  private function switchToGovernedUser(): void {
    if (!\Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
  }

  /**
   * Builds a main-request ResponseEvent for a path and response body.
   */
  private function makeResponseEvent(string $path, string $body, string $method = 'GET'): ResponseEvent {
    $request = Request::create($path, $method);
    $response = new Response($body, 200, ['Content-Type' => 'application/vnd.api+json']);
    /** @var \Symfony\Component\HttpKernel\HttpKernelInterface $kernel */
    $kernel = $this->container->get('http_kernel');
    return new ResponseEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST, $response);
  }

  /**
   * Sets a small byte budget via the finite defaults.
   */
  private function setByteBudget(int $bytes): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['bytes' => $bytes])
      ->save();
  }

  /**
   * An over-budget governed JSON:API response is replaced with a 413 refusal.
   */
  public function testOverBudgetJsonApiResponseIsRefused(): void {
    $this->switchToGovernedUser();
    $this->setByteBudget(10);
    /** @var \Drupal\mcp_sentinel\EventSubscriber\McpGovernedResponseSubscriber $subscriber */
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $event = $this->makeResponseEvent('/jsonapi/node/article', str_repeat('x', 11));
    $subscriber->onResponse($event);
    $response = $event->getResponse();
    $this->assertSame(413, $response->getStatusCode());
    $this->assertStringContainsString('response_size_cap_exceeded', (string) $response->getContent());
    $this->assertStringNotContainsString('xxxxxxxxxxx', (string) $response->getContent(),
      'The over-budget payload must not leak through the refusal.');
  }

  /**
   * A governed response within the budget is untouched.
   */
  public function testWithinBudgetResponsePassesThrough(): void {
    $this->switchToGovernedUser();
    $this->setByteBudget(1024);
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $event = $this->makeResponseEvent('/jsonapi/node/article', '{"data":[]}');
    $subscriber->onResponse($event);
    $this->assertSame(200, $event->getResponse()->getStatusCode());
    $this->assertSame('{"data":[]}', $event->getResponse()->getContent());
  }

  /**
   * A governed GraphQL POST response is measured by the same budget.
   *
   * GraphQL reads travel over POST, so the subscriber must evaluate the
   * read scope there — deriving scope from the verb would classify every
   * query as a write and skip measurement for read-only principals.
   */
  public function testOverBudgetGraphqlResponseIsRefused(): void {
    $this->switchToGovernedUser();
    $this->setByteBudget(10);
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $event = $this->makeResponseEvent('/graphql', str_repeat('y', 11), 'POST');
    $subscriber->onResponse($event);
    $this->assertSame(413, $event->getResponse()->getStatusCode());
  }

  /**
   * Ungoverned traffic on the same paths is never measured or replaced.
   */
  public function testUngovernedResponseUntouched(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', FALSE)
      ->set('governed_roles', [])
      ->save();
    $this->setByteBudget(10);
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $body = str_repeat('z', 100);
    $event = $this->makeResponseEvent('/jsonapi/node/article', $body);
    $subscriber->onResponse($event);
    $this->assertSame(200, $event->getResponse()->getStatusCode());
    $this->assertSame($body, $event->getResponse()->getContent());
  }

  /**
   * Non-agent paths are ignored even for governed users.
   */
  public function testNonAgentPathIgnored(): void {
    $this->switchToGovernedUser();
    $this->setByteBudget(10);
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $body = str_repeat('w', 100);
    $event = $this->makeResponseEvent('/node/1', $body);
    $subscriber->onResponse($event);
    $this->assertSame(200, $event->getResponse()->getStatusCode());
    $this->assertSame($body, $event->getResponse()->getContent());
  }

  /**
   * A budget denial writes a bounded, non-sensitive evidence row.
   */
  public function testDenialWritesEvidenceRow(): void {
    $this->switchToGovernedUser();
    $this->setByteBudget(10);
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)->save();
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $event = $this->makeResponseEvent('/jsonapi/node/article', str_repeat('x', 11));
    $subscriber->onResponse($event);

    $rows = \Drupal::database()->select('audit_chain_log', 'a')
      ->fields('a')
      ->condition('operation', 'read_budget_denied')
      ->execute()
      ->fetchAll();
    $this->assertNotEmpty($rows, 'A read_budget_denied evidence row is written.');
    $serialized = serialize($rows);
    $this->assertStringNotContainsString('xxxxxxxxxxx', $serialized,
      'Evidence must not contain the over-budget payload.');
  }

}
