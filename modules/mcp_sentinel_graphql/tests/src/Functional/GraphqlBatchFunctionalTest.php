<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Functional;

use Drupal\graphql\Entity\Server;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Service\McpRoleFallbackGate;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\Entity\Role;
use GuzzleHttp\RequestOptions;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Http\Message\ResponseInterface;

/**
 * POSTs batched and persisted GraphQL through the live server.
 *
 * Skips when graphql / graphql_compose are not installed. The HTTP
 * seam refuses a governed /graphql request without a principal before
 * the executor runs, so a batched POST and a persisted queryId each
 * produce one denied_access row. Per-operation GraphQL errors are
 * covered by GraphqlModuleEntryPointTest.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_graphql
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_graphql')]
#[RunTestsInSeparateProcesses]
final class GraphqlBatchFunctionalTest extends BrowserTestBase {

  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain',
    'mcp_sentinel',
    'mcp_sentinel_graphql',
    'node',
    'serialization',
    'jsonapi',
    'typed_data',
    'graphql',
    'graphql_compose',
    'mcp_sentinel_graphql_persisted_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    if (!class_exists(Server::class)) {
      $this->markTestSkipped('The graphql module is not available.');
    }
    parent::setUp();
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    $this->enableRoleFallbackGovernance();
    // Draft tests need the fixture principal. This class must not: the
    // HTTP gate is the denial without iss/sub/azp, same as
    // dropStampedPrincipal() in the kernel suite.
    $this->writeSettings([
      'settings' => [
        McpRoleFallbackGate::TEST_PRINCIPAL_KEY => (object) [
          'value' => [],
          'required' => TRUE,
        ],
      ],
    ]);
    $this->configureDefaultProfile(TRUE, TRUE, [], 0, TRUE);
    $role = Role::load('mcp_api');
    $this->assertInstanceOf(Role::class, $role);
    $role->grantPermission('execute graphql_compose_server arbitrary graphql requests');
    $role->grantPermission('execute graphql_compose_server persisted graphql requests');
    $role->grantPermission('access content');
    $role->save();
    $server = Server::load('graphql_compose_server');
    $this->assertInstanceOf(Server::class, $server);
    $plugin = $this->container
      ->get('plugin.manager.graphql.persisted_query')
      ->createInstance('mcp_sentinel_graphql_test_typename');
    $server->addPersistedQueryInstance($plugin);
    $server->save();
  }

  /**
   * A batched POST to /graphql is refused once without a principal.
   */
  public function testBatchedGraphqlPostGatesOncePerOperation(): void {
    $account = $this->createGovernedAgentAccount();
    $this->drupalLogin($account);
    $before = $this->deniedAccessCount();
    $response = $this->postGraphql([
      ['query' => '{ __typename }'],
      ['query' => '{ __typename }'],
    ]);
    $this->assertGraphqlPrincipalDenied($response);
    $this->assertSame($before + 1, $this->deniedAccessCount());
  }

  /**
   * A persisted queryId POST to /graphql is refused once without a principal.
   */
  public function testPersistedQueryIdGatesOnce(): void {
    $account = $this->createGovernedAgentAccount();
    $this->drupalLogin($account);
    $before = $this->deniedAccessCount();
    $response = $this->postGraphql(['queryId' => 'persisted-typename']);
    $this->assertGraphqlPrincipalDenied($response);
    $this->assertSame($before + 1, $this->deniedAccessCount());
  }

  /**
   * Asserts the HTTP seam refused /graphql for a missing principal.
   */
  private function assertGraphqlPrincipalDenied(ResponseInterface $response): void {
    $body = (string) $response->getBody();
    $this->assertSame(403, $response->getStatusCode(), $body);
    $this->assertSame(
      McpDenyExplainer::CALLER_MESSAGE,
      json_decode($body, TRUE)['message'] ?? $body,
    );
    $this->assertStringNotContainsString('verified principal', $body);
    $this->assertStringNotContainsString('required_scope_missing', $body);
  }

  /**
   * POSTs JSON to /graphql with the Mink session, not a bare Guzzle client.
   *
   * The Mink Guzzle client does not send the login cookie. GraphQL
   * Compose's own browser tests attach getSessionCookies() for the same
   * reason.
   *
   * @param array<mixed> $json
   *   Batched operations or a single query / queryId document.
   */
  private function postGraphql(array $json): ResponseInterface {
    return $this->getHttpClient()->request(
      'POST',
      $this->buildUrl('/graphql', ['absolute' => TRUE]),
      [
        RequestOptions::HTTP_ERRORS => FALSE,
        RequestOptions::COOKIES => $this->getSessionCookies(),
        RequestOptions::HEADERS => [
          'Content-Type' => 'application/json',
          'Accept' => 'application/json',
        ],
        RequestOptions::JSON => $json,
      ],
    );
  }

  /**
   * Counts denied_access rows.
   */
  private function deniedAccessCount(): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

}
