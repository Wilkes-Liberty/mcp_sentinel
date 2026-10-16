<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Functional;

use Drupal\graphql\Entity\Server;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\Entity\Role;
use GuzzleHttp\RequestOptions;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * POSTs batched and persisted GraphQL through the live server.
 *
 * Skips when graphql / graphql_compose are not installed. Proves the
 * GraphQL module fires one operation gate per batched query and for
 * a persisted queryId.
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
    $this->configureDefaultProfile(TRUE, TRUE, [], 0, TRUE);
    $role = Role::load('mcp_api');
    $this->assertInstanceOf(Role::class, $role);
    $role->grantPermission('execute graphql_compose_server arbitrary graphql requests');
    $role->grantPermission('access content');
    $role->save();
    $server = Server::load('graphql_compose_server');
    if ($server instanceof Server) {
      $plugin = $this->container
        ->get('plugin.manager.graphql.persisted_query')
        ->createInstance('mcp_sentinel_graphql_test_typename');
      $server->addPersistedQueryInstance($plugin);
      $server->save();
    }
  }

  /**
   * A batched POST to /graphql denies each operation without a principal.
   */
  public function testBatchedGraphqlPostGatesOncePerOperation(): void {
    $account = $this->createGovernedAgentAccount();
    $this->drupalLogin($account);
    $before = $this->deniedAccessCount();
    $response = $this->getHttpClient()->request(
      'POST',
      $this->buildUrl('/graphql', ['absolute' => TRUE]),
      [
        RequestOptions::HTTP_ERRORS => FALSE,
        RequestOptions::HEADERS => ['Content-Type' => 'application/json'],
        RequestOptions::JSON => [
          ['query' => '{ __typename }'],
          ['query' => '{ __typename }'],
        ],
      ],
    );
    $this->assertSame(200, $response->getStatusCode());
    $payload = json_decode((string) $response->getBody(), TRUE);
    $this->assertIsArray($payload);
    $this->assertCount(2, $payload);
    $this->assertArrayHasKey('errors', $payload[0]);
    $this->assertArrayHasKey('errors', $payload[1]);
    $this->assertSame($before + 2, $this->deniedAccessCount());
  }

  /**
   * A persisted queryId POST to /graphql still gates once.
   */
  public function testPersistedQueryIdGatesOnce(): void {
    $account = $this->createGovernedAgentAccount();
    $this->drupalLogin($account);
    $before = $this->deniedAccessCount();
    $response = $this->getHttpClient()->request(
      'POST',
      $this->buildUrl('/graphql', ['absolute' => TRUE]),
      [
        RequestOptions::HTTP_ERRORS => FALSE,
        RequestOptions::HEADERS => ['Content-Type' => 'application/json'],
        RequestOptions::JSON => ['queryId' => 'persisted-typename'],
      ],
    );
    $this->assertSame(200, $response->getStatusCode());
    $payload = json_decode((string) $response->getBody(), TRUE);
    $this->assertIsArray($payload);
    $this->assertArrayHasKey('errors', $payload);
    $this->assertSame($before + 1, $this->deniedAccessCount());
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
