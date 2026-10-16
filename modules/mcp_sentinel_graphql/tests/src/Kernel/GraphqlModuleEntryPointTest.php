<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Kernel;

use Drupal\graphql\Entity\Server;
use Drupal\graphql\Plugin\PersistedQueryPluginInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedEntryPointTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use GraphQL\Server\OperationParams;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Batch and persisted GraphQL go through the real GraphQL executor.
 *
 * These tests prove graphql.operation.before fires once per operation
 * (including executeBatch and a persisted queryId). They skip when the
 * graphql / graphql_compose stack is not present.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_graphql
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_graphql')]
#[RunTestsInSeparateProcesses]
final class GraphqlModuleEntryPointTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedEntryPointTestTrait;
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
    'typed_data',
    'graphql',
    'graphql_compose',
    'mcp_sentinel_graphql',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    if (!class_exists(Server::class)) {
      $this->markTestSkipped('The graphql module is not available.');
    }
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('graphql_server');
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel', 'graphql', 'graphql_compose']);
    $this->switchToGovernedUser();
  }

  /**
   * ExecuteBatch fires one OperationEvent per operation.
   */
  public function testBatchedQueriesGateOncePerOperation(): void {
    $server = Server::load('graphql_compose_server');
    $this->assertInstanceOf(Server::class, $server);
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();
    $results = $server->executeBatch([
      OperationParams::create(['query' => '{ __typename }']),
      OperationParams::create(['query' => '{ __typename }']),
    ]);
    $this->assertCount(2, $results);
    foreach ($results as $result) {
      $this->assertNotEmpty($result->errors);
    }
    $this->assertSame($before + 2, $this->deniedAccessCount());
    $this->assertSame(
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      $this->lastDenialMetadata()['reason'],
    );
  }

  /**
   * A persisted queryId still gates once through the GraphQL executor.
   */
  public function testPersistedQueryGatesOnce(): void {
    $server = Server::load('graphql_compose_server');
    $this->assertInstanceOf(Server::class, $server);
    $plugin = $this->createMock(PersistedQueryPluginInterface::class);
    $plugin->method('getQuery')->willReturnCallback(
      static fn (string $id): ?string => $id === 'persisted-typename'
        ? '{ __typename }'
        : NULL,
    );
    $plugin->method('getPluginId')->willReturn('test_persisted');
    $plugin->method('getWeight')->willReturn(0);
    $server->addPersistedQueryInstance($plugin);
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();
    $result = $server->executeOperation(
      OperationParams::create(['queryId' => 'persisted-typename']),
    );
    $this->assertNotEmpty($result->errors);
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $this->assertSame(
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      $this->lastDenialMetadata()['reason'],
    );
  }

}
