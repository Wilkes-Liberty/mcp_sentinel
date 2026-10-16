<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_graphql_persisted_test\Plugin\GraphQL\PersistedQuery;

use Drupal\graphql\PersistedQuery\PersistedQueryPluginBase;
use GraphQL\Server\OperationParams;

/**
 * Resolves a single persisted queryId to { __typename }.
 *
 * @PersistedQuery(
 *   id = "mcp_sentinel_graphql_test_typename",
 *   label = "MCP Sentinel persisted typename",
 *   description = "Test-only persisted queryId for functional coverage."
 * )
 */
final class TypenamePersistedQuery extends PersistedQueryPluginBase {

  /**
   * {@inheritdoc}
   */
  public function getQuery($id, OperationParams $operation): ?string {
    return $id === 'persisted-typename' ? '{ __typename }' : NULL;
  }

}
