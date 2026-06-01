<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_graphql\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\graphql\Entity\ServerInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use GraphQL\Utils\SchemaPrinter;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Returns the GraphQL schema (SDL) for a configured GraphQL server.
 *
 * Lets an agent discover the available GraphQL types, queries, and mutations
 * before issuing operations against the /graphql endpoint.
 */
#[Tool(
  id: 'mcp_sentinel_graphql_schema',
  label: new TranslatableMarkup('Get GraphQL schema'),
  description: new TranslatableMarkup('Returns the GraphQL schema as SDL for a configured GraphQL server, plus its endpoint path. Call this to discover available queries, mutations, and types before issuing GraphQL operations.'),
  operation: ToolOperation::Explain,
  input_definitions: [
    'server_id' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Server ID'),
      description: new TranslatableMarkup('The GraphQL server config ID. Defaults to the GraphQL Compose server (or the first configured server).'),
      required: FALSE,
    ),
  ],
)]
final class McpGraphqlSchemaTool extends ToolBase {

  /**
   * The entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $storage = $this->entityTypeManager->getStorage('graphql_server');

    if (!empty($values['server_id'])) {
      $server = $storage->load($values['server_id']);
    }
    else {
      $servers = $storage->loadMultiple();
      $server = $servers['graphql_compose_server'] ?? (reset($servers) ?: NULL);
    }

    if (!$server instanceof ServerInterface) {
      return ExecutableResult::failure($this->t('No GraphQL server is configured.'));
    }

    try {
      $schema = $server->configuration()->getSchema();
      $sdl = SchemaPrinter::doPrint($schema);
    }
    catch (\Throwable $e) {
      return ExecutableResult::failure(
        $this->t('Failed to print GraphQL schema: @message', ['@message' => $e->getMessage()]),
      );
    }

    return ExecutableResult::success(
      $this->t('GraphQL schema retrieved for server @id.', ['@id' => $server->id()]),
      [
        'server_id' => $server->id(),
        'endpoint' => $server->get('endpoint'),
        'sdl' => $sdl,
      ],
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(array $values, AccountInterface $account, bool $return_as_object = FALSE): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission($account, 'access mcp sentinel context');
    return $return_as_object ? $access : $access->isAllowed();
  }

}
