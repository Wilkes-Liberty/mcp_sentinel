<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpContentLock;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Bulk publish, unpublish, or delete entities under MCP Sentinel policy.
 *
 * Requires an explicit confirm flag. Each entity is individually checked
 * against McpAccessChecker, core access, and content locks; failures are
 * reported per-ID rather than aborting the batch.
 */
#[Tool(
  id: 'mcp_sentinel_bulk_operations',
  label: new TranslatableMarkup('Bulk publish/unpublish/delete'),
  description: new TranslatableMarkup('Performs a bulk publish, unpublish, or delete over a list of entity IDs. Requires confirm=true. Each item is policy-checked individually and results are reported per ID.'),
  operation: ToolOperation::Write,
  destructive: TRUE,
  input_definitions: [
    'operation' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Operation'),
      description: new TranslatableMarkup('One of: publish, unpublish, delete.'),
      required: TRUE,
      constraints: ['AllowedValues' => ['choices' => ['publish', 'unpublish', 'delete']]],
    ),
    'entity_type' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Entity type'),
      description: new TranslatableMarkup('Entity type ID. Defaults to node.'),
      required: FALSE,
      default_value: 'node',
    ),
    'ids' => new InputDefinition(
      data_type: 'list',
      label: new TranslatableMarkup('Entity IDs'),
      description: new TranslatableMarkup('List of entity IDs to operate on.'),
      required: TRUE,
    ),
    'confirm' => new InputDefinition(
      data_type: 'boolean',
      label: new TranslatableMarkup('Confirm'),
      description: new TranslatableMarkup('Must be true to execute the bulk operation.'),
      required: TRUE,
    ),
  ],
)]
final class McpBulkOperationsTool extends ToolBase {

  use McpEntityToolTrait;

  /**
   * The entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The MCP Sentinel access checker.
   */
  protected McpAccessChecker $accessChecker;

  /**
   * The MCP Sentinel content lock service.
   */
  protected McpContentLock $contentLock;

  /**
   * The MCP Sentinel policy resolver.
   */
  protected McpPolicyResolver $policyResolver;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->contentLock = $container->get('mcp_sentinel.content_lock');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    if (empty($values['confirm'])) {
      return ExecutableResult::failure($this->t('Refusing to run a bulk operation without confirm=true.'));
    }
    $operation = $values['operation'] ?? '';
    $entity_type = $values['entity_type'] ?? 'node';
    $ids = array_filter(array_map('strval', (array) ($values['ids'] ?? [])));
    if (!$ids) {
      return ExecutableResult::failure($this->t('No entity IDs supplied.'));
    }
    if (!$this->entityTypeManager->hasDefinition($entity_type)) {
      return ExecutableResult::failure($this->t('Unknown entity type "@type".', ['@type' => $entity_type]));
    }

    $entity_op = $operation === 'delete' ? 'delete' : 'update';
    $storage = $this->entityTypeManager->getStorage($entity_type);
    $results = ['succeeded' => [], 'failed' => []];

    foreach ($ids as $id) {
      $entity = $storage->load($id);
      if ($entity === NULL) {
        $results['failed'][$id] = (string) $this->t('not found');
        continue;
      }
      $profile = $this->policyResolver->resolve($this->currentUser);
      if ($profile === NULL) {
        $results['failed'][$id] = (string) $this->t('MCP Sentinel denied: no governance profile applies to this account.');
        continue;
      }
      $policyResult = $this->accessChecker->checkEntityAccess($entity, $entity_op, $profile);
      if ($reason = $this->denyReason($policyResult)) {
        $results['failed'][$id] = $reason;
        continue;
      }
      if (!$entity->access($entity_op, $this->currentUser)) {
        $results['failed'][$id] = (string) $this->t('access denied');
        continue;
      }
      if ($entity_op !== 'delete' && $this->contentLock->isLocked($entity_type, $id)) {
        $results['failed'][$id] = (string) $this->t('content locked');
        continue;
      }

      try {
        $this->performOperation($entity, $operation);
        $results['succeeded'][] = $id;
      }
      catch (\Exception $e) {
        $results['failed'][$id] = $e->getMessage();
      }
    }

    return ExecutableResult::success(
      $this->t('@op complete: @ok succeeded, @fail failed.', [
        '@op' => $operation,
        '@ok' => count($results['succeeded']),
        '@fail' => count($results['failed']),
      ]),
      $results,
    );
  }

  /**
   * Performs a single publish/unpublish/delete operation.
   */
  private function performOperation(object $entity, string $operation): void {
    if ($operation === 'delete') {
      $entity->delete();
      return;
    }
    if (!$entity instanceof EntityPublishedInterface) {
      throw new \RuntimeException('Entity does not support publishing.');
    }
    $operation === 'publish' ? $entity->setPublished() : $entity->setUnpublished();
    $entity->save();
  }

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(array $values, AccountInterface $account, bool $return_as_object = FALSE): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission($account, 'access mcp sentinel context');
    return $return_as_object ? $access : $access->isAllowed();
  }

}
