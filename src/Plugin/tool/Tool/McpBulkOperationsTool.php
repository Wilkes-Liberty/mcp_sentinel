<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Event\McpDestructiveOpEvent;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpContentLock;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

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
final class McpBulkOperationsTool extends McpGovernedToolBase {

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
   * The Symfony event dispatcher.
   *
   * Used to dispatch the veto-capable McpDestructiveOpEvent before a
   * destructive operation. When no subscriber is registered (e.g. the approval
   * submodule is absent) the event is a no-op and the operation proceeds.
   */
  protected EventDispatcherInterface $eventDispatcher;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->contentLock = $container->get('mcp_sentinel.content_lock');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->eventDispatcher = $container->get('event_dispatcher');
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
    $results = ['succeeded' => [], 'failed' => [], 'queued' => []];

    // Resolve the governance profile once. An ungoverned account must be
    // rejected before any entity work — this is the most destructive tool.
    $profileForRateLimit = $this->policyResolver->resolve($this->currentUser);
    if ($profileForRateLimit === NULL) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied: no governance profile applies to this account.'));
    }
    // Rate-limit check: a throttled agent is blocked before touching the entity
    // loop.
    if ($rateLimited = $this->checkRateLimit($profileForRateLimit, 'mcp_sentinel_bulk_operations')) {
      return $rateLimited;
    }

    foreach ($ids as $id) {
      $entity = $storage->load($id);
      if ($entity === NULL) {
        $results['failed'][$id] = (string) $this->t('not found');
        continue;
      }
      $profile = $profileForRateLimit;
      $policyResult = $this->accessChecker->checkEntityAccess($entity, $entity_op, $profile);
      if ($reason = $this->denyReason($policyResult)) {
        $this->logDeniedAccess('mcp_sentinel_bulk_operations', $entity_type, $id, $operation, $reason);
        $results['failed'][$id] = $reason;
        continue;
      }
      if (!$entity->access($entity_op, $this->currentUser)) {
        $this->logDeniedAccess('mcp_sentinel_bulk_operations', $entity_type, $id, $operation, 'access denied');
        $results['failed'][$id] = (string) $this->t('access denied');
        continue;
      }
      // Owner-aware, and applied to delete too (d.o #3616541): a bulk delete
      // must not remove content another principal has locked.
      if ($this->contentLock->conflictsForActor($entity_type, $id)) {
        $results['failed'][$id] = (string) $this->t('content locked');
        continue;
      }

      // For destructive operations, give optional subscribers (e.g. the
      // mcp_sentinel_approval submodule) a chance to veto execution — for
      // instance to queue the operation for human approval. When nothing
      // subscribes, the event is never vetoed and the delete proceeds as
      // before, keeping the base module fully decoupled.
      if ($operation === 'delete') {
        $event = new McpDestructiveOpEvent($entity, $operation, $this->currentUser);
        try {
          $this->eventDispatcher->dispatch($event, McpDestructiveOpEvent::NAME);
        }
        catch (\Throwable $e) {
          // Fail closed: a dispatcher-level error must never let a gated delete
          // slip through. Treat it as a veto and report the id as queued (not
          // failed), keeping behaviour consistent with an explicit veto.
          $results['queued'][$id] = (string) $this->t('queued for approval (dispatcher error: @msg)', ['@msg' => $e->getMessage()]);
          continue;
        }
        if ($event->isVetoed()) {
          $results['queued'][$id] = (string) $event->getVetoReason();
          continue;
        }
      }

      try {
        $this->performOperation($entity, $operation);
        $results['succeeded'][] = $id;
      }
      catch (\Exception $e) {
        $results['failed'][$id] = $e->getMessage();
      }
    }

    // Apply exfiltration result-count cap to the succeeded list before
    // returning. 'failed' and 'queued' are always fully returned.
    $results = $this->applyResultCap($results, $profileForRateLimit);

    // Apply response-size cap: because all writes have already been performed,
    // returning failure here would misreport a completed batch — an agent
    // seeing "failure" may retry and toggle publish/unpublish state again.
    // Instead, truncate the reported lists to fit under the cap and signal
    // truncation via '_size_truncated' / '_size_cap' keys. The operation WAS
    // performed.
    $results = $this->truncateBulkResultsToSizeCap($results, $profileForRateLimit);

    $truncationNote = '';
    if (!empty($results['_result_truncated'])) {
      $truncationNote .= ' (result list truncated to cap of ' . $results['_result_cap'] . ')';
    }
    if (!empty($results['_size_truncated'])) {
      $truncationNote .= ' (response truncated to size cap of ' . $results['_size_cap'] . ' bytes)';
    }

    return ExecutableResult::success(
      $this->t('@op complete: @ok succeeded, @fail failed, @queued queued for approval.@trunc', [
        '@op' => $operation,
        '@ok' => count($results['succeeded']),
        '@fail' => count($results['failed']),
        '@queued' => count($results['queued']),
        '@trunc' => $truncationNote,
      ]),
      $results,
    );
  }

  /**
   * Performs a single publish/unpublish/delete operation.
   *
   * Publish and unpublish require the entity to implement
   * EntityPublishedInterface; entity types without publishing support throw,
   * surfacing as a per-ID failure rather than aborting the batch.
   *
   * @param object $entity
   *   The loaded entity to act on.
   * @param string $operation
   *   One of 'publish', 'unpublish', or 'delete'.
   *
   * @throws \RuntimeException
   *   When a publish/unpublish is requested on a non-publishable entity type.
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

}
