<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_graphql\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\graphql\Event\OperationEvent;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use GraphQL\Error\Error;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Governs GraphQL operations originating from MCP clients.
 *
 * Runs before every GraphQL operation. For requests resolved as governed MCP
 * agents (via the policy resolver), it:
 *  - audits the attempted operation to the MCP Sentinel audit log, and
 *  - blocks the operation (by throwing a GraphQL error) when the active
 *    MCP Sentinel policy forbids it.
 *
 * Entity-level allow/deny and field access already flow through Drupal's
 * entity access system (hook_entity_access in mcp_sentinel.module), which
 * GraphQL Compose resolvers honour, so this subscriber only adds the
 * operation-level gates that have no entity-access equivalent.
 */
final class GraphqlGovernanceSubscriber implements EventSubscriberInterface {

  /**
   * Constructs a GraphqlGovernanceSubscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   * @param \Drupal\mcp_sentinel\Service\McpGovernanceReadiness $readiness
   *   Source-governance readiness evaluator.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   Current authenticated account.
   */
  public function __construct(
    private readonly McpAuditLogger $auditLogger,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly McpGovernanceReadiness $readiness,
    private readonly AccountProxyInterface $currentUser,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Gate on both the pre-execution event and the cache-hit event, so a
    // result cached under a more permissive policy cannot later be served to
    // an MCP client the current policy would block.
    return [
      OperationEvent::GRAPHQL_OPERATION_BEFORE => 'onOperation',
      OperationEvent::GRAPHQL_OPERATION_CACHE_HIT => 'onOperation',
    ];
  }

  /**
   * Audits and gates a GraphQL operation for MCP clients.
   *
   * @throws \GraphQL\Error\Error
   *   When the active MCP Sentinel policy forbids the operation.
   */
  public function onOperation(OperationEvent $event): void {
    $context = $event->getContext();
    $type = $context->getType();
    $operation_name = $context->getOperation()->operationName ?? NULL;
    $is_mutation = $type === 'mutation';
    $readiness = $this->readiness->evaluate(
      McpGovernedSurface::Graphql,
      $this->currentUser,
      $is_mutation ? 'mcp_write' : 'mcp_read',
    );
    if (!$readiness->isApplicable()) {
      return;
    }
    if (!$readiness->isReady()) {
      $reason = $readiness->reason();
      throw new Error(
        $reason?->isAuthorizationFailure()
          ? 'MCP access is denied.'
          : 'MCP source governance is not ready: '
            . $reason->value . '.',
      );
    }
    $profile = $readiness->profile();
    if ($profile === NULL) {
      throw new Error('MCP source governance is not ready: active_profile_missing.');
    }

    $config = $this->configFactory->get('mcp_sentinel.settings');

    // Audit the attempt first, so blocked operations are still recorded.
    if ($config->get('audit_enabled') && ($is_mutation || $config->get('audit_log_reads'))) {
      $this->auditLogger->log($is_mutation ? 'graphql_mutation' : 'graphql_query', [
        'operation_type' => $type,
        'operation_name' => $operation_name,
      ]);
    }

    // Mutation gate.
    if ($is_mutation) {
      if (!$profile->allowsWrite() || !$profile->allowsGraphqlMutations()) {
        throw new Error('GraphQL mutations are disabled by MCP Sentinel.');
      }
      return;
    }

    // Read gate (queries only; leave subscriptions/other types untouched).
    if ($type === 'query' && !$profile->allowsRead()) {
      throw new Error('GraphQL read access is disabled by MCP Sentinel.');
    }
  }

}
