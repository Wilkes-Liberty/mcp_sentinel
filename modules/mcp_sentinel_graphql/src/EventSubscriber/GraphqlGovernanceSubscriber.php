<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_graphql\EventSubscriber;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigCrudEvent;
use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\graphql\Event\OperationEvent;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use GraphQL\Error\Error;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;

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
   * Request attribute naming the GraphQL operation type (query/mutation).
   *
   * Field resolvers read this so a mutation write-echo is not logged as
   * entity_read (#3616612).
   */
  public const OPERATION_TYPE_ATTRIBUTE = 'mcp_sentinel.graphql_operation_type';

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
   * @param \Drupal\mcp_sentinel\Service\McpAccessChecker|null $accessChecker
   *   Live access checker (d.o #3617702). Nullable for the deploy window
   *   in which the cached container still passes four arguments.
   * @param \Drupal\Core\Cache\CacheBackendInterface|null $graphqlResultsCache
   *   GraphQL operation-result cache. Nullable for the deploy window in
   *   which the cached container still passes five arguments.
   * @param \Symfony\Component\HttpFoundation\RequestStack|null $requestStack
   *   The request stack. Nullable for the deploy window in which the
   *   cached container still passes six arguments.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher|null $principalDispatcher
   *   Principal and tenant gate. Nullable only for a cached container that
   *   predates it; a missing dispatcher fails closed on a governed operation.
   * @param \Drupal\mcp_sentinel\Service\McpDenyExplainer|null $denyExplainer
   *   Operator explainer. Nullable for a cached container that predates it.
   */
  public function __construct(
    private readonly McpAuditLogger $auditLogger,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly McpGovernanceReadiness $readiness,
    private readonly AccountProxyInterface $currentUser,
    private readonly ?McpAccessChecker $accessChecker = NULL,
    private readonly ?CacheBackendInterface $graphqlResultsCache = NULL,
    private readonly ?RequestStack $requestStack = NULL,
    private readonly ?McpPrincipalContextDispatcher $principalDispatcher = NULL,
    private readonly ?McpDenyExplainer $denyExplainer = NULL,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Gate on both the pre-execution event and the cache-hit event, so a
    // result cached under a more permissive policy cannot later be served to
    // an MCP client the current policy would block. Evict stale results when
    // Log reads is turned on so field resolvers run again.
    return [
      OperationEvent::GRAPHQL_OPERATION_BEFORE => 'onOperation',
      OperationEvent::GRAPHQL_OPERATION_CACHE_HIT => 'onOperation',
      ConfigEvents::SAVE => 'onSettingsSave',
    ];
  }

  /**
   * Whether Paladin or sealed-token claims are on the current request.
   */
  private function requestHasGovernedToken(): bool {
    $request = $this->requestStack?->getCurrentRequest();
    return $request !== NULL
      && ($request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)
        || $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE));
  }

  /**
   * Refuses an operation that has no verified principal, tenant, or scope.
   *
   * @param list<string> $requiredScopes
   *   Any-of OAuth scopes the sealed token must carry. Empty for
   *   subscriptions and other ungated operation types.
   *
   * @throws \GraphQL\Error\Error
   *   When the principal gate refuses the operation.
   */
  private function requirePrincipal(array $requiredScopes = []): void {
    if ($this->principalDispatcher === NULL) {
      throw new Error(
        $this->denyExplainer?->refuse('missing_principal')
          ?? McpDenyExplainer::CALLER_MESSAGE,
      );
    }
    try {
      // Sealed or deny-only audit context; never a live request rebuild.
      $this->principalDispatcher->assertDispatchAllowed(
        [],
        'graphql',
        [],
        [],
        $requiredScopes,
      );
    }
    catch (McpPrincipalContextDeniedException) {
      throw new Error(McpDenyExplainer::CALLER_MESSAGE);
    }
  }

  /**
   * Evicts cached GraphQL results when read audit is newly enabled.
   *
   * The executor reads cache.graphql.results before mergeCacheMaxAge(0) can
   * matter. Entries written while Log reads was off stay valid until their
   * entity tags invalidate, so a cache hit would skip field resolvers and
   * leave entity_read dark (#3616612).
   *
   * @param \Drupal\Core\Config\ConfigCrudEvent $event
   *   The config CRUD event.
   */
  public function onSettingsSave(ConfigCrudEvent $event): void {
    if ($this->graphqlResultsCache === NULL) {
      return;
    }
    $config = $event->getConfig();
    if ($config->getName() !== 'mcp_sentinel.settings') {
      return;
    }
    if (!$config->get('audit_enabled') || !$config->get('audit_log_reads')) {
      return;
    }
    if (!$event->isChanged('audit_log_reads')
      && !$event->isChanged('audit_enabled')) {
      return;
    }
    $this->graphqlResultsCache->deleteAll();
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
    // Stamp before readiness returns so field resolvers can skip write echoes.
    $this->requestStack?->getCurrentRequest()?->attributes->set(
      self::OPERATION_TYPE_ATTRIBUTE,
      $type,
    );
    $operation_name = $context->getOperation()->operationName ?? NULL;
    $is_mutation = $type === 'mutation';
    $readiness = $this->readiness->evaluate(
      McpGovernedSurface::Graphql,
      $this->currentUser,
      $is_mutation ? 'mcp_write' : 'mcp_read',
    );
    $requiredScopes = [];
    if ($is_mutation) {
      $requiredScopes = ['mcp_write'];
    }
    elseif ($type === 'query') {
      $requiredScopes = ['mcp_read'];
    }
    // Paladin or sealed-token claims fail closed even when this
    // operation is not applicable (undesignated client).
    if ($this->requestHasGovernedToken()
      || ($readiness->isApplicable() && $readiness->isReady())) {
      $this->requirePrincipal($requiredScopes);
    }
    if (!$readiness->isApplicable()) {
      return;
    }
    if (!$readiness->isReady()) {
      throw new Error(
        $this->denyExplainer?->refuse($readiness->reason()->value)
          ?? McpDenyExplainer::CALLER_MESSAGE,
      );
    }
    $profile = $readiness->profile();
    if ($profile === NULL) {
      throw new Error(
        $this->denyExplainer?->refuse('active_profile_missing')
          ?? McpDenyExplainer::CALLER_MESSAGE,
      );
    }

    $config = $this->configFactory->get('mcp_sentinel.settings');

    // Audit the attempt first, so blocked operations are still recorded.
    if ($config->get('audit_enabled') && ($is_mutation || $config->get('audit_log_reads'))) {
      $this->auditLogger->log($is_mutation ? 'graphql_mutation' : 'graphql_query', [
        'operation_type' => $type,
        'operation_name' => $operation_name,
      ]);
    }

    // entity_read is written only while GraphQL Compose field resolvers run.
    // An operation cache hit never re-runs that hook, so a repeat collection
    // read after the look-back window would leave no rows and bulk_read
    // would go dark (#3616612). JSON:API still sees cached documents because
    // it parses the response body; GraphQL has no equivalent type/id document.
    // Disable the operation cache so field resolvers and entity_read run
    // on every governed query when read audit is on. Existing entries are
    // evicted in onSettingsSave() when Log reads is turned on.
    if ($type === 'query'
      && $config->get('audit_enabled')
      && $config->get('audit_log_reads')) {
      $context->mergeCacheMaxAge(0);
    }

    // Mutation gate.
    if ($is_mutation) {
      if (!$profile->allowsWrite() || !$profile->allowsGraphqlMutations()) {
        throw new Error(
          $this->denyExplainer?->refuse('allow_write')
            ?? McpDenyExplainer::CALLER_MESSAGE,
        );
      }
      $this->refuseIfBundleDenies('update');
      return;
    }

    // Read gate (queries only; leave subscriptions/other types untouched).
    if ($type === 'query' && !$profile->allowsRead()) {
      throw new Error(
        $this->denyExplainer?->refuse('allow_read')
          ?? McpDenyExplainer::CALLER_MESSAGE,
      );
    }
    if ($type === 'query') {
      $this->refuseIfBundleDenies('view');
    }
  }

  /**
   * Throws when the attested portable-policy floor refuses this operation.
   *
   * @throws \GraphQL\Error\Error
   *   When the active bundle or emergency deny refuses.
   */
  private function refuseIfBundleDenies(string $operation): void {
    if ($this->accessChecker === NULL) {
      return;
    }
    if ($this->accessChecker->checkBundleFloor($operation, AccessResult::neutral())->isForbidden()) {
      throw new Error(
        $this->denyExplainer?->refuse(McpAccessChecker::BUNDLE_DENIAL_CODE)
          ?? McpDenyExplainer::CALLER_MESSAGE,
      );
    }
  }

}
