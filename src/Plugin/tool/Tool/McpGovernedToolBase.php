<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Enforces the non-bypassable readiness gate for Sentinel Tool plugins.
 */
abstract class McpGovernedToolBase extends ToolBase {

  /**
   * Source-governance readiness service.
   */
  protected McpGovernanceReadiness $governanceReadiness;

  /**
   * IP allowlist and policy access checker.
   */
  protected McpAccessChecker $governanceAccessChecker;

  /**
   * Exact OAuth scope derived from this plugin's declaration.
   */
  protected string $governanceRequiredScope;

  /**
   * The request stack, stamped with the Tool surface at the access gate.
   *
   * Nullable so a Tool constructed outside the container (unit tests, or a
   * subclass that overrides create()) still works; without it the surface is
   * simply not stamped and the classification resolver falls back to its
   * strictest-ceiling rule.
   */
  protected ?RequestStack $governanceRequestStack = NULL;

  /**
   * DLP scanner applied to successful Tool context.
   */
  protected ?McpDlp $governanceDlp = NULL;

  /**
   * Classification resolver used to tighten Tool egress (NULL in unit tests).
   */
  protected ?McpClassificationResolver $governanceClassification = NULL;

  /**
   * Policy resolver used to read the Tool ceiling (NULL in unit tests).
   */
  protected ?McpPolicyResolver $governancePolicyResolver = NULL;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->governanceReadiness = $container->get('mcp_sentinel.governance_readiness');
    $instance->governanceAccessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->governanceRequiredScope = McpToolScopeResolver::resolveDefinition($plugin_definition);
    $instance->governanceRequestStack = $container->get('request_stack');
    $instance->governanceDlp = $container->has('mcp_sentinel.dlp')
      ? $container->get('mcp_sentinel.dlp')
      : NULL;
    $instance->governanceClassification = $container->has('mcp_sentinel.classification')
      ? $container->get('mcp_sentinel.classification')
      : NULL;
    $instance->governancePolicyResolver = $container->has('mcp_sentinel.policy_resolver')
      ? $container->get('mcp_sentinel.policy_resolver')
      : NULL;
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function execute(): static {
    parent::execute();
    $this->applyDlpToResult();
    return $this;
  }

  /**
   * Scans successful Tool context through DLP (tighten-only).
   *
   * Failure results are left alone — they carry no entity values. Unit
   * tests that construct a Tool without the container skip this pass.
   */
  private function applyDlpToResult(): void {
    if ($this->governanceDlp === NULL || $this->result === NULL || !$this->result->isSuccess()) {
      return;
    }
    $ceiling = NULL;
    if ($this->governanceClassification !== NULL && $this->governancePolicyResolver !== NULL) {
      $profile = $this->governancePolicyResolver->resolve();
      if ($profile !== NULL) {
        $ceiling = $this->governanceClassification->effectiveCeiling($profile, McpGovernedSurface::Tool);
      }
    }
    $scanned = $this->governanceDlp->scanTree(
      $this->result->getContextValues(),
      $ceiling,
      $this->governanceClassification,
    );
    if (!is_array($scanned)) {
      return;
    }
    $this->result = ExecutableResult::success($this->result->getMessage(), $scanned);
    $provided = $this->getOutputDefinitions();
    if ($provided === []) {
      return;
    }
    $this->outputs = [];
    foreach ($scanned as $name => $value) {
      if (isset($provided[$name])) {
        $this->setOutputValue($name, $value);
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  final protected function checkAccess(
    array $values,
    AccountInterface $account,
    bool $return_as_object = FALSE,
  ): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission(
      $account,
      'access mcp sentinel context',
    );
    if (!$access->isAllowed()) {
      return $return_as_object ? $access : FALSE;
    }

    // Name the surface on the request (d.o #3616540 part 2): Tool execution
    // has no path of its own, and the bridge executes the Tool under this same
    // request after access(), so entity reads inside doExecute() resolve the
    // Tool egress ceiling.
    $this->governanceRequestStack?->getCurrentRequest()?->attributes->set(
      McpClassificationResolver::REQUEST_ATTRIBUTE_SURFACE,
      McpGovernedSurface::Tool->value,
    );

    $readiness = $this->governanceReadiness->evaluate(
      McpGovernedSurface::Tool,
      $account,
      $this->governanceRequiredScope,
    );
    if (!$readiness->isReady()) {
      $reason = $readiness->reason()->value;
      $denied = AccessResult::forbidden(
        'MCP Sentinel source governance is not ready: ' . $reason . '.',
      )->addCacheableDependency($readiness);
      return $return_as_object ? $denied : FALSE;
    }

    $profile = $readiness->profile();
    if ($profile === NULL || !$this->governanceAccessChecker->isClientIpAllowed($profile)) {
      $denied = AccessResult::forbidden(
        'Source IP not permitted by MCP Sentinel policy.',
      )->setCacheMaxAge(0);
      return $return_as_object ? $denied : FALSE;
    }

    $subclassAccess = $this->checkGovernedAccess($values, $account);
    $access->addCacheableDependency($readiness);
    $access = $access->andIf($subclassAccess);
    return $return_as_object ? $access : $access->isAllowed();
  }

  /**
   * Applies optional Tool-specific access after the common governance gates.
   *
   * Subclasses may narrow the decision but cannot bypass permission,
   * readiness, or IP policy because the public access seam above is final.
   */
  protected function checkGovernedAccess(
    array $values,
    AccountInterface $account,
  ): AccessResultInterface {
    return AccessResult::allowed();
  }

}
