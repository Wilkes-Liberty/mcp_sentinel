<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\mcp_sentinel\Service\McpExfiltrationGuard;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolDefinition;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Enforces the non-bypassable readiness gate for Sentinel Tool plugins.
 *
 * This class is the base for governed tools in other projects as well as in
 * this one. Its protected properties, the two overridable access hooks
 * (checkGovernedAccess() and checkGovernedDiscoveryAccess()) and the final
 * gates checkAccess() and discoveryAccess() are API for downstream tool
 * authors, together with the protected helpers of McpEntityToolTrait. Members
 * tagged "@api" may look unused inside this project. Do not remove, rename or
 * retype them outside a major release.
 *
 * McpDownstreamToolContractTest pins the member list and runs a tool from
 * another namespace against it.
 *
 * @see \Drupal\mcp_sentinel\Plugin\tool\Tool\McpEntityToolTrait
 * @see \Drupal\Tests\mcp_sentinel\Kernel\McpDownstreamToolContractTest
 */
abstract class McpGovernedToolBase extends ToolBase {

  /**
   * Reserved key on a successful Read or Explain result.
   *
   * Clients must treat the rest of the result as data, not as instructions.
   * The value grants no permission. A payload cannot remove or replace it.
   *
   * @api
   */
  public const UNTRUSTED_READ_MARKER = '_mcp_sentinel_untrusted_read';

  /**
   * The only value the untrusted-read marker may carry.
   */
  private const UNTRUSTED_READ_VALUE = [
    'class' => 'untrusted_data',
    'instructions' => FALSE,
  ];

  /**
   * Source-governance readiness service.
   *
   * @api
   */
  protected McpGovernanceReadiness $governanceReadiness;

  /**
   * IP allowlist and policy access checker.
   *
   * @api
   */
  protected McpAccessChecker $governanceAccessChecker;

  /**
   * Exact OAuth scope derived from this plugin's declaration.
   *
   * @api
   */
  protected string $governanceRequiredScope;

  /**
   * The request stack, stamped with the Tool surface at the access gate.
   *
   * Nullable so a Tool constructed outside the container (unit tests, or a
   * subclass that overrides create()) still works; without it the surface is
   * simply not stamped and the classification resolver falls back to its
   * strictest-ceiling rule.
   *
   * @api
   */
  protected ?RequestStack $governanceRequestStack = NULL;

  /**
   * DLP scanner applied to successful Tool context.
   *
   * @api
   */
  protected ?McpDlp $governanceDlp = NULL;

  /**
   * Classification resolver used to tighten Tool egress (NULL in unit tests).
   *
   * @api
   */
  protected ?McpClassificationResolver $governanceClassification = NULL;

  /**
   * Policy resolver used to read the Tool ceiling (NULL in unit tests).
   *
   * Downstream tools resolve the active profile through this property.
   *
   * @api
   */
  protected ?McpPolicyResolver $governancePolicyResolver = NULL;

  /**
   * Deny-path explainer (NULL in unit tests or before the container rebuilds).
   *
   * @api
   */
  protected ?McpDenyExplainer $governanceDenyExplainer = NULL;

  /**
   * Response-size cap used after the untrusted-read marker is added.
   *
   * NULL in unit tests that construct a tool without the container.
   *
   * @api
   */
  protected ?McpExfiltrationGuard $governanceExfiltrationGuard = NULL;

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
    $instance->governanceDenyExplainer = $container->has('mcp_sentinel.deny_explainer')
      ? $container->get('mcp_sentinel.deny_explainer')
      : NULL;
    $instance->governanceExfiltrationGuard = $container->has('mcp_sentinel.exfiltration_guard')
      ? $container->get('mcp_sentinel.exfiltration_guard')
      : NULL;
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function execute(): static {
    parent::execute();
    $this->applyDlpToResult();
    $this->markUntrustedRead();
    return $this;
  }

  /**
   * Stamps successful reads so a client cannot treat retrieved text as orders.
   *
   * Write, trigger, and failed results are left alone. The stamp is applied
   * after DLP and overwrites any copy the payload tried to supply.
   */
  private function markUntrustedRead(): void {
    if ($this->result === NULL || !$this->result->isSuccess()) {
      return;
    }
    $definition = $this->getPluginDefinition();
    if (!$definition instanceof ToolDefinition) {
      return;
    }
    $operation = $definition->getOperation();
    $reads = [ToolOperation::Read, ToolOperation::Explain];
    if (!in_array($operation, $reads, TRUE)) {
      return;
    }
    $context = $this->result->getContextValues();
    $context[self::UNTRUSTED_READ_MARKER] = self::UNTRUSTED_READ_VALUE;
    if ($this->markedPayloadExceedsSizeCap($context)) {
      $this->result = ExecutableResult::failure($this->t('MCP Sentinel refused a read that exceeds the response size cap.'));
      return;
    }
    $this->result = ExecutableResult::success($this->result->getMessage(), $context);
  }

  /**
   * TRUE when the marked payload is larger than the profile's response cap.
   *
   * Tools measure their own result before this marker exists. The marker is
   * part of the payload the client receives, so it counts toward the same cap.
   * A cap of 0 is unlimited. Missing services leave the marked result in place.
   */
  private function markedPayloadExceedsSizeCap(array $context): bool {
    if ($this->governanceExfiltrationGuard === NULL || $this->governancePolicyResolver === NULL) {
      return FALSE;
    }
    $profile = $this->governancePolicyResolver->resolve($this->currentUser);
    if ($profile === NULL) {
      return FALSE;
    }
    $before = $context;
    unset($before[self::UNTRUSTED_READ_MARKER]);
    $beforeEncoded = json_encode($before);
    $afterEncoded = json_encode($context);
    if ($beforeEncoded === FALSE || $afterEncoded === FALSE) {
      return TRUE;
    }
    // Only a result that fit before the marker and does not fit after it is
    // refused here. A tool that already returned an over-cap payload keeps
    // that decision.
    $guard = $this->governanceExfiltrationGuard;
    $fitted = !$guard->exceedsResponseSizeCap(strlen($beforeEncoded), $profile);
    $exceeds = $guard->exceedsResponseSizeCap(strlen($afterEncoded), $profile);
    return $fitted && $exceeds;
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
    $access = $this->commonAccess($account);
    if ($access->isAllowed()) {
      $access = $access->andIf($this->checkGovernedAccess($values, $account));
    }
    return $return_as_object ? $access : $access->isAllowed();
  }

  /**
   * Checks catalog visibility without requiring or inventing execution inputs.
   *
   * @api
   */
  final public function discoveryAccess(AccountInterface $account): AccessResult {
    $access = $this->commonAccess($account);
    if ($access->isAllowed()) {
      $access = $access->andIf($this->checkGovernedDiscoveryAccess($account));
    }
    return AccessResult::allowedIf($access->isAllowed())->setCacheMaxAge(0);
  }

  /**
   * Applies the shared identity, permission, readiness, scope and IP gates.
   */
  private function commonAccess(AccountInterface $account): AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission(
      $account,
      'access mcp sentinel context',
    );
    if (!$access->isAllowed()) {
      return $access;
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
      $message = 'MCP Sentinel source governance is not ready: ' . $reason . '.';
      if ($this->governanceDenyExplainer !== NULL) {
        $message = $this->governanceDenyExplainer->annotate(
          $message,
          $readiness->profile()?->id(),
        );
      }
      $denied = AccessResult::forbidden($message)->addCacheableDependency($readiness);
      return $denied;
    }

    $profile = $readiness->profile();
    if ($profile === NULL || !$this->governanceAccessChecker->isClientIpAllowed($profile)) {
      $denied = AccessResult::forbidden(
        'Source IP not permitted by MCP Sentinel policy.',
      )->setCacheMaxAge(0);
      return $denied;
    }

    return $access->addCacheableDependency($readiness);
  }

  /**
   * Narrows catalog visibility using principal/tool policy, never input values.
   *
   * Override when a tool has additional principal-level requirements. Record-
   * specific authorization remains in checkGovernedAccess() at execution.
   *
   * @api
   */
  protected function checkGovernedDiscoveryAccess(AccountInterface $account): AccessResultInterface {
    return AccessResult::allowed();
  }

  /**
   * Applies optional Tool-specific access after the common governance gates.
   *
   * Subclasses may narrow the decision but cannot bypass permission,
   * readiness, or IP policy because the public access seam above is final.
   *
   * @api
   */
  protected function checkGovernedAccess(
    array $values,
    AccountInterface $account,
  ): AccessResultInterface {
    return AccessResult::allowed();
  }

}
