<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpEntityToolTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\mcp_sentinel\Tool\ConfigScopeToolInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Drupal\user\Entity\User;

/**
 * Stands in for a governed tool that another project ships.
 *
 * MCP Sentinel's own tools do not call every protected helper it offers, so a
 * search of this project alone reports some of them as unused. Other projects
 * build tools on McpGovernedToolBase and McpEntityToolTrait and do call them.
 * This class lives outside the mcp_sentinel namespace and calls each one the
 * way a downstream tool would. Removing or renaming a helper makes the call
 * below an undefined method, which fails McpDownstreamToolContractTest.
 *
 * Add a helper here when you add one to the base class or the trait.
 */
#[Tool(
  id: 'mcp_sentinel_downstream_contract',
  label: new TranslatableMarkup('Downstream contract test'),
  description: new TranslatableMarkup('Calls one protected MCP Sentinel tool helper by name and reports what it returned.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'helper' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Helper'),
      description: new TranslatableMarkup('The protected helper to call.'),
      required: TRUE,
    ),
    'payload' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Payload'),
      description: new TranslatableMarkup('A serialized response body for the size-cap helpers.'),
      required: FALSE,
    ),
  ],
)]
final class DownstreamContractTool extends McpGovernedToolBase implements ConfigScopeToolInterface {

  use McpEntityToolTrait;

  /**
   * The permission this tool adds on top of the common Sentinel gates.
   */
  public const PERMISSION = 'use mcp sentinel downstream contract tool';

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedDiscoveryAccess(AccountInterface $account): AccessResultInterface {
    return $this->checkGovernedAccess([], $account);
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedAccess(array $values, AccountInterface $account): AccessResultInterface {
    return AccessResult::allowedIfHasPermission($account, self::PERMISSION)->setCacheMaxAge(0);
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    // ToolBase::execute() does not call access(), so a downstream tool
    // re-checks through the final gate it inherits.
    if (!$this->checkAccess($values, $this->currentUser)) {
      return ExecutableResult::failure($this->t('Downstream contract tool refused.'));
    }
    // Downstream tools read these inherited properties directly.
    $profile = $this->governancePolicyResolver?->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('Downstream contract tool refused.'));
    }
    $wired = $this->governanceRequiredScope !== ''
      && $this->governanceRequestStack !== NULL
      && $this->governanceDlp !== NULL
      && $this->governanceClassification !== NULL
      && $this->governanceReadiness->evaluate(
        McpGovernedSurface::Tool,
        $this->currentUser,
        $this->governanceRequiredScope,
      )->isReady()
      && $this->governanceAccessChecker->isClientIpAllowed($profile);
    if (!$wired) {
      return ExecutableResult::failure($this->t('Downstream contract tool refused.'));
    }

    $helper = (string) ($values['helper'] ?? '');
    $payload = (string) ($values['payload'] ?? '');
    $bulk = ['succeeded' => ['a', 'b', 'c'], 'failed' => [], 'queued' => []];

    $returned = match ($helper) {
      'denyReason' => [
        'forbidden' => $this->denyReason(AccessResult::forbidden('contract reason')),
        'allowed' => $this->denyReason(AccessResult::allowed()),
      ],
      'logDeniedAccess' => $this->callLogDeniedAccess(),
      'validationMessages' => $this->validationMessages(User::create(['name' => ''])),
      'checkRateLimit' => $this->checkRateLimit($profile, $this->getPluginId()),
      'applyResultCap' => $this->applyResultCap($bulk, $profile),
      'checkResponseSizeCap' => $this->checkResponseSizeCap($payload, $profile),
      'truncateBulkResultsToSizeCap' => $this->truncateBulkResultsToSizeCap(
        ['succeeded' => str_split($payload, 8), 'failed' => [], 'queued' => []],
        $profile,
      ),
      default => throw new \InvalidArgumentException('Unknown helper.'),
    };

    // The three limit helpers hand back a ready failure result on refusal.
    if ($returned instanceof ExecutableResult) {
      return $returned;
    }
    return ExecutableResult::success(
      $this->t('Helper called.'),
      ['helper' => $helper, 'returned' => $returned],
    );
  }

  /**
   * Calls the void audit helper and reports that it returned.
   */
  private function callLogDeniedAccess(): bool {
    $this->logDeniedAccess($this->getPluginId(), 'contract', '(new)', 'create', 'contract reason');
    return TRUE;
  }

}
