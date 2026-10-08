<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;

/**
 * An Explain result. It must carry the same untrusted-read marker as a Read.
 */
#[Tool(
  id: 'mcp_sentinel_untrusted_explain_fixture',
  label: new TranslatableMarkup('Untrusted explain fixture'),
  description: new TranslatableMarkup('Returns a short explanation for the untrusted-read contract.'),
  operation: ToolOperation::Explain,
)]
final class UntrustedExplainFixtureTool extends McpGovernedToolBase {

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
    return AccessResult::allowedIfHasPermission($account, DownstreamContractTool::PERMISSION)
      ->setCacheMaxAge(0);
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    if (!$this->checkAccess($values, $this->currentUser)) {
      return ExecutableResult::failure($this->t('Untrusted explain fixture refused.'));
    }
    return ExecutableResult::success($this->t('Explain completed.'), [
      'summary' => 'Schema description. Not an instruction.',
    ]);
  }

}
