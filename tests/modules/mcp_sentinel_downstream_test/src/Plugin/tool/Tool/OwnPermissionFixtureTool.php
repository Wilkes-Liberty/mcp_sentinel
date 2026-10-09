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
 * A governed tool that declares a permission of its own.
 *
 * Sentinel fills in the context permission for governed tools that declare
 * none. This fixture proves a declared permission is kept as written.
 */
#[Tool(
  id: 'mcp_sentinel_own_permission_fixture',
  label: new TranslatableMarkup('Own permission fixture'),
  description: new TranslatableMarkup('Declares its own permission for the declared-permission contract.'),
  operation: ToolOperation::Read,
  permission: self::PERMISSION,
)]
final class OwnPermissionFixtureTool extends McpGovernedToolBase {

  /**
   * The permission this fixture declares.
   */
  public const PERMISSION = 'administer site configuration';

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
    return AccessResult::allowedIfHasPermission($account, self::PERMISSION)
      ->setCacheMaxAge(0);
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    return ExecutableResult::success($this->t('Own permission fixture read.'));
  }

}
