<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Tool\ConfigScopeToolInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reads a single configuration object under MCP Sentinel governance.
 *
 * The read is gated by the resolved policy profile's allow_config_read flag and
 * its denied_config_types denylist. A successful read is audited as
 * 'config_read' (suppressed unless audit_log_reads is on, like entity reads).
 */
#[Tool(
  id: 'mcp_sentinel_config_get',
  label: new TranslatableMarkup('Get configuration'),
  description: new TranslatableMarkup('Returns the values of a single Drupal configuration object (e.g. system.site). Governed by MCP Sentinel config-read policy.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'name' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Config name'),
      description: new TranslatableMarkup('The configuration object name, e.g. system.site.'),
      required: TRUE,
    ),
  ],
)]
final class McpConfigGetTool extends ToolBase implements ConfigScopeToolInterface {

  use McpEntityToolTrait;

  /**
   * The config factory.
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * The MCP Sentinel access checker.
   */
  protected McpAccessChecker $accessChecker;

  /**
   * The MCP Sentinel policy resolver.
   */
  protected McpPolicyResolver $policyResolver;

  /**
   * The MCP Sentinel audit logger.
   */
  protected McpAuditLogger $auditLogger;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->configFactory = $container->get('config.factory');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->auditLogger = $container->get('mcp_sentinel.audit_logger');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $name = trim((string) ($values['name'] ?? ''));
    if ($name === '') {
      return ExecutableResult::failure($this->t('A configuration name is required.'));
    }
    $profile = $this->policyResolver->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied: no governance profile applies to this account.'));
    }
    if ($rateLimited = $this->checkRateLimit($profile, 'mcp_sentinel_config_get')) {
      return $rateLimited;
    }
    $policyResult = $this->accessChecker->checkConfigAccess($name, 'read', $profile);
    if ($reason = $this->denyReason($policyResult)) {
      $this->logDeniedAccess('mcp_sentinel_config_get', 'config', $name, 'read', $reason);
      return ExecutableResult::failure($this->t('MCP Sentinel denied the config read: @reason', ['@reason' => $reason]));
    }

    $data = $this->configFactory->get($name)->getRawData();
    $this->auditLogger->log('config_read', [
      'entity_type' => 'config',
      'id' => $name,
    ]);

    return ExecutableResult::success(
      $this->t('Configuration @name read.', ['@name' => $name]),
      ['name' => $name, 'data' => $data],
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(array $values, AccountInterface $account, bool $return_as_object = FALSE): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission($account, 'access mcp sentinel context');
    if (!$access->isAllowed()) {
      return $return_as_object ? $access : FALSE;
    }
    $profile = $this->policyResolver->resolve($account);
    if ($profile !== NULL && !$this->accessChecker->isClientIpAllowed($profile)) {
      $denied = AccessResult::forbidden('Source IP not permitted by MCP Sentinel policy.')->setCacheMaxAge(0);
      return $return_as_object ? $denied : FALSE;
    }
    return $return_as_object ? $access : $access->isAllowed();
  }

}
