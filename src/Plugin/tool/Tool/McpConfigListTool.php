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
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Lists configuration object names under MCP Sentinel governance.
 *
 * Requires the resolved profile's allow_config_read flag. Names matching the
 * profile's denied_config_types denylist are filtered out of the result so the
 * agent cannot even enumerate denied configuration. The list is audited as
 * 'config_list' (suppressed unless audit_log_reads is on).
 */
#[Tool(
  id: 'mcp_sentinel_config_list',
  label: new TranslatableMarkup('List configuration'),
  description: new TranslatableMarkup('Returns the names of Drupal configuration objects, optionally filtered by a name prefix. Governed by MCP Sentinel config-read policy.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'prefix' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Name prefix'),
      description: new TranslatableMarkup('Optional config name prefix to filter by, e.g. system. — empty lists all readable config.'),
      required: FALSE,
      default_value: '',
    ),
  ],
)]
final class McpConfigListTool extends ToolBase {

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
    $prefix = trim((string) ($values['prefix'] ?? ''));
    $profile = $this->policyResolver->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied: no governance profile applies to this account.'));
    }
    if ($rateLimited = $this->checkRateLimit($profile, 'mcp_sentinel_config_list')) {
      return $rateLimited;
    }
    // The read gate applies to listing as a whole; per-name denials are then
    // filtered below so denied config is never enumerated.
    if (!$profile->allowsConfigRead()) {
      $this->logDeniedAccess('mcp_sentinel_config_list', 'config', $prefix, 'read', 'Configuration read is disabled in MCP Sentinel.');
      return ExecutableResult::failure($this->t('MCP Sentinel denied the config list: configuration read is disabled.'));
    }

    $names = $this->configFactory->listAll($prefix);
    $tags = [];
    $names = array_values(array_filter(
      $names,
      fn (string $name): bool => $this->accessChecker->checkConfigTypePolicy($name, $profile, $tags) === NULL,
    ));

    $names = $this->applyResultCap([
      'succeeded' => $names,
      'failed' => [],
      'queued' => [],
    ], $profile)['succeeded'];

    $this->auditLogger->log('config_list', [
      'entity_type' => 'config',
      'id' => $prefix,
    ]);

    return ExecutableResult::success(
      $this->t('Listed @count configuration object(s).', ['@count' => count($names)]),
      ['prefix' => $prefix, 'names' => $names],
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
