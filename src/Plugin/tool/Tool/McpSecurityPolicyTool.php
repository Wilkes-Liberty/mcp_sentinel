<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Returns the active MCP Sentinel security policy for the current agent.
 *
 * Agents should check this before attempting write operations so they know
 * which entity types and operations are permitted, and which fields are
 * redacted. The policy is resolved from the agent's authenticated roles.
 */
#[Tool(
  id: 'mcp_sentinel_security_policy',
  label: new TranslatableMarkup('Get MCP security policy'),
  description: new TranslatableMarkup('Returns the active MCP Sentinel security configuration: allowed/denied entity types, permitted operations, and redacted fields. Check this before attempting write operations.'),
  operation: ToolOperation::Explain,
)]
final class McpSecurityPolicyTool extends ToolBase {

  /**
   * The policy resolver service.
   */
  protected McpPolicyResolver $resolver;

  /**
   * The config factory.
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * The MCP Sentinel access checker service.
   */
  protected McpAccessChecker $accessChecker;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->resolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->configFactory = $container->get('config.factory');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $enabled = (bool) $this->configFactory->get('mcp_sentinel.settings')->get('enabled');
    $profile = $this->resolver->resolve();
    if ($profile === NULL) {
      return ExecutableResult::success($this->t('No MCP policy applies to this account.'), [
        'enabled' => $enabled,
        'governed' => FALSE,
      ]);
    }
    $data = [
      'enabled' => $enabled,
      'governed' => TRUE,
      'profile' => $profile->id(),
      'allow_read' => $profile->allowsRead(),
      'allow_write' => $profile->allowsWrite(),
      'allow_delete' => $profile->allowsDelete(),
      'allow_graphql_mutations' => $profile->allowsGraphqlMutations(),
      'allowed_entity_types' => $profile->getAllowedEntityTypes() ?: 'all',
      'denied_entity_types' => $profile->getDeniedEntityTypes(),
      'redacted_fields' => $profile->getRedactedFields(),
    ];
    return ExecutableResult::success($this->t('Security policy retrieved.'), $data);
  }

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(array $values, AccountInterface $account, bool $return_as_object = FALSE): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission($account, 'access mcp sentinel context');
    if (!$access->isAllowed()) {
      return $return_as_object ? $access : FALSE;
    }

    // IP allowlist gate — governed requests only. When a policy profile applies
    // and the client IP is not in the profile's allowlist, deny access.
    // The result is explicitly uncacheable: client IP is not a cache context.
    $profile = $this->resolver->resolve($account);
    if ($profile !== NULL && !$this->accessChecker->isClientIpAllowed($profile)) {
      $denied = AccessResult::forbidden('Source IP not permitted by MCP Sentinel policy.')->setCacheMaxAge(0);
      return $return_as_object ? $denied : FALSE;
    }

    return $return_as_object ? $access : $access->isAllowed();
  }

}
