<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
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
final class McpSecurityPolicyTool extends McpGovernedToolBase {

  /**
   * The policy resolver service.
   */
  protected McpPolicyResolver $resolver;

  /**
   * The config factory.
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->resolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->configFactory = $container->get('config.factory');
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
      // Per-entity-type destructive overrides. Each entry overrides the global
      // allow_delete / allow_write flag for that entity type only; types absent
      // here follow the global flags. Surfaced to the connector as entityRules.
      'entity_rules' => $profile->getEntityRules(),
    ];
    return ExecutableResult::success($this->t('Security policy retrieved.'), $data);
  }

}
