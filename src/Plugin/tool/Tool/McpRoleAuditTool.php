<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpRoleAssertions;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports role-assertion violations as role and permission names only.
 */
#[Tool(
  id: 'mcp_sentinel_role_audit',
  label: new TranslatableMarkup('Role audit'),
  description: new TranslatableMarkup('Report governance role-assertion violations: role names and permissions only. Requires the administer permission. No personal data.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class McpRoleAuditTool extends McpStatusToolBase {

  /**
   * Role assertions.
   */
  protected McpRoleAssertions $roleAssertions;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->roleAssertions = $container->get('mcp_sentinel.role_assertions');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function extraPermissions(): array {
    return ['administer mcp sentinel'];
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $violations = [];
    foreach ($this->roleAssertions->violations() as $violation) {
      $violations[] = [
        'role' => $violation['role'],
        'permission' => $violation['permission'],
        'type' => $violation['type'],
        'profile' => $violation['profile'],
        'via' => $violation['via'],
      ];
    }
    return [
      'count' => count($violations),
      'violations' => $violations,
    ];
  }

}
