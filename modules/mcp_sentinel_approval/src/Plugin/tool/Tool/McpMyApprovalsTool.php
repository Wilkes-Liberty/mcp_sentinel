<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Plugin\tool\Tool;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpStatusToolBase;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Lists the acting account's own approval requests. Never the payload.
 */
#[Tool(
  id: 'mcp_sentinel_my_approvals',
  label: new TranslatableMarkup('My approval requests'),
  description: new TranslatableMarkup("List the acting account's own pending and recently decided approval requests: id, operation, target name, state and times. Never the payload or another account's requests."),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class McpMyApprovalsTool extends McpStatusToolBase {

  /**
   * Maximum rows returned.
   */
  private const LIMIT = 50;

  /**
   * Entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $uid = (int) $this->currentUser->id();
    if ($uid <= 0) {
      throw new \InvalidArgumentException('No acting account.');
    }
    $storage = $this->entityTypeManager->getStorage('mcp_approval_request');
    $ids = $storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('requested_by', $uid)
      ->sort('created', 'DESC')
      ->range(0, self::LIMIT)
      ->execute();
    $rows = [];
    foreach ($storage->loadMultiple($ids) as $request) {
      if (!$request instanceof McpApprovalRequestInterface) {
        continue;
      }
      // Re-check ownership in PHP so a query miss cannot leak another account.
      if ($request->getRequestedById() !== $uid) {
        continue;
      }
      $rows[] = [
        'id' => (int) $request->id(),
        'operation' => $request->getOperation(),
        'target' => $request->getTargetEntityTypeId() . ':' . $request->getTargetEntityId(),
        'status' => (string) $request->get('status')->value,
        'created' => (int) $request->get('created')->value,
        'decided' => (int) ($request->get('decided')->value ?? 0),
      ];
    }
    return [
      'count' => count($rows),
      'requests' => $rows,
    ];
  }

}
