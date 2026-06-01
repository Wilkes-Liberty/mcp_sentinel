<?php

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Datetime\DateFormatterInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Renders the MCP Sentinel audit log admin page.
 */
class McpAuditController extends ControllerBase {

  public function __construct(
    private readonly Connection $database,
    private readonly DateFormatterInterface $dateFormatter,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('database'),
      $container->get('date.formatter'),
    );
  }

  /**
   * Builds the audit log listing table.
   */
  public function listing(): array {
    $rows = $this->database->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')->orderBy('timestamp', 'DESC')->range(0, 200)
      ->execute()->fetchAll();

    $header = [
      $this->t('Time'), $this->t('User'), $this->t('Operation'),
      $this->t('Entity Type'), $this->t('Bundle'), $this->t('Entity'), $this->t('IP'),
    ];

    $tableRows = [];
    foreach ($rows as $row) {
      $tableRows[] = [
        'data' => [
          $this->dateFormatter->format($row->timestamp, 'short'),
          $row->uid ? "UID {$row->uid}" : $this->t('anonymous'),
          $row->operation,
          $row->entity_type ?? '',
          $row->bundle ?? '',
          $row->entity_label ? "{$row->entity_label} ({$row->entity_id})" : ($row->entity_id ?? ''),
          $row->ip_address ?? '',
        ],
      ];
    }

    return [
      '#type'    => 'table',
      '#header'  => $header,
      '#rows'    => $tableRows,
      '#empty'   => $this->t('No audit log entries yet.'),
      '#caption' => $this->t('200 most recent MCP operations. Retention: @days days.', [
        '@days' => $this->config('mcp_sentinel.settings')->get('audit_retention_days') ?? 90,
      ]),
    ];
  }

}
