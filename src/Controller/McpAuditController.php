<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\SelectInterface;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Renders the MCP Sentinel audit log admin page and provides CSV/JSON export.
 */
class McpAuditController extends ControllerBase {

  /**
   * Maximum rows returned by the listing page and export.
   */
  private const MAX_ROWS = 2000;

  /**
   * Constructs an McpAuditController.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Datetime\DateFormatterInterface $dateFormatter
   *   The date formatter service.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger (provides the decodeMetadata accessor).
   */
  public function __construct(
    private readonly Connection $database,
    private readonly DateFormatterInterface $dateFormatter,
    private readonly McpAuditLogger $auditLogger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('database'),
      $container->get('date.formatter'),
      $container->get('mcp_sentinel.audit_logger'),
    );
  }

  /**
   * Builds the audit log listing table with optional query-param filters.
   *
   * Supported query parameters: operation, entity_type, uid, from, to.
   * The listing is capped at MAX_ROWS entries, ordered newest-first.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current HTTP request (provides query-parameter filter values).
   *
   * @return array
   *   A render array containing the filter form and the results table.
   */
  public function listing(Request $request): array {
    $query = $this->buildFilteredQuery($request);
    $query->orderBy('timestamp', 'DESC')->range(0, 200);
    $rows = $query->execute()->fetchAll();

    $header = [
      $this->t('Time'), $this->t('User'), $this->t('Operation'),
      $this->t('Entity Type'), $this->t('Bundle'), $this->t('Entity'), $this->t('IP'),
    ];

    $tableRows = [];
    foreach ($rows as $row) {
      // All metadata reads go through the decodeMetadata accessor so that
      // Feature 5 (at-rest encryption) can transparently decrypt here.
      $this->auditLogger->decodeMetadata((string) ($row->metadata ?? ''));

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

    $retentionDays = $this->config('mcp_sentinel.settings')->get('audit_retention_days') ?? 90;

    return [
      'filter_form' => $this->formBuilder()->getForm('Drupal\mcp_sentinel\Form\McpAuditFilterForm'),
      'table' => [
        '#type'    => 'table',
        '#header'  => $header,
        '#rows'    => $tableRows,
        '#empty'   => $this->t('No audit log entries match the current filters.'),
        '#caption' => $this->t('Up to 200 most recent MCP operations. Retention: @days days.', [
          '@days' => $retentionDays,
        ]),
      ],
    ];
  }

  /**
   * Returns audit log entries as a CSV or JSON download.
   *
   * Honors the same query-parameter filters as the listing page. The response
   * format is CSV by default; pass ?format=json for a JSON array.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current HTTP request (provides query-parameter filter values
   *   and the optional ?format=json switch).
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A Response containing the exported data with an appropriate
   *   Content-Type and Content-Disposition header.
   */
  public function export(Request $request): Response {
    $format = $request->query->get('format', 'csv');

    $query = $this->buildFilteredQuery($request);
    $query->orderBy('timestamp', 'ASC')->range(0, self::MAX_ROWS);
    $rows = $query->execute()->fetchAll();

    if ($format === 'json') {
      return $this->buildJsonResponse($rows);
    }

    return $this->buildCsvResponse($rows);
  }

  /**
   * Builds a SELECT query for the audit log, applying request filter params.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request whose query parameters supply the filter values.
   *
   * @return \Drupal\Core\Database\Query\SelectInterface
   *   A configured select query (no ORDER BY or range applied yet).
   */
  private function buildFilteredQuery(Request $request): SelectInterface {
    $query = $this->database->select('mcp_sentinel_audit_log', 'l')->fields('l');

    $operation = trim((string) $request->query->get('operation', ''));
    if ($operation !== '') {
      $query->condition('l.operation', $operation);
    }

    $entityType = trim((string) $request->query->get('entity_type', ''));
    if ($entityType !== '') {
      $query->condition('l.entity_type', $entityType);
    }

    $uid = trim((string) $request->query->get('uid', ''));
    if ($uid !== '') {
      $query->condition('l.uid', (int) $uid);
    }

    $from = trim((string) $request->query->get('from', ''));
    if ($from !== '') {
      $ts = strtotime($from);
      if ($ts !== FALSE) {
        $query->condition('l.timestamp', $ts, '>=');
      }
    }

    $to = trim((string) $request->query->get('to', ''));
    if ($to !== '') {
      $ts = strtotime($to);
      if ($ts !== FALSE) {
        $query->condition('l.timestamp', $ts, '<=');
      }
    }

    return $query;
  }

  /**
   * Builds a CSV download response from a set of audit log rows.
   *
   * Each row's metadata column is decoded through
   * McpAuditLogger::decodeMetadata and re-encoded as compact JSON in the cell.
   *
   * @param object[] $rows
   *   Rows from the audit log table as stdClass objects.
   *
   * @return \Symfony\Component\HttpFoundation\StreamedResponse
   *   A streamed CSV response.
   */
  private function buildCsvResponse(array $rows): StreamedResponse {
    $auditLogger = $this->auditLogger;

    $response = new StreamedResponse(static function () use ($rows, $auditLogger): void {
      $handle = fopen('php://output', 'w');
      if ($handle === FALSE) {
        return;
      }

      // Header row.
      fputcsv($handle, [
        'id',
        'timestamp',
        'uid',
        'operation',
        'entity_type',
        'bundle',
        'entity_id',
        'entity_label',
        'ip_address',
        'user_agent',
        'metadata',
        'prev_hash',
        'row_hash',
      ]);

      foreach ($rows as $row) {
        // Route metadata reads through the accessor seam for Feature 5.
        $metadata = $auditLogger->decodeMetadata((string) ($row->metadata ?? ''));
        fputcsv($handle, [
          $row->id ?? '',
          $row->timestamp ?? '',
          $row->uid ?? '',
          $row->operation ?? '',
          $row->entity_type ?? '',
          $row->bundle ?? '',
          $row->entity_id ?? '',
          $row->entity_label ?? '',
          $row->ip_address ?? '',
          $row->user_agent ?? '',
          json_encode($metadata),
          $row->prev_hash ?? '',
          $row->row_hash ?? '',
        ]);
      }

      fclose($handle);
    });

    $filename = 'mcp-sentinel-audit-' . date('Y-m-d') . '.csv';
    $response->headers->set('Content-Type', 'text/csv; charset=utf-8');
    $response->headers->set('Content-Disposition', 'attachment; filename="' . $filename . '"');

    return $response;
  }

  /**
   * Builds a JSON download response from a set of audit log rows.
   *
   * Each row is returned as an associative array. The metadata column is
   * decoded through McpAuditLogger::decodeMetadata (the Feature 5 seam).
   *
   * @param object[] $rows
   *   Rows from the audit log table as stdClass objects.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A JSON response with an array of row objects.
   */
  private function buildJsonResponse(array $rows): Response {
    $output = [];
    foreach ($rows as $row) {
      $rowArray = (array) $row;
      // Route metadata reads through the accessor seam for Feature 5.
      $rowArray['metadata'] = $this->auditLogger->decodeMetadata(
        (string) ($rowArray['metadata'] ?? '')
      );
      $output[] = $rowArray;
    }

    $filename = 'mcp-sentinel-audit-' . date('Y-m-d') . '.json';
    $response = new Response(
      (string) json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
      200,
      [
        'Content-Type'        => 'application/json',
        'Content-Disposition' => 'attachment; filename="' . $filename . '"',
      ]
    );

    return $response;
  }

}
