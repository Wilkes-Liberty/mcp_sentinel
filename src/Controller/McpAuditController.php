<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Component\Utility\Html;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\SelectInterface;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpChartRenderer;
use Drupal\mcp_sentinel\Service\McpMetrics;
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
   * Operation prefixes that map to the critical (denied) badge.
   */
  private const DENIED_OPS = ['denied_', 'access_denied'];

  /**
   * Constructs an McpAuditController.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Datetime\DateFormatterInterface $dateFormatter
   *   The date formatter service.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger (provides the decodeMetadata accessor).
   * @param \Drupal\mcp_sentinel\Service\McpMetrics $metrics
   *   The dashboard metrics service.
   * @param \Drupal\mcp_sentinel\Service\McpChartRenderer $chartRenderer
   *   The chart renderer service.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly DateFormatterInterface $dateFormatter,
    private readonly McpAuditLogger $auditLogger,
    private readonly McpMetrics $metrics,
    private readonly McpChartRenderer $chartRenderer,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('database'),
      $container->get('date.formatter'),
      $container->get('mcp_sentinel.audit_logger'),
      $container->get('mcp_sentinel.metrics'),
      $container->get('mcp_sentinel.chart_renderer'),
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
      $this->t('Entity Type'), $this->t('Bundle'), $this->t('Entity'),
      $this->t('IP'), $this->t('Details'),
    ];

    $tableRows = [];
    foreach ($rows as $row) {
      // All metadata reads go through decodeMetadata so Feature 5 (at-rest
      // encryption) can transparently decrypt here.
      $decoded = $this->auditLogger->decodeMetadata(
        (string) ($row->metadata ?? '')
      );

      $operation = (string) ($row->operation ?? '');
      $badgeClass = $this->operationBadgeClass($operation);
      $badge = '<span class="mcp-badge ' . Html::escape($badgeClass) . '">'
        . Html::escape($operation) . '</span>';
      $operationCell = [
        'data' => ['#markup' => $badge],
      ];

      // Build expandable metadata/change-diff block (all values escaped).
      $metaItems = [];
      foreach ($decoded as $key => $value) {
        if (is_array($value)) {
          $value = json_encode($value);
        }
        $metaItems[] = Html::escape((string) $key)
          . ': ' . Html::escape((string) $value);
      }
      $detailCell = [
        'data' => [
          '#type' => 'html_tag',
          '#tag' => 'details',
          '#attributes' => ['class' => ['mcp-audit-detail']],
          'summary' => [
            '#type' => 'html_tag',
            '#tag' => 'summary',
            '#value' => $this->t('Metadata'),
          ],
          'content' => [
            '#theme' => 'item_list',
            '#items' => $metaItems,
            '#empty' => $this->t('No metadata.'),
          ],
        ],
      ];

      $label = $row->entity_label
        ? "{$row->entity_label} ({$row->entity_id})"
        : ((string) ($row->entity_id ?? ''));

      $tableRows[] = [
        'data' => [
          $this->dateFormatter->format($row->timestamp, 'short'),
          $row->uid
            ? Html::escape("UID {$row->uid}")
            : $this->t('anonymous'),
          $operationCell,
          Html::escape((string) ($row->entity_type ?? '')),
          Html::escape((string) ($row->bundle ?? '')),
          Html::escape($label),
          Html::escape((string) ($row->ip_address ?? '')),
          $detailCell,
        ],
      ];
    }

    $retentionDays = $this->config('mcp_sentinel.settings')
      ->get('audit_retention_days') ?? 90;

    // Build export buttons, preserving any active filter query params.
    $filterQuery = array_filter([
      'operation'   => $request->query->get('operation', ''),
      'entity_type' => $request->query->get('entity_type', ''),
      'uid'         => $request->query->get('uid', ''),
      'from'        => $request->query->get('from', ''),
      'to'          => $request->query->get('to', ''),
    ], static fn($v) => $v !== '');

    $csvUrl = Url::fromRoute('mcp_sentinel.audit_export', [], [
      'query' => $filterQuery + ['format' => 'csv'],
    ]);
    $jsonUrl = Url::fromRoute('mcp_sentinel.audit_export', [], [
      'query' => $filterQuery + ['format' => 'json'],
    ]);

    $exportBlock = [
      '#type' => 'container',
      '#attributes' => ['class' => ['mcp-audit-export-actions']],
      'csv' => [
        '#type' => 'link',
        '#title' => $this->t('Export CSV'),
        '#url' => $csvUrl,
        '#attributes' => ['class' => ['button', 'button--small']],
      ],
      'json' => [
        '#type' => 'link',
        '#title' => $this->t('Export JSON'),
        '#url' => $jsonUrl,
        '#attributes' => ['class' => ['button', 'button--small']],
      ],
    ];

    // Mini chart strip: volume time-series + allowed-vs-denied.
    $chartStrip = $this->buildChartStrip();

    return [
      'chart_strip' => $chartStrip,
      'export_actions' => $exportBlock,
      'filter_form' => $this->formBuilder()
        ->getForm('Drupal\mcp_sentinel\Form\McpAuditFilterForm'),
      'table' => [
        '#type'    => 'table',
        '#header'  => $header,
        '#rows'    => $tableRows,
        '#empty'   => $this->t('No audit log entries match the current filters.'),
        '#caption' => $this->t(
          'Up to 200 most recent MCP operations. Retention: @days days.',
          ['@days' => $retentionDays]
        ),
        '#attached' => ['library' => ['mcp_sentinel/admin']],
      ],
    ];
  }

  /**
   * Builds the mini chart strip for the audit listing header.
   *
   * Degrades gracefully to an empty array on any error.
   *
   * @return array
   *   A render array with up to two chart cells, or an empty array.
   */
  private function buildChartStrip(): array {
    try {
      $drillUrl = Url::fromRoute('mcp_sentinel.audit_log')->toString();

      // auditTimeSeries returns per-bucket arrays; extract count values.
      $rawTimeSeries = $this->metrics->auditTimeSeries('24h');
      $volumeSeries = [];
      foreach ($rawTimeSeries as $label => $bucket) {
        $volumeSeries[(string) $label] = $bucket['count'];
      }

      // allowedVsDenied returns keyed ints; remap to labelled chart series.
      $avd = $this->metrics->allowedVsDenied('24h');
      $avdSeries = [
        (string) $this->t('Allowed') => $avd['allowed'],
        (string) $this->t('Denied')  => $avd['denied'],
      ];

      return [
        '#type' => 'container',
        '#attributes' => ['class' => ['mcp-audit-chart-strip']],
        'volume' => [
          '#type' => 'container',
          '#attributes' => ['class' => ['mcp-chart-cell']],
          'chart' => $this->chartRenderer->render('line', $volumeSeries, [
            'title'     => (string) $this->t('Audit volume (24 h)'),
            'drill_url' => $drillUrl,
          ]),
        ],
        'avd' => [
          '#type' => 'container',
          '#attributes' => ['class' => ['mcp-chart-cell']],
          'chart' => $this->chartRenderer->render('bar', $avdSeries, [
            'title'     => (string) $this->t('Allowed vs denied (24 h)'),
            'drill_url' => $drillUrl,
          ]),
        ],
      ];
    }
    catch (\Throwable $e) {
      $this->getLogger('mcp_sentinel')->error(
        'Audit chart strip error: @msg',
        ['@msg' => $e->getMessage()]
      );
      return [];
    }
  }

  /**
   * Returns the badge CSS modifier class for an operation string.
   *
   * @param string $operation
   *   The operation name from the audit log.
   *
   * @return string
   *   One of: mcp-badge--crit, mcp-badge--warn, mcp-badge--ok.
   */
  private function operationBadgeClass(string $operation): string {
    foreach (self::DENIED_OPS as $prefix) {
      if (str_starts_with($operation, $prefix)) {
        return 'mcp-badge--crit';
      }
    }
    if ($operation === 'entity_delete') {
      return 'mcp-badge--warn';
    }
    return 'mcp-badge--ok';
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
    $query = $this->database
      ->select('audit_chain_log', 'l')
      ->condition('l.channel', McpAuditLogger::READ_CHANNELS, 'IN')
      ->fields('l');

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

    $response = new StreamedResponse(
      static function () use ($rows, $auditLogger): void {
        $handle = fopen('php://output', 'w');
        if ($handle === FALSE) {
          return;
        }

        // Header row. The separator/enclosure/escape are passed explicitly:
        // PHP 8.4 deprecates calling fputcsv() without the $escape argument.
        fputcsv($handle, [
          'id', 'timestamp', 'uid', 'operation', 'entity_type', 'bundle',
          'entity_id', 'entity_label', 'ip_address', 'user_agent',
          'metadata', 'prev_hash', 'row_hash',
        ], ',', '"', '\\');

        foreach ($rows as $row) {
          // Route metadata reads through the accessor seam for Feature 5.
          $metadata = $auditLogger->decodeMetadata(
            (string) ($row->metadata ?? '')
          );
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
          ], ',', '"', '\\');
        }

        fclose($handle);
      }
    );

    $filename = 'mcp-sentinel-audit-' . date('Y-m-d') . '.csv';
    $response->headers->set('Content-Type', 'text/csv; charset=utf-8');
    $response->headers->set(
      'Content-Disposition',
      'attachment; filename="' . $filename . '"'
    );

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
      (string) json_encode(
        $output,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
      ),
      200,
      [
        'Content-Type'        => 'application/json',
        'Content-Disposition' => 'attachment; filename="' . $filename . '"',
      ]
    );

    return $response;
  }

}
