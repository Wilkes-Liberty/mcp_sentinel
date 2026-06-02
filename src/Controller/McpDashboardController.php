<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Utility\Html;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\State\StateInterface;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpChartRenderer;
use Drupal\mcp_sentinel\Service\McpMetrics;
use Drupal\mcp_sentinel\Service\McpUrgentConditions;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Renders the MCP Sentinel governance dashboard.
 *
 * GET /admin/reports/mcp-sentinel. Read-only: assembles the urgent banner,
 * posture hero, status tiles, chain-integrity card, top-agents / denied panels,
 * quick-actions, active-controls strip, and the six charts from the three data
 * services (mcp_sentinel.metrics, mcp_sentinel.urgent_conditions,
 * mcp_sentinel.chart_renderer). Every widget is built behind its own try/catch
 * so a single failing metric degrades to an empty/"—" widget rather than
 * fataling the whole page (spec §6); failures are logged to mcp_sentinel.
 */
class McpDashboardController extends ControllerBase {

  /**
   * Allowlisted dashboard windows.
   */
  private const WINDOWS = ['24h', '7d', '30d'];

  /**
   * The default window.
   */
  private const DEFAULT_WINDOW = '24h';

  /**
   * The placeholder shown when a widget value cannot be computed.
   */
  private const PLACEHOLDER = '—';

  /**
   * Constructs an McpDashboardController.
   *
   * @param \Drupal\mcp_sentinel\Service\McpMetrics $metrics
   *   The dashboard-data service.
   * @param \Drupal\mcp_sentinel\Service\McpUrgentConditions $urgentConditions
   *   The urgent-conditions evaluator.
   * @param \Drupal\mcp_sentinel\Service\McpChartRenderer $chartRenderer
   *   The chart renderer (charts + SVG fallback).
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger (Verify-now runs verifyChain()).
   * @param \Drupal\Core\State\StateInterface $state
   *   The state service (Verify-now writes mcp_sentinel.last_verify).
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection (Verify-now reads the audit row count).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service (Verify-now timestamps the last-verify result).
   * @param \Psr\Log\LoggerInterface $logger
   *   The mcp_sentinel logger channel.
   */
  public function __construct(
    private readonly McpMetrics $metrics,
    private readonly McpUrgentConditions $urgentConditions,
    private readonly McpChartRenderer $chartRenderer,
    private readonly McpAuditLogger $auditLogger,
    private readonly StateInterface $state,
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.metrics'),
      $container->get('mcp_sentinel.urgent_conditions'),
      $container->get('mcp_sentinel.chart_renderer'),
      $container->get('mcp_sentinel.audit_logger'),
      $container->get('state'),
      $container->get('database'),
      $container->get('datetime.time'),
      $container->get('logger.channel.mcp_sentinel'),
    );
  }

  /**
   * Builds the governance dashboard render array.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request (supplies the validated ?window= query parameter).
   *
   * @return array
   *   The dashboard render array.
   */
  public function dashboard(Request $request): array {
    $window = $this->resolveWindow($request);

    $build = [
      '#theme' => 'mcp_sentinel_dashboard',
      '#banner' => $this->widget('banner', fn() => $this->buildBanner()),
      '#status' => $this->widget('status', fn() => $this->buildStatus(), []),
      '#tiles' => $this->widget('tiles', fn() => $this->buildTiles($window), []),
      '#chain' => $this->widget('chain', fn() => $this->buildChain(), []),
      '#panels' => $this->widget('panels', fn() => $this->buildPanels($window), []),
      '#quick_actions' => $this->widget('quick_actions', fn() => $this->buildQuickActions(), []),
      '#active_controls' => $this->widget('active_controls', fn() => $this->buildActiveControls(), []),
      '#charts' => $this->widget('charts', fn() => $this->buildCharts($window), []),
      '#window' => $window,
      '#windows' => $this->buildWindowLinks($window),
      '#attached' => [
        'library' => ['mcp_sentinel/dashboard'],
      ],
      '#cache' => [
        'contexts' => ['user.permissions', 'url.query_args:window'],
        'tags' => ['mcp_sentinel_audit_log', 'config:mcp_sentinel.settings'],
        // The dashboard reflects volatile audit/state data; keep it briefly
        // cached so the urgent banner and counts stay fresh.
        'max-age' => 60,
      ],
    ];

    return $build;
  }

  /**
   * Validates and returns the requested window, defaulting to 24h.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return string
   *   A guaranteed-valid window key.
   */
  private function resolveWindow(Request $request): string {
    $window = (string) $request->query->get('window', self::DEFAULT_WINDOW);
    return in_array($window, self::WINDOWS, TRUE) ? $window : self::DEFAULT_WINDOW;
  }

  /**
   * Runs a widget builder behind a try/catch, returning a safe default.
   *
   * @param string $name
   *   The widget name (for logging).
   * @param callable $builder
   *   The widget builder.
   * @param mixed $default
   *   The safe value to return when the builder throws.
   *
   * @return mixed
   *   The built widget value, or $default on failure.
   */
  private function widget(string $name, callable $builder, mixed $default = NULL): mixed {
    try {
      return $builder();
    }
    catch (\Throwable $e) {
      $this->logger->error('Dashboard widget @widget failed: @message', [
        '@widget' => $name,
        '@message' => $e->getMessage(),
      ]);
      return $default;
    }
  }

  /**
   * Builds the urgent-conditions banner render array.
   *
   * @return array
   *   A themed banner build, or an empty array when nothing is urgent.
   */
  private function buildBanner(): array {
    $conditions = $this->urgentConditions->evaluate();
    if ($conditions === []) {
      return [];
    }
    return [
      '#theme' => 'mcp_sentinel_urgent_banner',
      '#conditions' => $conditions,
    ];
  }

  /**
   * Builds the posture-hero summary.
   *
   * Rolls up the count of items needing attention from the urgent conditions
   * plus pending approvals, anomaly alerts, and webhook failures.
   *
   * @return array{attention: int, all_clear: bool, headline: string}
   *   The posture summary.
   */
  private function buildStatus(): array {
    $attention = 0;
    foreach ($this->urgentConditions->evaluate() as $condition) {
      if ($condition['severity'] !== 'info') {
        $attention++;
      }
    }
    $attention += $this->metrics->approvalSummary()['pending'];
    $attention += $this->metrics->anomalySummary('24h')['alerts'];
    $attention += $this->metrics->webhookHealth('24h')['failed'];

    return [
      'attention' => $attention,
      'all_clear' => $attention === 0,
      'headline' => $attention === 0
        ? (string) $this->t('All clear — no governance items need attention.')
        : (string) $this->formatPlural(
          $attention,
          '1 item needs attention',
          '@count items need attention',
      ),
    ];
  }

  /**
   * Builds the five status tiles.
   *
   * @param string $window
   *   The selected window.
   *
   * @return array<int, array{label: string, value: string, sub: string, state: string, url: string|null}>
   *   The tile list.
   */
  private function buildTiles(string $window): array {
    $status = $this->metrics->statusSummary();
    $counts = $this->metrics->auditCounts($window);
    $anomaly = $this->metrics->anomalySummary($window);
    $approvals = $this->metrics->approvalSummary();
    $webhooks = $this->metrics->webhookHealth($window);

    $auditUrl = Url::fromRoute('mcp_sentinel.audit_log')->toString();
    $deniedUrl = Url::fromRoute('mcp_sentinel.audit_log', [], [
      'query' => ['operation' => 'denied_access'],
    ])->toString();

    $tiles = [];
    $tiles[] = [
      'label' => (string) $this->t('Governance'),
      'value' => $status['governed']
        ? (string) $this->t('On')
        : (string) $this->t('Off'),
      'sub' => (string) $this->formatPlural(
        $status['profile_count'],
        '1 policy profile',
        '@count policy profiles',
      ),
      'state' => $status['governed'] ? 'ok' : 'warn',
      'url' => Url::fromRoute('mcp_sentinel.settings')->toString(),
    ];
    $tiles[] = [
      'label' => (string) $this->t('Audit'),
      'value' => (string) $counts['total'],
      'sub' => (string) $this->t('@n denied', ['@n' => $counts['denied']]),
      'state' => 'ok',
      'url' => $auditUrl,
    ];
    $tiles[] = [
      'label' => (string) $this->t('Anomaly'),
      'value' => (string) $anomaly['alerts'],
      'sub' => (string) $this->formatPlural(
        $anomaly['enabled_rules'],
        '1 rule enabled',
        '@count rules enabled',
      ),
      'state' => $anomaly['alerts'] > 0 ? 'warn' : 'ok',
      'url' => $deniedUrl,
    ];
    $tiles[] = [
      'label' => (string) $this->t('Approvals'),
      'value' => $approvals['available']
        ? (string) $approvals['pending']
        : self::PLACEHOLDER,
      'sub' => $approvals['available']
        ? (string) $this->t('pending')
        : (string) $this->t('not installed'),
      'state' => $approvals['pending'] > 0 ? 'warn' : 'ok',
      'url' => $approvals['available']
        ? Url::fromRoute('entity.mcp_approval_request.collection')->toString()
        : NULL,
    ];
    $tiles[] = [
      'label' => (string) $this->t('Webhooks'),
      'value' => (string) $webhooks['total'],
      'sub' => (string) $this->t('@n failed', ['@n' => $webhooks['failed']]),
      'state' => $webhooks['failed'] > 0 ? 'crit' : 'ok',
      'url' => $this->webhookUrl(),
    ];
    return $tiles;
  }

  /**
   * Builds the chain-integrity card.
   *
   * @return array{state: string, label: string, detail: string}
   *   The chain card.
   */
  private function buildChain(): array {
    $chain = $this->metrics->chainIntegrity();
    $rows = $chain['rows'];
    $ok = $chain['ok'];
    if ($ok === NULL) {
      return [
        'state' => 'warn',
        'label' => (string) $this->t('Not yet verified'),
        'detail' => (string) $this->t('@n audit rows. Run "Verify now" to check integrity.', ['@n' => $rows]),
      ];
    }
    if ($ok === TRUE) {
      return [
        'state' => 'ok',
        'label' => (string) $this->t('Chain intact'),
        'detail' => (string) $this->t('@n rows verified.', ['@n' => $rows]),
      ];
    }
    $brokenAt = $chain['broken_at'];
    return [
      'state' => 'crit',
      'label' => (string) $this->t('Chain broken'),
      'detail' => $brokenAt !== NULL
        ? (string) $this->t('Tampering indicated at row @id.', ['@id' => (int) $brokenAt])
        : (string) $this->t('Tampering indicated.'),
    ];
  }

  /**
   * Builds the top-agents and denied-by-policy panels.
   *
   * @param string $window
   *   The selected window.
   *
   * @return array{top_agents: array, denied_reasons: array}
   *   The two panels' row data (escaped).
   */
  private function buildPanels(string $window): array {
    $agents = [];
    foreach ($this->metrics->topAgents($window) as $agent) {
      $uid = $agent['uid'];
      $agents[] = [
        'label' => $uid > 0
          ? (string) $this->t('UID @uid', ['@uid' => $uid])
          : (string) $this->t('anonymous'),
        'total' => $agent['total'],
        'denied' => $agent['denied'],
        'url' => Url::fromRoute('mcp_sentinel.audit_log', [], [
          'query' => ['uid' => $uid],
        ])->toString(),
      ];
    }

    $reasons = [];
    foreach ($this->metrics->deniedReasons($window) as $reason => $count) {
      $reasons[] = [
        // Reason labels are operator/agent-sourced — escape for safety.
        'label' => Html::escape((string) $reason),
        'count' => (int) $count,
      ];
    }

    return [
      'top_agents' => $agents,
      'denied_reasons' => $reasons,
    ];
  }

  /**
   * Builds the quick-actions bar.
   *
   * The "Verify chain now" action is expensive (walks the full audit table
   * computing HMACs) and is therefore only rendered for users with
   * 'administer mcp sentinel'. Read-only viewers still see chain-integrity
   * status in the chain card; they simply cannot trigger a re-verify.
   *
   * @return array<int, array{title: string, url: string}>
   *   Quick-action links.
   */
  private function buildQuickActions(): array {
    $actions = [];
    if ($this->currentUser()->hasPermission('administer mcp sentinel')) {
      $actions[] = [
        'title' => (string) $this->t('Verify chain now'),
        'url' => $this->verifyUrl(),
      ];
    }
    $actions[] = [
      'title' => (string) $this->t('Audit log'),
      'url' => Url::fromRoute('mcp_sentinel.audit_log')->toString(),
    ];
    $actions[] = [
      'title' => (string) $this->t('Settings'),
      'url' => Url::fromRoute('mcp_sentinel.settings')->toString(),
    ];
    return array_values(array_filter($actions, static fn(array $a): bool => $a['url'] !== ''));
  }

  /**
   * Builds the active-controls strip.
   *
   * @return array<int, array{label: string, active: bool}>
   *   Control name + active flag.
   */
  private function buildActiveControls(): array {
    $labels = [
      'hash_chain' => $this->t('Hash chain'),
      'encryption' => $this->t('Encryption'),
      'siem' => $this->t('SIEM streaming'),
      'dlp' => $this->t('DLP redaction'),
      'rate_limit' => $this->t('Rate limiting'),
      'ip_allowlist' => $this->t('IP allowlist'),
      'approvals' => $this->t('Approvals'),
    ];
    $controls = $this->metrics->activeControls();
    $strip = [];
    foreach ($labels as $key => $label) {
      $strip[] = [
        'label' => (string) $label,
        'active' => (bool) ($controls[$key] ?? FALSE),
      ];
    }
    return $strip;
  }

  /**
   * Builds the six dashboard charts via the chart renderer.
   *
   * (1) audit volume time-series (anomaly buckets flagged in the title),
   * (2) allowed vs denied, (3) operation mix, (4) top agents, (5) denied
   * reasons, (6) webhook health. Each chart that maps onto a filterable report
   * carries a click-to-drill URL into the (moved) audit log or webhook log.
   *
   * @param string $window
   *   The selected window.
   *
   * @return array<int, array>
   *   The ordered chart render arrays.
   */
  private function buildCharts(string $window): array {
    $auditUrl = Url::fromRoute('mcp_sentinel.audit_log')->toString();
    $deniedUrl = Url::fromRoute('mcp_sentinel.audit_log', [], [
      'query' => ['operation' => 'denied_access'],
    ])->toString();

    $charts = [];

    // (1) Audit volume time-series.
    $timeSeries = $this->metrics->auditTimeSeries($window);
    $volume = [];
    $anomalyBuckets = 0;
    foreach ($timeSeries as $label => $bucket) {
      $volume[(string) $label] = $bucket['count'];
      if ($bucket['anomaly']) {
        $anomalyBuckets++;
      }
    }
    $volumeTitle = $anomalyBuckets > 0
      ? (string) $this->formatPlural(
        $anomalyBuckets,
        'Audit volume (1 anomaly bucket)',
        'Audit volume (@count anomaly buckets)',
      )
      : (string) $this->t('Audit volume');
    $charts[] = $this->chartRenderer->render('line', $volume, [
      'title' => $volumeTitle,
      'drill_url' => $auditUrl,
    ]);

    // (2) Allowed vs denied.
    $split = $this->metrics->allowedVsDenied($window);
    $charts[] = $this->chartRenderer->render('bar', [
      (string) $this->t('Allowed') => $split['allowed'],
      (string) $this->t('Denied') => $split['denied'],
    ], [
      'title' => (string) $this->t('Allowed vs denied'),
      'drill_url' => $auditUrl,
    ]);

    // (3) Operation mix.
    $charts[] = $this->chartRenderer->render('donut', $this->metrics->operationMix($window), [
      'title' => (string) $this->t('Operation mix'),
      'drill_url' => $auditUrl,
    ]);

    // (4) Top agents.
    $agentSeries = [];
    foreach ($this->metrics->topAgents($window) as $agent) {
      $uid = $agent['uid'];
      $key = $uid > 0
        ? (string) $this->t('UID @uid', ['@uid' => $uid])
        : (string) $this->t('anonymous');
      $agentSeries[$key] = $agent['total'];
    }
    $charts[] = $this->chartRenderer->render('bar', $agentSeries, [
      'title' => (string) $this->t('Top agents'),
      'drill_url' => $auditUrl,
    ]);

    // (5) Denied reasons.
    $reasonSeries = [];
    foreach ($this->metrics->deniedReasons($window) as $reason => $count) {
      $reasonSeries[(string) $reason] = (int) $count;
    }
    $charts[] = $this->chartRenderer->render('bar', $reasonSeries, [
      'title' => (string) $this->t('Denied reasons'),
      'drill_url' => $deniedUrl,
    ]);

    // (6) Webhook health.
    $health = $this->metrics->webhookHealth($window);
    $charts[] = $this->chartRenderer->render('donut', [
      (string) $this->t('Sent') => $health['sent'],
      (string) $this->t('Failed') => $health['failed'],
      (string) $this->t('Pending') => $health['pending'],
    ], [
      'title' => (string) $this->t('Webhook health'),
      'drill_url' => $this->webhookUrl() ?? '',
    ]);

    return $charts;
  }

  /**
   * Builds the window-toggle link metadata.
   *
   * @param string $current
   *   The current window.
   *
   * @return array<int, array{key: string, label: string, url: string, active: bool}>
   *   The window links.
   */
  private function buildWindowLinks(string $current): array {
    $labels = [
      '24h' => $this->t('24 hours'),
      '7d' => $this->t('7 days'),
      '30d' => $this->t('30 days'),
    ];
    $links = [];
    foreach (self::WINDOWS as $window) {
      $links[] = [
        'key' => $window,
        'label' => (string) $labels[$window],
        'url' => Url::fromRoute('mcp_sentinel.dashboard', [], [
          'query' => ['window' => $window],
        ])->toString(),
        'active' => $window === $current,
      ];
    }
    return $links;
  }

  /**
   * Returns the webhook delivery log URL, or NULL when unavailable.
   *
   * @return string|null
   *   The internal path.
   */
  private function webhookUrl(): ?string {
    try {
      return Url::fromRoute('mcp_sentinel.webhook_delivery')->toString();
    }
    catch (\Throwable $e) {
      return NULL;
    }
  }

  /**
   * Returns the CSRF-tokened Verify-now action URL, or '' when unavailable.
   *
   * The route declares `_csrf_token: TRUE`, so generating its URL automatically
   * appends the per-session `?token=` query parameter that the action's access
   * check validates.
   *
   * @return string
   *   The internal path with a CSRF token, or ''.
   */
  private function verifyUrl(): string {
    try {
      return Url::fromRoute('mcp_sentinel.verify_chain')->toString();
    }
    catch (\Throwable $e) {
      return '';
    }
  }

  /**
   * Runs the audit hash-chain verification and records the result.
   *
   * CSRF-protected (route requirement). Walks the audit chain via the audit
   * logger, writes the outcome to @state 'mcp_sentinel.last_verify' in the SAME
   * shape the `drush mcp-sentinel:audit-verify` command writes (ok, broken_at,
   * rows, time) so the chain-integrity widget and the urgent-conditions
   * chain_broken alert stay live, then redirects back to the dashboard with a
   * status message.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   A redirect back to the dashboard.
   */
  public function verify(): RedirectResponse {
    try {
      $result = $this->auditLogger->verifyChain();
      $rows = (int) $this->database
        ->select('mcp_sentinel_audit_log', 'l')
        ->countQuery()
        ->execute()
        ->fetchField();
      $this->state->set('mcp_sentinel.last_verify', [
        'ok' => (bool) $result['ok'],
        'broken_at' => isset($result['broken_at']) ? (int) $result['broken_at'] : NULL,
        'rows' => $rows,
        'time' => $this->time->getRequestTime(),
      ]);
      if ($result['ok']) {
        $this->messenger()->addStatus($this->t('Audit hash chain verified — @n rows intact.', [
          '@n' => $rows,
        ]));
      }
      else {
        $this->messenger()->addError($this->t('Audit hash chain BROKEN at row @id. Tampering or data loss is indicated.', [
          '@id' => isset($result['broken_at']) ? (int) $result['broken_at'] : 0,
        ]));
      }
    }
    catch (\Throwable $e) {
      $this->logger->error('Verify-now failed: @message', ['@message' => $e->getMessage()]);
      $this->messenger()->addError($this->t('Audit hash chain verification could not be completed.'));
    }

    return $this->redirect('mcp_sentinel.dashboard');
  }

}
