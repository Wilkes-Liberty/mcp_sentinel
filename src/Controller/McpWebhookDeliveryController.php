<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Component\Utility\Html;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Renders the MCP Sentinel webhook delivery log and handles replay/prune.
 */
class McpWebhookDeliveryController extends ControllerBase {

  /**
   * Maximum rows shown on the listing page.
   */
  private const MAX_ROWS = 500;

  /**
   * Constructs an McpWebhookDeliveryController.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Datetime\DateFormatterInterface $dateFormatter
   *   The date formatter service.
   * @param \Drupal\mcp_sentinel\Service\McpWebhookQueueManager $queueManager
   *   The webhook queue manager (handles replay re-enqueue and pruning).
   */
  public function __construct(
    private readonly Connection $database,
    private readonly DateFormatterInterface $dateFormatter,
    private readonly McpWebhookQueueManager $queueManager,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('database'),
      $container->get('date.formatter'),
      $container->get('mcp_sentinel.webhook_queue_manager'),
    );
  }

  /**
   * Builds the webhook delivery log listing.
   *
   * Supports optional ?status= and ?endpoint_id= query filters. Each row
   * has a colored status badge and an expandable block for payload/response.
   * A Prune delivery log action link is shown above the table.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request (provides the optional filter params).
   *
   * @return array
   *   A render array containing the filter form and the deliveries table.
   */
  public function listing(Request $request): array {
    $query = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d');
    $status = trim((string) $request->query->get('status', ''));
    if ($status !== '') {
      $query->condition('d.status', $status);
    }
    $endpointId = trim((string) $request->query->get('endpoint_id', ''));
    if ($endpointId !== '') {
      $query->condition('d.endpoint_id', $endpointId);
    }
    $query->orderBy('d.created', 'DESC')->range(0, self::MAX_ROWS);
    $rows = $query->execute()->fetchAll();

    $header = [
      $this->t('ID'), $this->t('Endpoint'), $this->t('Event'),
      $this->t('Status'), $this->t('Attempts'), $this->t('Last code'),
      $this->t('Next attempt'), $this->t('Created'),
      $this->t('Payload'), $this->t('Operations'),
    ];

    $tableRows = [];
    foreach ($rows as $row) {
      $rowStatus = (string) ($row->status ?? '');
      $badge = '<span class="mcp-badge ' . Html::escape($this->statusBadgeClass($rowStatus)) . '">'
        . Html::escape($rowStatus) . '</span>';

      // Expandable block for payload and last response body.
      // Payload and response body are external data — always escaped.
      $payload = (string) ($row->payload ?? '');
      $responseBody = (string) ($row->last_response_body ?? '');
      $expandCell = [
        'data' => [
          '#type' => 'html_tag',
          '#tag' => 'details',
          '#attributes' => ['class' => ['mcp-webhook-detail']],
          'summary' => [
            '#type' => 'html_tag',
            '#tag' => 'summary',
            '#value' => $this->t('Payload / response'),
          ],
          'payload' => [
            '#type' => 'html_tag',
            '#tag' => 'pre',
            '#attributes' => ['class' => ['mcp-webhook-payload']],
            '#value' => Html::escape($payload),
          ],
          'response' => $responseBody !== '' ? [
            '#type' => 'html_tag',
            '#tag' => 'pre',
            '#attributes' => ['class' => ['mcp-webhook-response']],
            '#value' => Html::escape($responseBody),
          ] : [],
        ],
      ];

      $operations = [];
      if (in_array($row->status, ['failed', 'failed_ssrf', 'failed_redirect', 'failed_key', 'sent'], TRUE)) {
        $operations['replay'] = [
          'title' => $this->t('Replay'),
          'url' => Url::fromRoute('mcp_sentinel.webhook_replay', [
            'delivery' => (int) $row->id,
          ]),
        ];
      }

      $tableRows[] = [
        (string) $row->id,
        Html::escape((string) ($row->endpoint_id ?? '')),
        Html::escape((string) ($row->event_name ?? '')),
        ['data' => ['#markup' => $badge]],
        (string) $row->attempts,
        $row->last_response_code !== NULL
          ? (string) $row->last_response_code
          : '',
        $row->next_attempt
          ? $this->dateFormatter->format((int) $row->next_attempt, 'short')
          : '',
        $this->dateFormatter->format((int) $row->created, 'short'),
        $expandCell,
        [
          'data' => $operations
            ? ['#type' => 'operations', '#links' => $operations]
            : ['#markup' => ''],
        ],
      ];
    }

    // Prune action link (CSRF-protected via the route requirement).
    $pruneUrl = Url::fromRoute('mcp_sentinel.webhook_prune');
    $pruneLink = [
      '#type' => 'link',
      '#title' => $this->t('Prune delivery log'),
      '#url' => $pruneUrl,
      '#attributes' => ['class' => ['button', 'button--small', 'button--danger']],
    ];

    return [
      'filter_form' => $this->formBuilder()
        ->getForm('Drupal\mcp_sentinel\Form\McpWebhookFilterForm'),
      'prune_action' => [
        '#type' => 'container',
        '#attributes' => ['class' => ['mcp-webhook-actions']],
        'prune' => $pruneLink,
      ],
      'table' => [
        '#type'    => 'table',
        '#header'  => $header,
        '#rows'    => $tableRows,
        '#empty'   => $this->t('No webhook deliveries recorded.'),
        '#caption' => $this->t(
          'Up to @n most recent webhook deliveries.',
          ['@n' => self::MAX_ROWS]
        ),
        '#attached' => ['library' => ['mcp_sentinel/admin']],
      ],
    ];
  }

  /**
   * Returns the badge CSS modifier class for a delivery status.
   *
   * @param string $status
   *   The delivery status string.
   *
   * @return string
   *   One of: mcp-badge--crit, mcp-badge--warn, mcp-badge--ok.
   */
  private function statusBadgeClass(string $status): string {
    return match ($status) {
      'failed', 'failed_ssrf', 'failed_redirect', 'failed_key' => 'mcp-badge--crit',
      'pending', 'in_progress' => 'mcp-badge--warn',
      default => 'mcp-badge--ok',
    };
  }

  /**
   * Replays a single delivery by resetting it to pending and re-enqueuing.
   *
   * The route is CSRF-protected via the _csrf_token requirement, so the link
   * generated in the listing carries a valid token.
   *
   * @param int $delivery
   *   The delivery log row ID.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   A redirect back to the delivery log listing.
   */
  public function replay(int $delivery): RedirectResponse {
    if ($this->queueManager->replayDelivery($delivery)) {
      $this->messenger()->addStatus($this->t(
        'Delivery @id re-queued for replay.',
        ['@id' => $delivery]
      ));
    }
    else {
      $this->messenger()->addError($this->t(
        'Delivery @id could not be replayed (row or endpoint missing).',
        ['@id' => $delivery]
      ));
    }
    return new RedirectResponse(
      Url::fromRoute('mcp_sentinel.webhook_delivery')->toString()
    );
  }

  /**
   * Prunes old delivery log rows and redirects back to the listing.
   *
   * The route is CSRF-protected via the _csrf_token requirement.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   A redirect back to the delivery log listing with a status message.
   */
  public function prune(): RedirectResponse {
    $deleted = $this->queueManager->pruneOldDeliveries();
    if ($deleted > 0) {
      $this->messenger()->addStatus($this->t(
        'Pruned @count delivery log @rows.',
        ['@count' => $deleted, '@rows' => $deleted === 1 ? 'row' : 'rows']
      ));
    }
    else {
      $this->messenger()->addStatus($this->t(
        'No delivery rows eligible for pruning (check retention settings).'
      ));
    }
    return new RedirectResponse(
      Url::fromRoute('mcp_sentinel.webhook_delivery')->toString()
    );
  }

}
