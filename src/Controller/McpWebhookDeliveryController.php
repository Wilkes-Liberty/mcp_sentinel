<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Renders the MCP Sentinel webhook delivery log and handles replay.
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
   *   The webhook queue manager (handles replay re-enqueue).
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
   * Builds the webhook delivery log listing, with an optional status filter.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request (provides the optional ?status= filter).
   *
   * @return array
   *   A render array containing the deliveries table.
   */
  public function listing(Request $request): array {
    $query = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d');
    $status = trim((string) $request->query->get('status', ''));
    if ($status !== '') {
      $query->condition('d.status', $status);
    }
    $query->orderBy('d.created', 'DESC')->range(0, self::MAX_ROWS);
    $rows = $query->execute()->fetchAll();

    $header = [
      $this->t('ID'), $this->t('Endpoint'), $this->t('Event'),
      $this->t('Status'), $this->t('Attempts'), $this->t('Last code'),
      $this->t('Next attempt'), $this->t('Created'), $this->t('Operations'),
    ];

    $tableRows = [];
    foreach ($rows as $row) {
      $operations = [];
      if (in_array($row->status, ['failed', 'failed_ssrf', 'sent'], TRUE)) {
        $operations['replay'] = [
          'title' => $this->t('Replay'),
          'url' => Url::fromRoute('mcp_sentinel.webhook_replay', [
            'delivery' => (int) $row->id,
          ]),
        ];
      }
      $tableRows[] = [
        (string) $row->id,
        $row->endpoint_id,
        $row->event_name,
        $row->status,
        (string) $row->attempts,
        $row->last_response_code !== NULL ? (string) $row->last_response_code : '',
        $row->next_attempt ? $this->dateFormatter->format((int) $row->next_attempt, 'short') : '',
        $this->dateFormatter->format((int) $row->created, 'short'),
        [
          'data' => $operations
            ? ['#type' => 'operations', '#links' => $operations]
            : ['#markup' => ''],
        ],
      ];
    }

    return [
      'table' => [
        '#type'    => 'table',
        '#header'  => $header,
        '#rows'    => $tableRows,
        '#empty'   => $this->t('No webhook deliveries recorded.'),
        '#caption' => $this->t('Up to @n most recent webhook deliveries.', [
          '@n' => self::MAX_ROWS,
        ]),
      ],
    ];
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
      $this->messenger()->addStatus($this->t('Delivery @id re-queued for replay.', [
        '@id' => $delivery,
      ]));
    }
    else {
      $this->messenger()->addError($this->t('Delivery @id could not be replayed (row or endpoint missing).', [
        '@id' => $delivery,
      ]));
    }
    return new RedirectResponse(
      Url::fromRoute('mcp_sentinel.webhook_delivery')->toString()
    );
  }

}
