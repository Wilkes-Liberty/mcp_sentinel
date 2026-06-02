<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\QueueWorker;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Queue\Attribute\QueueWorker;
use Drupal\Core\Queue\QueueWorkerBase;
use Drupal\Core\Queue\RequeueException;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\key\KeyRepositoryInterface;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Processes MCP webhook deliveries with retry, backoff and an SSRF guard.
 *
 * Each queue item references a row in mcp_sentinel_webhook_delivery. The worker
 * loads the row, re-validates the destination against the SSRF guard at send
 * time (DNS can rebind between enqueue and delivery), signs the body with
 * HMAC-SHA256 when a Key-backed secret is configured, and POSTs it over HTTPS.
 *
 * Claim-safety / idempotency: the delivery row status is the single source of
 * truth. A row already marked 'sent' short-circuits with no HTTP call, so a
 * duplicate queue item (or a concurrent worker that already delivered) can
 * never double-send. The row is only advanced to 'sent'/'failed'/'failed_ssrf'
 * after the attempt resolves.
 */
#[QueueWorker(
  id: 'mcp_sentinel_webhook_delivery',
  title: new TranslatableMarkup('MCP Sentinel webhook delivery'),
  cron: ['time' => 30],
)]
final class McpWebhookWorker extends QueueWorkerBase implements ContainerFactoryPluginInterface {

  /**
   * Maximum delivery attempts before marking a permanent failure.
   */
  private const MAX_ATTEMPTS = 5;

  /**
   * Per-attempt backoff in seconds: 30 s, 5 min, 30 min, 2 h, 8 h.
   */
  private const BACKOFF = [30, 300, 1800, 7200, 28800];

  /**
   * Returns the backoff delay (seconds) before the given attempt's retry.
   *
   * @param int $attempt
   *   The 1-based number of the just-completed attempt.
   *
   * @return int
   *   The number of seconds to wait before the next attempt.
   */
  public static function backoffSeconds(int $attempt): int {
    $index = max(0, min($attempt - 1, count(self::BACKOFF) - 1));
    return self::BACKOFF[$index];
  }

  /**
   * Determines whether an IP address is in a private/reserved/loopback range.
   *
   * Public and static so the SSRF policy is unit-testable in isolation.
   *
   * @param string $ip
   *   The IP address (v4 or v6).
   *
   * @return bool
   *   TRUE if the IP is internal, link-local, loopback or otherwise reserved.
   */
  public static function ipIsInternal(string $ip): bool {
    $public = filter_var(
      $ip,
      FILTER_VALIDATE_IP,
      FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
    );
    return $public === FALSE;
  }

  /**
   * Constructs a new McpWebhookWorker.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin ID.
   * @param mixed $plugin_definition
   *   The plugin definition.
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The HTTP client.
   * @param \Drupal\key\KeyRepositoryInterface $keyRepository
   *   The key repository for resolving signing secrets.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The MCP Sentinel logger channel.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   */
  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    private readonly Connection $database,
    private readonly ClientInterface $httpClient,
    private readonly KeyRepositoryInterface $keyRepository,
    private readonly TimeInterface $time,
    private readonly LoggerInterface $logger,
    private readonly ConfigFactoryInterface $configFactory,
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(
    ContainerInterface $container,
    array $configuration,
    $plugin_id,
    $plugin_definition,
  ): static {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('database'),
      $container->get('http_client'),
      $container->get('key.repository'),
      $container->get('datetime.time'),
      $container->get('logger.channel.mcp_sentinel'),
      $container->get('config.factory'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function processItem(mixed $data): void {
    $deliveryId = (int) ($data['delivery_id'] ?? 0);
    $row = $this->loadRow($deliveryId);
    if ($row === NULL || $row['status'] === 'sent') {
      // Already delivered, terminal-failed elsewhere, or row missing.
      return;
    }
    if (in_array($row['status'], ['failed', 'failed_ssrf'], TRUE)) {
      return;
    }

    $attempts = (int) $row['attempts'];
    if ($attempts >= self::MAX_ATTEMPTS) {
      $this->updateRow($deliveryId, 'failed', NULL, 'Max attempts reached.', $attempts);
      return;
    }

    // A row whose next_attempt has not yet arrived is requeued unchanged so a
    // backed-off delivery is not sent early.
    $next = $row['next_attempt'] !== NULL ? (int) $row['next_attempt'] : 0;
    if ($next > $this->time->getRequestTime()) {
      throw new RequeueException('Webhook delivery not yet due.');
    }

    $url = (string) ($data['endpoint']['url'] ?? '');
    // Layer-2 SSRF: DNS-resolve and block internal addresses at send time.
    if ($this->isInternalAfterDns($url)) {
      $this->updateRow($deliveryId, 'failed_ssrf', NULL,
        'SSRF blocked: hostname resolves to an internal address.', $attempts);
      $this->logger->error(
        'Webhook SSRF blocked (DNS) for delivery @id: @url',
        ['@id' => $deliveryId, '@url' => $url],
      );
      return;
    }

    $payload = (string) ($data['payload'] ?? '');
    $secret = $this->resolveSecret((array) ($data['endpoint'] ?? []));
    $headers = [
      'Content-Type' => 'application/json',
      'User-Agent'   => 'mcp-sentinel-webhook/1.0',
    ];
    if ($secret !== '') {
      $headers['X-MCP-Signature'] = 'sha256=' . hash_hmac('sha256', $payload, $secret);
    }

    $newAttempts = $attempts + 1;
    try {
      $response = $this->httpClient->request('POST', $url, [
        'headers' => $headers,
        'body'    => $payload,
        'timeout' => 10,
        'verify'  => TRUE,
        'http_errors' => FALSE,
      ]);
      $code = $response->getStatusCode();
      $body = substr($response->getBody()->getContents(), 0, 512);
      if ($code >= 200 && $code < 300) {
        $this->updateRow($deliveryId, 'sent', $code, $body, $newAttempts);
        return;
      }
      $this->scheduleRetry($deliveryId, $newAttempts, $code, $body);
    }
    catch (\Throwable $e) {
      $this->scheduleRetry($deliveryId, $newAttempts, NULL,
        substr($e->getMessage(), 0, 512));
      if ($newAttempts < self::MAX_ATTEMPTS) {
        throw new RequeueException($e->getMessage());
      }
    }
  }

  /**
   * Schedules the next retry or marks the row failed when attempts run out.
   *
   * @param int $id
   *   The delivery row ID.
   * @param int $attempts
   *   The new attempt count.
   * @param int|null $code
   *   The last HTTP response code, if any.
   * @param string|null $body
   *   The last response/error body, truncated.
   */
  private function scheduleRetry(int $id, int $attempts, ?int $code, ?string $body): void {
    if ($attempts >= self::MAX_ATTEMPTS) {
      $this->updateRow($id, 'failed', $code, $body, $attempts);
      return;
    }
    // The attempt count is 1-based for the just-completed try; the next wait
    // uses the backoff slot for the upcoming attempt.
    $backoff = self::backoffSeconds($attempts);
    $now = $this->time->getRequestTime();
    $this->database->update('mcp_sentinel_webhook_delivery')
      ->condition('id', $id)
      ->fields([
        'status'             => 'pending',
        'attempts'           => $attempts,
        'last_attempt'       => $now,
        'next_attempt'       => $now + $backoff,
        'last_response_code' => $code,
        'last_response_body' => $body,
      ])->execute();
  }

  /**
   * Writes a terminal/sent status update to a delivery row.
   *
   * @param int $id
   *   The delivery row ID.
   * @param string $status
   *   The new status.
   * @param int|null $code
   *   The last HTTP response code, if any.
   * @param string|null $body
   *   The last response/error body, truncated.
   * @param int $attempts
   *   The attempt count to store.
   */
  private function updateRow(int $id, string $status, ?int $code, ?string $body, int $attempts): void {
    $this->database->update('mcp_sentinel_webhook_delivery')
      ->condition('id', $id)
      ->fields([
        'status'             => $status,
        'attempts'           => $attempts,
        'last_attempt'       => $this->time->getRequestTime(),
        'last_response_code' => $code,
        'last_response_body' => $body,
      ])->execute();
  }

  /**
   * Loads a delivery row by ID.
   *
   * @param int $id
   *   The delivery row ID.
   *
   * @return array|null
   *   The row as an associative array, or NULL if missing.
   */
  private function loadRow(int $id): ?array {
    $row = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('d.id', $id)->execute()->fetchAssoc();
    return $row ?: NULL;
  }

  /**
   * SSRF Layer-2: resolves the host and blocks internal/reserved addresses.
   *
   * Literal IPs are validated directly. Hostnames are resolved via DNS at send
   * time so a rebind after enqueue is still caught. Honours the global
   * allow_internal_webhook_urls opt-out for legitimate internal deployments.
   *
   * @param string $url
   *   The endpoint URL.
   *
   * @return bool
   *   TRUE if the destination is internal and must be blocked.
   */
  private function isInternalAfterDns(string $url): bool {
    if ($this->configFactory->get('mcp_sentinel.settings')->get('allow_internal_webhook_urls')) {
      return FALSE;
    }
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    $host = trim($host, '[]');
    if ($host === '') {
      return TRUE;
    }
    if (in_array($host, ['localhost', '::1'], TRUE)) {
      return TRUE;
    }

    // A literal IP (v4 or v6) is validated directly — no DNS lookup.
    if (filter_var($host, FILTER_VALIDATE_IP) !== FALSE) {
      return self::ipIsInternal($host);
    }

    // Resolve all A records for the hostname; block if any is internal.
    $records = @gethostbynamel($host);
    if ($records === FALSE || $records === []) {
      $ip = @gethostbyname($host);
      // Unresolvable: treat as a network error, not SSRF — let the HTTP layer
      // fail it and schedule a normal retry.
      if ($ip === $host) {
        return FALSE;
      }
      $records = [$ip];
    }
    foreach ($records as $ip) {
      if (self::ipIsInternal($ip)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Resolves the HMAC signing secret from the endpoint's Key entity.
   *
   * @param array $endpoint
   *   The endpoint configuration map.
   *
   * @return string
   *   The signing secret, or an empty string when none is configured.
   */
  private function resolveSecret(array $endpoint): string {
    $keyId = (string) ($endpoint['secret_key'] ?? '');
    if ($keyId === '') {
      return '';
    }
    $key = $this->keyRepository->getKey($keyId);
    return $key ? (string) $key->getKeyValue() : '';
  }

}
