<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\QueueWorker;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Queue\Attribute\QueueWorker;
use Drupal\Core\Queue\QueueWorkerBase;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\key\KeyRepositoryInterface;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Processes MCP webhook deliveries with retry, backoff and an SSRF guard.
 *
 * Each queue item references a row in mcp_sentinel_webhook_delivery. The worker
 * atomically claims the row via an in_progress status update before POSTing
 * (preventing double-send on concurrent workers). It enforces HTTPS at send
 * time, resolves the hostname ONCE, validates resolved IPs against the SSRF
 * guard, then pins the validated IP via CURLOPT_RESOLVE so the TCP connection
 * goes to the exact IP that passed the check (defeating DNS-rebind TOCTOU).
 * Payloads are stored in the delivery row at enqueue time and re-sent byte-
 * for-byte on replay.
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
    );
  }

  /**
   * {@inheritdoc}
   */
  public function processItem(mixed $data): void {
    $deliveryId = (int) ($data['delivery_id'] ?? 0);
    $row = $this->loadRow($deliveryId);
    if ($row === NULL) {
      return;
    }
    if (in_array($row['status'], ['sent', 'failed', 'failed_ssrf'], TRUE)) {
      // Terminal states: already delivered or permanently failed.
      return;
    }
    // in_progress rows were claimed by another worker; skip without re-sending.
    if ($row['status'] === 'in_progress') {
      return;
    }

    $attempts = (int) $row['attempts'];
    if ($attempts >= self::MAX_ATTEMPTS) {
      $this->updateRow($deliveryId, 'failed', NULL, 'Max attempts reached.', $attempts);
      return;
    }

    // A row whose next_attempt has not yet arrived is not-yet-due; return
    // without re-queuing. The hook_cron scan re-enqueues when due so there is
    // no busy-loop from RequeueException.
    $next = $row['next_attempt'] !== NULL ? (int) $row['next_attempt'] : 0;
    if ($next > $this->time->getRequestTime()) {
      return;
    }

    $url = (string) ($data['endpoint']['url'] ?? '');

    // Fix 1: Enforce HTTPS at the worker (sender) level, not just at enqueue.
    // A row can be replayed or directly inserted after an operator edits an
    // endpoint — catching it here prevents cleartext sends.
    if (!str_starts_with($url, 'https://')) {
      $this->updateRow($deliveryId, 'failed_ssrf', NULL,
        'HTTPS required: URL scheme is not https.', $attempts);
      $this->logger->error(
        'Webhook blocked for delivery @id: URL must use HTTPS (got @url).',
        ['@id' => $deliveryId, '@url' => $url],
      );
      return;
    }

    // Fix 2: Resolve the host ONCE, validate the IP(s), then pin via
    // CURLOPT_RESOLVE so the TCP connect uses the validated IP, not a
    // subsequent DNS resolution (defeats DNS-rebind TOCTOU).
    $endpoint = (array) ($data['endpoint'] ?? []);
    $allowInternal = !empty($endpoint['allow_internal']);
    $resolvedIp = $this->validateAndResolveHost($url, $allowInternal);
    if ($resolvedIp === NULL) {
      // NULL means SSRF-blocked (internal/unresolvable literal).
      $this->updateRow($deliveryId, 'failed_ssrf', NULL,
        'SSRF blocked: hostname resolves to an internal address.', $attempts);
      $this->logger->error(
        'Webhook SSRF blocked (DNS) for delivery @id: @url',
        ['@id' => $deliveryId, '@url' => $url],
      );
      return;
    }
    // FALSE means unresolvable hostname — let the HTTP layer fail it normally.
    $curlResolvePin = [];
    if ($resolvedIp !== FALSE) {
      $host = (string) parse_url($url, PHP_URL_HOST);
      $port = (int) (parse_url($url, PHP_URL_PORT) ?: 443);
      // Pin the validated IP to the host:port so libcurl skips a second DNS
      // lookup and connects to the exact address we checked.
      $curlResolvePin = [CURLOPT_RESOLVE => ["{$host}:{$port}:{$resolvedIp}"]];
    }

    // Fix 3: Atomic claim — update status from 'pending' to 'in_progress'
    // only if status is still 'pending'. A return value of 0 means another
    // worker already claimed or delivered the row.
    $now = $this->time->getRequestTime();
    $claimed = $this->database->update('mcp_sentinel_webhook_delivery')
      ->condition('id', $deliveryId)
      ->condition('status', 'pending')
      ->fields(['status' => 'in_progress', 'last_attempt' => $now])
      ->execute();
    if (!$claimed) {
      // Another worker already claimed or sent this delivery.
      return;
    }

    // Fix 4: Use the stored payload for byte-identical delivery and replay.
    // Fall back to the queue-item payload if the column is empty (legacy rows).
    $storedPayload = (string) ($row['payload'] ?? '');
    if ($storedPayload === '') {
      $storedPayload = (string) ($data['payload'] ?? '');
      if ($storedPayload === '') {
        $this->logger->warning(
          'Webhook delivery @id has no stored payload; sending empty body.',
          ['@id' => $deliveryId],
        );
      }
    }
    $payload = $storedPayload;
    $secret = $this->resolveSecret($endpoint);
    $headers = [
      'Content-Type' => 'application/json',
      'User-Agent'   => 'mcp-sentinel-webhook/1.0',
    ];
    if ($secret !== '') {
      $headers['X-MCP-Signature'] = 'sha256=' . hash_hmac('sha256', $payload, $secret);
    }

    $newAttempts = $attempts + 1;
    $requestOptions = [
      'headers' => $headers,
      'body'    => $payload,
      'timeout' => 10,
      'verify'  => TRUE,
      'http_errors' => FALSE,
    ];
    if ($curlResolvePin !== []) {
      $requestOptions['curl'] = $curlResolvePin;
    }

    try {
      $response = $this->httpClient->request('POST', $url, $requestOptions);
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
    // Reset to 'pending' so the next cron scan can re-enqueue when due.
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
   * SSRF Layer-2: resolves the host ONCE and validates all resolved IPs.
   *
   * Returns the first validated (public) IP to use for CURLOPT_RESOLVE
   * pinning, FALSE when the host is unresolvable (let the HTTP layer handle
   * it), or NULL when the destination is blocked as SSRF.
   *
   * Literal IPs are validated directly; hostnames are resolved via DNS. Each
   * resolved IP is checked; the first one that passes the public-IP guard is
   * returned so the caller can pin it. If ANY IP is internal the whole
   * resolution is blocked (NULL).
   *
   * @param string $url
   *   The endpoint URL.
   * @param bool $allowInternal
   *   Per-endpoint opt-out of the private-IP guard (e.g. internal/VPN targets).
   *   HTTPS is always enforced regardless of this flag.
   *
   * @return string|false|null
   *   The validated public IP string to pin, FALSE if unresolvable, or NULL if
   *   SSRF-blocked.
   */
  private function validateAndResolveHost(string $url, bool $allowInternal): string|false|null {
    if ($allowInternal) {
      // The operator has explicitly opted this endpoint in for internal
      // delivery (e.g. an internal webhook receiver on a VPN). Skip IP checks
      // but return a sentinel so the caller does not attempt to pin (the host
      // may itself be a hostname pointing to an internal address).
      return FALSE;
    }
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    $host = trim($host, '[]');
    if ($host === '') {
      return NULL;
    }
    if (in_array($host, ['localhost', '::1'], TRUE)) {
      return NULL;
    }

    // A literal IP (v4 or v6) is validated directly — no DNS lookup needed.
    if (filter_var($host, FILTER_VALIDATE_IP) !== FALSE) {
      return self::ipIsInternal($host) ? NULL : $host;
    }

    // Resolve all A records for the hostname. Block if ANY resolved IP is
    // internal (an attacker returning a mix of public and private IPs must not
    // bypass the guard).
    $records = @gethostbynamel($host);
    if ($records === FALSE || $records === []) {
      $ip = @gethostbyname($host);
      // Unresolvable: the host value equals the input when lookup fails.
      if ($ip === $host) {
        // Return FALSE so the HTTP layer generates a normal network error and
        // the delivery can be retried.
        return FALSE;
      }
      $records = [$ip];
    }
    $validatedIp = FALSE;
    foreach ($records as $ip) {
      if (self::ipIsInternal($ip)) {
        // Any internal IP in the result set blocks the whole request.
        return NULL;
      }
      if ($validatedIp === FALSE) {
        // Capture the first public IP to pin via CURLOPT_RESOLVE.
        $validatedIp = $ip;
      }
    }
    return $validatedIp;
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
