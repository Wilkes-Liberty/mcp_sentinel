<?php

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\mcp_sentinel\Event\McpEntityEvent;
use GuzzleHttp\ClientInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Dispatches Drupal events and HMAC-signed HTTPS webhooks for MCP changes.
 *
 * Webhook URLs MUST use HTTPS. Plain HTTP is rejected.
 * Payloads are signed with HMAC-SHA256 in the X-MCP-Signature header.
 *
 * The signing secret is resolved from a Key entity (webhook_secret_key) so it
 * never lives in exported configuration. A legacy plaintext webhook_secret is
 * honoured as a fallback for sites that have not yet migrated.
 *
 * Verify signature:
 *   hash_equals('sha256=' . hash_hmac('sha256', $body, $secret), $header)
 */
class McpEventDispatcher {

  public function __construct(
    private readonly EventDispatcherInterface $eventDispatcher,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerChannelInterface $logger,
    private readonly ClientInterface $httpClient,
    private readonly TimeInterface $time,
    private readonly KeyRepositoryInterface $keyRepository,
  ) {}

  /**
   * Resolves the webhook signing secret from the configured Key entity.
   *
   * Falls back to the legacy plaintext webhook_secret if no key is configured.
   */
  private function resolveSecret(Config $config): string {
    $keyId = (string) $config->get('webhook_secret_key');
    if ($keyId !== '') {
      $key = $this->keyRepository->getKey($keyId);
      if ($key) {
        return (string) $key->getKeyValue();
      }
      $this->logger->warning('Webhook signing key @id not found.', ['@id' => $keyId]);
    }
    return (string) $config->get('webhook_secret');
  }

  /**
   * Dispatch an MCP entity event and optionally fire a webhook.
   */
  public function dispatch(string $eventName, EntityInterface $entity): void {
    $this->eventDispatcher->dispatch(new McpEntityEvent($entity, $eventName), $eventName);

    $config = $this->configFactory->get('mcp_sentinel.settings');
    if ($config->get('webhook_enabled') && $config->get('webhook_url')) {
      $this->fireWebhook($eventName, $entity, $config);
    }
  }

  /**
   * Sends an HMAC-signed HTTPS webhook for an MCP entity change.
   */
  private function fireWebhook(string $eventName, EntityInterface $entity, Config $config): void {
    $url    = (string) $config->get('webhook_url');
    $secret = $this->resolveSecret($config);

    if (!str_starts_with($url, 'https://')) {
      $this->logger->error(
        'Webhook URL must use HTTPS. Blocked for event @event.', ['@event' => $eventName]
      );
      return;
    }

    try {
      $payload = json_encode([
        'event'       => $eventName,
        'entity_type' => $entity->getEntityTypeId(),
        'bundle'      => $entity->bundle(),
        'id'          => $entity->id(),
        'uuid'        => $entity->uuid(),
        'label'       => $entity->label(),
        'timestamp'   => $this->time->getRequestTime(),
      ], JSON_THROW_ON_ERROR);
    }
    catch (\JsonException $e) {
      $this->logger->error('Webhook JSON encode failed: @msg', ['@msg' => $e->getMessage()]);
      return;
    }

    $headers = [
      'Content-Type' => 'application/json',
      'User-Agent'   => 'mcp-sentinel-webhook/1.0',
    ];
    if ($secret) {
      $headers['X-MCP-Signature'] = 'sha256=' . hash_hmac('sha256', $payload, $secret);
    }

    $logger = $this->logger;
    try {
      $this->httpClient->requestAsync('POST', $url, [
        'headers' => $headers,
        'body'    => $payload,
        'timeout' => 5,
        'verify'  => TRUE,
      ])->then(NULL, static function ($reason) use ($eventName, $logger) {
        $logger->warning(
          'Webhook failed for @event: @reason', ['@event' => $eventName, '@reason' => (string) $reason]
        );
      });
    }
    catch (\Exception $e) {
      $this->logger->error(
        'Webhook exception for @event: @msg', ['@event' => $eventName, '@msg' => $e->getMessage()]
      );
    }
  }

}
