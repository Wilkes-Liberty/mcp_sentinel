<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_server\EventSubscriber;

use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_server\Event\McpAuthorizationDeniedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Records protocol and HTTP authorization refusals without request payloads.
 */
final class McpAuthorizationAuditSubscriber implements EventSubscriberInterface {

  /**
   * Constructs the subscriber.
   */
  public function __construct(private readonly McpAuditLogger $auditLogger) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [McpAuthorizationDeniedEvent::class => 'onDenied'];
  }

  /**
   * Records exactly the bounded authorization event supplied by MCP Server.
   */
  public function onDenied(McpAuthorizationDeniedEvent $event): void {
    $this->auditLogger->logSurvivingRollback('denied_access', [
      'http_status' => $event->httpStatus,
      'reason' => $event->reason,
    ]);
  }

}
