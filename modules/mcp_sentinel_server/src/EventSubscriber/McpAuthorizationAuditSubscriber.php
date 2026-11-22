<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_server\EventSubscriber;

use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_server\Event\McpAuthorizationDeniedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Records protocol and HTTP authorization refusals without request payloads.
 */
final class McpAuthorizationAuditSubscriber implements EventSubscriberInterface {

  /**
   * Constructs the subscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Writes denied_access rows that survive an unrelated rollback.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder|null $holder
   *   Sealed principal for this request. NULL on a cached container
   *   that predates this argument.
   */
  public function __construct(
    private readonly McpAuditLogger $auditLogger,
    private readonly ?McpPrincipalContextHolder $holder = NULL,
  ) {}

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
    $held = $this->holder?->get();
    $this->auditLogger->logSurvivingRollback(
      'denied_access',
      McpPrincipalContextDispatcher::stampPrincipalFields(
        [
          'http_status' => $event->httpStatus,
          'reason' => $event->reason,
        ],
        $held instanceof McpPrincipalContext ? $held : NULL,
      ),
    );
  }

}
