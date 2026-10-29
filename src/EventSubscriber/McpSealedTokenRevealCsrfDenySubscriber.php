<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Audits a CSRF refusal on the sealed-token reveal POST.
 *
 * Drupal's _csrf_token check 403s before the controller runs, so the
 * consume path never sees a missing or bad token. That refusal is still
 * a secret-disclosure deny and must leave a row. The write is fail-closed
 * for the secret: a logging failure does not reveal the bearer and does
 * not change the 403.
 *
 * @internal
 */
final class McpSealedTokenRevealCsrfDenySubscriber implements EventSubscriberInterface {

  /**
   * POST consume route that requires Drupal's CSRF token.
   */
  public const ROUTE = 'mcp_sentinel.sealed_token_reveal_post';

  /**
   * Audit operation for a refused reveal POST.
   */
  public const OPERATION = 'sealed_token_reveal_denied';

  /**
   * Request attribute that prevents exception+response double writes.
   */
  private const AUDITED_ATTRIBUTE = '_mcp_sentinel_reveal_csrf_denied_audited';

  /**
   * Constructs the subscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Writes sealed_token_reveal_denied through logAlways().
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   Acting uid. Permission denials are not csrf_invalid.
   * @param \Psr\Log\LoggerInterface $logger
   *   Records an audit-write failure without the bearer or CSRF token.
   */
  public function __construct(
    private readonly McpAuditLogger $auditLogger,
    private readonly AccountProxyInterface $currentUser,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Observe only. Do not replace the 403 or stop other subscribers.
    return [
      KernelEvents::EXCEPTION => ['onException', 0],
      KernelEvents::RESPONSE => ['onResponse', 0],
    ];
  }

  /**
   * Writes one denied row when CSRF access fails on the reveal POST.
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   The exception event.
   */
  public function onException(ExceptionEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    if (!$event->getThrowable() instanceof AccessDeniedHttpException) {
      return;
    }
    $this->auditCsrfDenial($event->getRequest());
  }

  /**
   * Writes one denied row when the reveal POST already rendered as 403.
   *
   * @param \Symfony\Component\HttpKernel\Event\ResponseEvent $event
   *   The response event.
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    if ($event->getResponse()->getStatusCode() !== 403) {
      return;
    }
    $this->auditCsrfDenial($event->getRequest());
  }

  /**
   * Records csrf_invalid for a privileged actor on the consume route.
   *
   * The route's only other requirement is administer mcp sentinel. A
   * 403 after that permission is the CSRF deny. Never stores the
   * bearer or the CSRF token value.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The reveal POST request.
   */
  private function auditCsrfDenial(Request $request): void {
    if ($request->attributes->get('_route') !== self::ROUTE) {
      return;
    }
    if ($request->getMethod() !== 'POST') {
      return;
    }
    if ($request->attributes->get(self::AUDITED_ATTRIBUTE)) {
      return;
    }
    if (!$this->currentUser->hasPermission('administer mcp sentinel')) {
      return;
    }
    $request->attributes->set(self::AUDITED_ATTRIBUTE, TRUE);
    try {
      $this->auditLogger->logAlways(self::OPERATION, [
        'reason' => 'csrf_invalid',
        'route' => self::ROUTE,
        'uid' => (int) $this->currentUser->id(),
      ]);
    }
    catch (\Throwable $exception) {
      // Fail-closed for the secret: keep the 403 and never reveal.
      $this->logger->error(
        'Sealed-token reveal CSRF denial audit write failed with @class.',
        ['@class' => $exception::class],
      );
    }
  }

}
