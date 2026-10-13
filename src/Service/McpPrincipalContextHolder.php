<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Seals the frozen principal context once per request or CLI job.
 *
 * Tools read through this holder, never from a swappable request
 * attribute. A subrequest cannot reseal a different principal. A
 * long-running CLI worker must call resetForJob() per message so the
 * first context is never reused. No shipped runner does so today:
 * validated claims live on the HTTP request, so a no-request call has
 * no claim source and is refused before it seals. sealForJob() is
 * reached only by a custom CLI/queue runner that supplies claims, and
 * that runner owns the per-message reset.
 */
final class McpPrincipalContextHolder {

  /**
   * Token used when a CLI / queue job is sealed.
   */
  private const JOB_TOKEN = 'job';

  /**
   * The sealed context, or NULL before the first seal.
   */
  private ?McpPrincipalContext $context = NULL;

  /**
   * Request (or job sentinel) this context is sealed to.
   */
  private mixed $sealedFor = NULL;

  /**
   * Constructs the holder.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   Distinguishes main request, subrequest, and CLI.
   */
  public function __construct(
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * Seals ctx for an HTTP request token.
   *
   * Same token is a no-op. A subrequest with a different principal
   * is refused. A new main request (previous token off the stack)
   * replaces the seal.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $ctx
   *   The frozen context from the validated token.
   * @param mixed $token
   *   The current request object.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When a subrequest tries to reseal a different principal, or when
   *   a job is already sealed.
   */
  public function seal(McpPrincipalContext $ctx, mixed $token): void {
    if ($this->sealedFor === $token) {
      return;
    }
    if ($this->sealedFor === self::JOB_TOKEN) {
      throw new McpPrincipalContextDeniedException(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        'CLI/worker principal context is already sealed. Call resetForJob() per message.',
      );
    }
    if ($this->context === NULL) {
      $this->context = $ctx;
      $this->sealedFor = $token;
      return;
    }
    $current = $this->requestStack->getCurrentRequest();
    $main = $this->requestStack->getMainRequest();
    $isSubrequest = $current !== NULL && $main !== NULL && $current !== $main;
    if ($isSubrequest) {
      if ($this->identityOf($this->context) !== $this->identityOf($ctx)) {
        throw new McpPrincipalContextDeniedException(
          McpPrincipalContextDeniedException::RESEAL_REFUSED,
          'A subrequest cannot reseal a different principal.',
        );
      }
      return;
    }
    if ($current !== NULL
      && $this->sealedFor !== $current
      && $this->sealedFor !== $main) {
      $this->context = $ctx;
      $this->sealedFor = $token;
      return;
    }
    if ($current !== NULL
      && ($this->sealedFor === $current || $this->sealedFor === $main)) {
      return;
    }
    throw new McpPrincipalContextDeniedException(
      McpPrincipalContextDeniedException::RESEAL_REFUSED,
      'Principal context is already sealed for this request.',
    );
  }

  /**
   * Seals ctx for one CLI / queue job.
   *
   * A second seal without resetForJob() is refused so a worker cannot
   * reuse the first message's principal.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $ctx
   *   The frozen context for this job.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When a job is already sealed.
   */
  public function sealForJob(McpPrincipalContext $ctx): void {
    $current = $this->requestStack->getCurrentRequest();
    if ($current !== NULL && $this->sealedFor === $current) {
      if ($this->context !== NULL
        && $this->identityOf($this->context) !== $this->identityOf($ctx)) {
        throw new McpPrincipalContextDeniedException(
          McpPrincipalContextDeniedException::RESEAL_REFUSED,
          'A subrequest cannot reseal a different principal.',
        );
      }
      return;
    }
    if ($this->context !== NULL) {
      throw new McpPrincipalContextDeniedException(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        'CLI/worker principal context is already sealed. Call resetForJob() per message.',
      );
    }
    $this->context = $ctx;
    $this->sealedFor = self::JOB_TOKEN;
  }

  /**
   * Clears the seal so the next CLI/queue message can seal again.
   *
   * Long-running workers call this at the start of each job. It is
   * refused while an HTTP request's own seal is current: code running
   * inside that request cannot clear it. A leftover Drupal CLI
   * bootstrap request is not an inbound HTTP seal, so a job may reset.
   *
   * @throws \LogicException
   *   When an HTTP request's sealed principal is current.
   */
  public function resetForJob(): void {
    if ($this->requestStack->getCurrentRequest() !== NULL
      && $this->sealedFor !== NULL
      && $this->sealedFor !== self::JOB_TOKEN) {
      throw new \LogicException(
        'resetForJob() is for CLI/queue workers; an HTTP request cannot reset its sealed principal.',
      );
    }
    $this->context = NULL;
    $this->sealedFor = NULL;
  }

  /**
   * The sealed context, or NULL if none has been sealed for this call.
   *
   * A context sealed for another HTTP request is not returned after
   * that request leaves the stack. A job seal is visible even when a
   * leftover CLI bootstrap request is still on the stack.
   */
  public function get(): ?McpPrincipalContext {
    if ($this->context === NULL) {
      return NULL;
    }
    if ($this->sealedFor === self::JOB_TOKEN) {
      return $this->context;
    }
    $current = $this->requestStack->getCurrentRequest();
    $main = $this->requestStack->getMainRequest();
    if ($current !== NULL) {
      if ($this->sealedFor === $current || $this->sealedFor === $main) {
        return $this->context;
      }
      return NULL;
    }
    return NULL;
  }

  /**
   * Test-only reset so a kernel test can reseal a new request.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function resetForTest(): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Principal-context holder can be reset only under PHPUnit.',
      );
    }
    $this->context = NULL;
    $this->sealedFor = NULL;
  }

  /**
   * Stable identity used to compare two sealed contexts.
   */
  private function identityOf(McpPrincipalContext $ctx): string {
    try {
      return $ctx->principalKey();
    }
    catch (\Throwable) {
      return $ctx->issuer()
        . '|'
        . $ctx->subject()
        . '|'
        . $ctx->azp()
        . '|'
        . $ctx->tenant();
    }
  }

}
