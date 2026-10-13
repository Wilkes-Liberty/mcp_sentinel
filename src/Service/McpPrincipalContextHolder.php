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
 * first context is never reused.
 */
final class McpPrincipalContextHolder {

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
   *   When a subrequest tries to reseal a different principal.
   */
  public function seal(McpPrincipalContext $ctx, mixed $token): void {
    if ($this->sealedFor === $token) {
      return;
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
    if ($this->context !== NULL) {
      throw new McpPrincipalContextDeniedException(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        'CLI/worker principal context is already sealed. Call resetForJob() per message.',
      );
    }
    $this->context = $ctx;
    $this->sealedFor = 'job';
  }

  /**
   * Clears the seal so the next CLI/queue message can seal again.
   *
   * Long-running workers must call this at the start of each job.
   */
  public function resetForJob(): void {
    $this->context = NULL;
    $this->sealedFor = NULL;
  }

  /**
   * The sealed context, or NULL if none has been sealed.
   */
  public function get(): ?McpPrincipalContext {
    return $this->context;
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
    $this->resetForJob();
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
