<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Queue\QueueWorkerInterface;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Seals the frozen principal context once per request or CLI job.
 *
 * Tools read through this holder, never from a swappable request
 * attribute. A subrequest cannot reseal a different principal. A
 * long-running CLI worker resets through the internal
 * mcp_sentinel.principal_context_job service (not this class) per
 * message so the first context is never reused. A web-cron HTTP
 * request is already sealed; the job service pushes a nested job
 * overlay that never mutates that request seal and restores it
 * after the item. sealForJob() and resetForJob() are @internal.
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
   * TRUE while a job overlay is active over the request seal.
   */
  private bool $inJobScope = FALSE;

  /**
   * Job-overlay context. Independent of the request seal.
   */
  private ?McpPrincipalContext $jobContext = NULL;

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
   * Internal: called by the dispatcher. Runners reset through
   * mcp_sentinel.principal_context_job, not this method. A second
   * seal without resetForJob() is refused so a worker cannot reuse
   * the first message's principal. While a job scope is active the
   * overlay is written; the request seal is not mutated.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $ctx
   *   The frozen context for this job.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When a job is already sealed.
   */
  public function sealForJob(McpPrincipalContext $ctx): void {
    if ($this->inJobScope) {
      if ($this->jobContext !== NULL) {
        throw new McpPrincipalContextDeniedException(
          McpPrincipalContextDeniedException::RESEAL_REFUSED,
          'CLI/worker principal context is already sealed. Call resetForJob() per message.',
        );
      }
      $this->jobContext = $ctx;
      return;
    }
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
   * Pushes a job overlay over the current seal.
   *
   * A request-sealed HTTP principal (web cron) is left untouched.
   * A leftover JOB_TOKEN seal from a previous CLI item is cleared
   * so the next item can seal its own principal. A second begin()
   * without leaveJobScope() clears only the overlay.
   *
   * @internal Called by mcp_sentinel.principal_context_job.
   *
   * @throws \LogicException
   *   When an HTTP request's sealed principal is current and the
   *   caller is not a queue worker or Drush command.
   */
  public function enterJobScope(): void {
    if ($this->hasInboundHttpSeal()
      && !$this->calledFromInternalJobPath()) {
      throw new \LogicException(
        'enterJobScope() is for CLI/queue workers; an HTTP '
        . 'request cannot open a job overlay.',
      );
    }
    $this->inJobScope = TRUE;
    $this->jobContext = NULL;
    if ($this->sealedFor === self::JOB_TOKEN) {
      $this->context = NULL;
      $this->sealedFor = NULL;
    }
  }

  /**
   * Drops the job overlay and restores the request seal.
   *
   * @internal Called by mcp_sentinel.principal_context_job.
   */
  public function leaveJobScope(): void {
    $this->inJobScope = FALSE;
    $this->jobContext = NULL;
  }

  /**
   * Whether a job overlay is currently active.
   *
   * @internal The dispatcher seals via sealForJob() while TRUE.
   */
  public function inJobScope(): bool {
    return $this->inJobScope;
  }

  /**
   * Clears the seal so the next CLI/queue message can seal again.
   *
   * Internal: called by mcp_sentinel.principal_context_job. Not a
   * public API. While a job scope is active, only the overlay is
   * cleared. Refused while an HTTP request's own seal is current
   * and no job scope is open. A leftover Drupal CLI bootstrap
   * request is not an inbound HTTP seal, so a job may reset.
   *
   * @throws \LogicException
   *   When an HTTP request's sealed principal is current.
   */
  public function resetForJob(): void {
    if ($this->inJobScope) {
      $this->jobContext = NULL;
      return;
    }
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
   * While a job scope is open the overlay is returned (NULL until
   * that item seals). A context sealed for another HTTP request is
   * not returned after that request leaves the stack. A job seal is
   * visible even when a leftover CLI bootstrap request is still on
   * the stack.
   */
  public function get(): ?McpPrincipalContext {
    if ($this->inJobScope) {
      return $this->jobContext;
    }
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
    $this->inJobScope = FALSE;
    $this->jobContext = NULL;
  }

  /**
   * TRUE when this process holds an inbound HTTP request seal.
   */
  private function hasInboundHttpSeal(): bool {
    return $this->requestStack->getCurrentRequest() !== NULL
      && $this->sealedFor !== NULL
      && $this->sealedFor !== self::JOB_TOKEN;
  }

  /**
   * TRUE when a queue worker or Drush command opened this scope.
   *
   * Arbitrary HTTP controllers are refused even if they construct
   * McpPrincipalContextJob themselves.
   */
  private function calledFromInternalJobPath(): bool {
    foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20) as $frame) {
      $class = $frame['class'] ?? '';
      if ($class === '') {
        continue;
      }
      if (str_starts_with($class, 'Drupal\\mcp_sentinel\\Drush\\')) {
        return TRUE;
      }
      if (is_a($class, QueueWorkerInterface::class, TRUE)) {
        return TRUE;
      }
    }
    return FALSE;
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
