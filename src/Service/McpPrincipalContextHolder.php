<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Value\McpCarriedPrincipal;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Seals the frozen principal context once per request.
 *
 * Tools read through this holder, never from a swappable request
 * attribute. A subrequest cannot reseal a different principal. A
 * queue or Drush job opens a deny-only overlay that hides the
 * request seal and never stores a caller-built context. Governed
 * tools refuse under that overlay until a hop token supplies a
 * Paladin principal. seal() is a no-op while an overlay is open
 * so it is not a forgery path.
 */
final class McpPrincipalContextHolder {

  /**
   * The sealed context, or NULL before the first seal.
   */
  private ?McpPrincipalContext $context = NULL;

  /**
   * Request this context is sealed to.
   */
  private mixed $sealedFor = NULL;

  /**
   * Open overlay handles, innermost last.
   *
   * @var list<\Drupal\mcp_sentinel\Service\McpJobScopeHandle>
   */
  private array $scopeHandles = [];

  /**
   * Kill-check keys carried by open job handles, keyed by spl_object_id.
   *
   * @var array<int, \Drupal\mcp_sentinel\Value\McpCarriedPrincipal>
   */
  private array $carriedByHandle = [];

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
   * replaces the seal. While a job overlay is open this is a no-op
   * so a caller-built context cannot replace the request seal.
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
    if ($this->inJobScope()) {
      return;
    }
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
    // Replace only when the sealed request is gone from the stack.
    // A leftover that is still a parent (or any intermediate) is not
    // replaced here; the subrequest branch above already refused a
    // different identity.
    if ($current !== NULL && !$this->sealedRequestStillOnStack()) {
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
   * Pushes a deny-only overlay over the current seal.
   *
   * Hides the request seal. Does not store a job principal.
   * A second enter without the matching leave stays in the overlay.
   *
   * @return \Drupal\mcp_sentinel\Service\McpJobScopeHandle
   *   Token that the matching leaveJobScope() must present.
   *
   * @internal Called by mcp_sentinel.principal_context_job.
   */
  public function enterJobScope(): McpJobScopeHandle {
    $handle = new McpJobScopeHandle();
    $this->scopeHandles[] = $handle;
    return $handle;
  }

  /**
   * Drops the matching overlay and restores the request seal.
   *
   * @param \Drupal\mcp_sentinel\Service\McpJobScopeHandle $handle
   *   The token returned by the matching enterJobScope().
   *
   * @throws \LogicException
   *   When $handle is not the innermost open overlay.
   *
   * @internal Called by mcp_sentinel.principal_context_job.
   */
  public function leaveJobScope(McpJobScopeHandle $handle): void {
    $top = $this->scopeHandles === []
      ? NULL
      : $this->scopeHandles[array_key_last($this->scopeHandles)];
    if ($top !== $handle) {
      throw new \LogicException(
        'leaveJobScope() requires the handle returned by the '
        . 'matching enterJobScope().',
      );
    }
    array_pop($this->scopeHandles);
    unset($this->carriedByHandle[spl_object_id($handle)]);
  }

  /**
   * Closes leftover inner overlays down to $handle.
   *
   * Used by a worker finally block. Does not throw when $handle
   * is already gone or when an item left an inner scope open.
   *
   * @param \Drupal\mcp_sentinel\Service\McpJobScopeHandle $handle
   *   The worker's own enterJobScope() handle.
   *
   * @return int
   *   Overlays closed, including $handle when it was still open.
   *
   * @internal Called by mcp_sentinel.principal_context_job.
   */
  public function unwindTo(McpJobScopeHandle $handle): int {
    $closed = 0;
    while ($this->scopeHandles !== []) {
      $top = $this->scopeHandles[array_key_last($this->scopeHandles)];
      array_pop($this->scopeHandles);
      unset($this->carriedByHandle[spl_object_id($top)]);
      $closed++;
      if ($top === $handle) {
        return $closed;
      }
    }
    return 0;
  }

  /**
   * Whether a deny-only job overlay is currently active.
   *
   * @internal The dispatcher refuses governed tools while TRUE.
   */
  public function inJobScope(): bool {
    return $this->scopeHandles !== [];
  }

  /**
   * Attaches kill-check keys to an open job overlay.
   *
   * Does not seal identity. Tools still refuse under the overlay
   * until a hop token supplies a Paladin principal.
   *
   * @param \Drupal\mcp_sentinel\Service\McpJobScopeHandle $handle
   *   Handle returned by enterJobScope().
   * @param \Drupal\mcp_sentinel\Value\McpCarriedPrincipal $carried
   *   Keys the queued work was admitted under.
   *
   * @throws \LogicException
   *   When $handle is not an open overlay.
   *
   * @internal Called by mcp_sentinel.principal_context_job.
   */
  public function carryPrincipal(McpJobScopeHandle $handle, McpCarriedPrincipal $carried): void {
    $open = FALSE;
    foreach ($this->scopeHandles as $openHandle) {
      if ($openHandle === $handle) {
        $open = TRUE;
        break;
      }
    }
    if (!$open) {
      throw new \LogicException(
        'carryPrincipal() requires an open job-scope handle.',
      );
    }
    $this->carriedByHandle[spl_object_id($handle)] = $carried;
  }

  /**
   * Innermost carried keys, or NULL when the overlay carries none.
   *
   * @internal Used by the kill switch at admit() and pre-commit.
   */
  public function carriedPrincipal(): ?McpCarriedPrincipal {
    if ($this->scopeHandles === []) {
      return NULL;
    }
    $top = $this->scopeHandles[array_key_last($this->scopeHandles)];
    return $this->carriedByHandle[spl_object_id($top)] ?? NULL;
  }

  /**
   * The sealed context, or NULL if none is visible for this call.
   *
   * While a job overlay is open this is always NULL: the overlay
   * hides the request seal and never holds a caller-built context.
   * A context sealed for another HTTP request is not returned after
   * that request leaves the stack.
   */
  public function get(): ?McpPrincipalContext {
    if ($this->inJobScope()) {
      return NULL;
    }
    if ($this->context === NULL) {
      return NULL;
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
    $this->scopeHandles = [];
    $this->carriedByHandle = [];
  }

  /**
   * TRUE when the sealed request is still current, parent, or main.
   *
   * RequestStack exposes only those three windows. Combined with the
   * subrequest identity check, a nested request cannot replace an
   * intermediate parent's seal.
   */
  private function sealedRequestStillOnStack(): bool {
    if ($this->sealedFor === NULL) {
      return FALSE;
    }
    $current = $this->requestStack->getCurrentRequest();
    $main = $this->requestStack->getMainRequest();
    if ($this->sealedFor === $current || $this->sealedFor === $main) {
      return TRUE;
    }
    $parent = $this->requestStack->getParentRequest();
    return $parent !== NULL && $this->sealedFor === $parent;
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
