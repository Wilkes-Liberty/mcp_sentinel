<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Seals the frozen principal context once per request.
 *
 * Tools read through this holder, never from a swappable request
 * attribute. A later seal for the still-current request is ignored.
 */
final class McpPrincipalContextHolder {

  /**
   * The sealed context, or NULL before the first seal.
   */
  private ?McpPrincipalContext $context = NULL;

  /**
   * Request (or sentinel) this context is sealed to.
   */
  private mixed $sealedFor = NULL;

  /**
   * Constructs the holder.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   Used to refuse a swap while the sealed request is still current.
   */
  public function __construct(
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * Seals ctx for $token. A second seal for the same request is a no-op.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $ctx
   *   The frozen context from the validated token.
   * @param mixed $token
   *   The current request object, or a CLI sentinel.
   */
  public function seal(McpPrincipalContext $ctx, mixed $token): void {
    if ($this->sealedFor === $token) {
      return;
    }
    $current = $this->requestStack->getCurrentRequest();
    if ($this->sealedFor !== NULL && $this->sealedFor === $current) {
      return;
    }
    $this->context = $ctx;
    $this->sealedFor = $token;
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
    $this->context = NULL;
    $this->sealedFor = NULL;
  }

}
